# FastAPI

A token model fits FastAPI naturally: the dependency returns a **typed object**
instead of a `dict[str, Any]`, and every rejection is already a
`ValidationError`, so one exception handler covers malformed, expired and forged
tokens alike.

This page builds a complete application — access and refresh tokens, a bearer
dependency, scopes, and clean OpenAPI — one piece at a time. The
[whole file](#the-complete-application) is at the bottom.

```bash
pip install pydantic-jwt fastapi "uvicorn[standard]"
```

## 1. The token models

Two models, two secrets. Separate keys mean a refresh token can never be
replayed as an access token, and `verified_only=True` means neither model can be
built from anything a client sent — only from a token whose signature was
checked, or from an explicit `from_claims()` call on the issuing side.

```python
import os
from typing import Annotated

from pydantic_jwt import ConfigDict, Exp, Iat, JWTModel, after, uuid

ACCESS_SECRET = os.environ["JWT_ACCESS_SECRET"]
REFRESH_SECRET = os.environ["JWT_REFRESH_SECRET"]
ISSUER = "https://auth.example.com"


class AccessToken(JWTModel):
    """Short-lived credential sent on every request."""

    model_config = ConfigDict(
        algorithm="HS256",
        encoding_key=ACCESS_SECRET,
        decoding_key=ACCESS_SECRET,
        verified_only=True,
    )

    sub: str
    scopes: list[str] = []
    exp: Exp = after(minutes=15)
    iat: Iat = after()
    jti: str = uuid()


class RefreshToken(JWTModel):
    """Long-lived credential, exchanged for a new access token."""

    model_config = ConfigDict(
        algorithm="HS256",
        encoding_key=REFRESH_SECRET,
        decoding_key=REFRESH_SECRET,
        verified_only=True,
    )

    sub: str
    exp: Exp = after(days=30)
    jti: str = uuid()
```

Because the two use different keys, feeding a refresh token to `AccessToken`
fails with `jwt_invalid_signature` — the models cannot be confused for one
another.

`verified_only=True` is what makes these models safe to hold anywhere in a
request: a client that `POST`s `{"sub": "admin", "scopes": ["users:write"]}`
gets a `jwt_unverified_payload` error instead of an `AccessToken`. See
[Refusing unverified payloads](../guide/models.md#refusing-unverified-payloads).

## 2. Response models

The wire format is a string, so response models declare `str` and are filled
with `token.generate()`. (Serialising the model itself would emit the claims as
a JSON object — see [Serialisation](../guide/models.md#serialisation).)

```python
from pydantic import BaseModel


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
```

## 3. The authentication dependency

`HTTPBearer` pulls the credential out of the `Authorization` header and rejects
the request itself when the header is absent or malformed. Everything the token
can do wrong is a
`ValueError` — both `ValidationError` and `PydanticCustomError` subclass it — so
one `except` turns the whole family into a 401.

```python
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

bearer_scheme = HTTPBearer(description="A `pydantic-jwt` access token.")


def current_token(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
) -> AccessToken:
    try:
        return AccessToken.from_token(credentials.credentials)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None


CurrentToken = Annotated[AccessToken, Depends(current_token)]
```

The alias is worth the two lines: endpoints then read as `token: CurrentToken`.

!!! warning "Take tokens from the header, not the body"

    ```python
    @app.post("/admin")
    def admin(token: AccessToken) -> None: ...
    ```

    FastAPI parses the JSON body straight into the model. On a model *without*
    `verified_only`, that is a hole: no signature is involved, so a client could
    simply `POST {"sub": "admin"}`. With `verified_only=True` — as in
    [step 1](#1-the-token-models) — the same request fails with
    `jwt_unverified_payload` instead, which is why these models set it.

    Do not rely on the flag alone, though. Tokens belong in the `Authorization`
    header, through the dependency above; when one genuinely arrives in a body
    (a refresh token, say), type the field as `str` and call `from_token()`
    yourself, as [step 4](#4-endpoints) does. See
    [Security notes](../guide/security.md#a-model-built-from-a-dict-is-not-authenticated).

## 4. Endpoints

Issuing a pair:

```python
from fastapi import FastAPI

app = FastAPI(title="pydantic-jwt example")

ACCESS_TTL = 15 * 60


@app.post("/login", response_model=TokenPair)
def login(credentials: LoginRequest) -> TokenPair:
    user_id = authenticate(credentials.username, credentials.password)
    if user_id is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Bad credentials")

    return TokenPair(
        access_token=AccessToken.from_claims(sub=user_id, scopes=scopes_for(user_id)).generate(),
        refresh_token=RefreshToken.from_claims(sub=user_id).generate(),
        expires_in=ACCESS_TTL,
    )
```

`from_claims()` is the deliberate-construction call these `verified_only` models
require; `generate()` signs. On a model without the flag, `AccessToken(sub=...)`
would do just as well.

Consuming one — the endpoint body works with a typed object, so `token.sub` and
`token.scopes` are autocompleted and type-checked:

```python
@app.get("/me")
def me(token: CurrentToken) -> dict[str, object]:
    return {"user": token.sub, "scopes": token.scopes, "expires_at": token.exp}
```

Refreshing. The refresh token arrives in the body here rather than the header,
so it is typed as `str` and verified explicitly:

```python
class RefreshRequest(BaseModel):
    refresh_token: str


@app.post("/refresh", response_model=TokenPair)
def refresh(body: RefreshRequest) -> TokenPair:
    try:
        old = RefreshToken.from_token(body.refresh_token)
    except ValueError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token") from None

    if is_revoked(old.jti):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token revoked")
    revoke(old.jti)  # rotate: a refresh token is single-use

    return TokenPair(
        access_token=AccessToken.from_claims(sub=old.sub, scopes=scopes_for(old.sub)).generate(),
        refresh_token=RefreshToken.from_claims(sub=old.sub).generate(),
        expires_in=ACCESS_TTL,
    )
```

## 5. Scopes

A dependency factory turns the `scopes` claim into a reusable authorisation
check:

```python
from collections.abc import Callable


def requires(*scopes: str) -> Callable[[AccessToken], AccessToken]:
    def dependency(token: CurrentToken) -> AccessToken:
        missing = set(scopes) - set(token.scopes)
        if missing:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Missing scope(s): {', '.join(sorted(missing))}",
            )
        return token

    return dependency


@app.delete("/users/{user_id}", dependencies=[Depends(requires("users:write"))])
def delete_user(user_id: str) -> dict[str, str]:
    return {"deleted": user_id}
```

FastAPI's own `SecurityScopes` works too, if you want the scopes to show up in
OpenAPI; the claim itself is just a list of strings on the model.

## 6. Distinguishing the failure

The dependency above answers 401 for anything wrong. Clients behave better when
"expired" is distinguishable from "invalid" — the first means *go refresh*, the
second means *log in again*. The error `type` carries that:

```python
from pydantic import ValidationError
from pydantic_core import PydanticCustomError


def current_token(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
) -> AccessToken:
    try:
        return AccessToken.from_token(credentials.credentials)
    except ValidationError as exc:
        expired = any(
            error["type"] == "jwt_claim_invalid" and error.get("ctx", {}).get("claim") == "exp"
            for error in exc.errors()
        )
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Token expired" if expired else "Malformed token",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        ) from None
    except PydanticCustomError:
        # jwt_format, jwt_invalid_signature or jwt_missing_key — never leak which
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token") from None
```

`from_token()` reports claim failures as a `ValidationError` and structural,
signature and key failures as a bare `PydanticCustomError` — see
[`ValidationError` vs `PydanticCustomError`](../guide/validation.md#validationerror-vs-pydanticcustomerror).

Do not return the raw `exc.errors()` to the client: `jwt_missing_key` is a
server misconfiguration, and telling an attacker that their forgery failed on the
*signature* rather than the claims is free information. Log the detail, return
the category.

## 7. Per-request keys (multi-tenant)

When the key depends on the request — one signing key per tenant — pass it per
call instead of putting it in `model_config`:

```python
def tenant_token(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
    tenant: Annotated[str, Header(alias="X-Tenant-Id")],
) -> AccessToken:
    key = KEYS.get(tenant)
    if key is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown tenant")
    try:
        return AccessToken.from_token(credentials.credentials, decoding_key=key, algorithm="HS256")
    except ValueError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token") from None
```

See [Configuration](../guide/configuration.md#per-call-keys) for the same thing
via validation context, and
[Working with raw tokens](../guide/jwt-str.md#routing-before-verification) for
selecting a key from the `kid` header.

## 8. OpenAPI

A `JWTModel` reports itself as a string with `format: jwt` and a description
listing its claims, so a token used as a *field type* stays readable in the
schema:

```python
class DebugResponse(BaseModel):
    token: AccessToken


DebugResponse.model_json_schema()
#> {'properties': {'token': {'type': 'string',
#>                           'format': 'jwt',
#>                           'description': 'JWT token containing claims: sub, scopes, exp, iat, jti'}},
#>  ...}
```

Note that this only affects the *schema*. A response model that must actually
emit the compact token still needs a `str` field assigned `token.generate()`, as
in [step 2](#2-response-models).

## Testing

`TestClient` plus the models themselves — no fixtures for signing needed, since
the model is the signer. `from_claims()` builds the tokens, `generate()` signs
them:

```python
import time

from fastapi.testclient import TestClient

client = TestClient(app)


def auth(token: AccessToken | RefreshToken) -> dict[str, str]:
    return {"Authorization": f"Bearer {token.generate()}"}


def test_me_returns_the_subject() -> None:
    token = AccessToken.from_claims(sub="user-42", scopes=["read"])

    response = client.get("/me", headers=auth(token))

    assert response.status_code == 200
    assert response.json()["user"] == "user-42"


def test_expired_token_is_rejected() -> None:
    expired = AccessToken.from_claims(
        {"validate_claims": False}, sub="user-42", exp=int(time.time()) - 1
    )

    assert client.get("/me", headers=auth(expired)).status_code == 401


def test_refresh_token_is_not_an_access_token() -> None:
    forged = RefreshToken.from_claims(sub="user-42")

    assert client.get("/me", headers=auth(forged)).status_code == 401


def test_a_forged_payload_never_becomes_a_token() -> None:
    with pytest.raises(ValidationError) as exc_info:
        AccessToken(sub="admin", scopes=["users:write"])

    assert "jwt_unverified_payload" in {e["type"] for e in exc_info.value.errors()}
```

Three things worth copying:

- `f"Bearer {token}"` would send the *claims*, not a token — `str()` does not
  sign. Always `token.generate()`.
- Claim markers run on construction, so building an expired token needs
  `from_claims({"validate_claims": False}, ...)`; see
  [Skipping claim checks](../guide/claims.md#skipping-claim-checks).
- The last test is the one that keeps `verified_only` honest: it asserts that the
  dangerous shape stays impossible, so nobody quietly drops the flag later.

The refresh-token test relies on the two models using different keys: a
`RefreshToken` is a perfectly well-formed JWT that simply does not verify as an
`AccessToken`.

## The complete application

```python
from __future__ import annotations

import os
import time
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from pydantic_jwt import ConfigDict, Exp, Iat, JWTModel, after, uuid

ACCESS_SECRET = os.environ.get("JWT_ACCESS_SECRET", "dev-secret-" + "0" * 32)
REFRESH_SECRET = os.environ.get("JWT_REFRESH_SECRET", "dev-refresh-" + "0" * 32)
ACCESS_TTL = 15 * 60


class AccessToken(JWTModel):
    model_config = ConfigDict(
        algorithm="HS256",
        encoding_key=ACCESS_SECRET,
        decoding_key=ACCESS_SECRET,
        verified_only=True,
    )

    sub: str
    scopes: list[str] = []
    exp: Exp = after(seconds=ACCESS_TTL)
    iat: Iat = after()
    jti: str = uuid()


class RefreshToken(JWTModel):
    model_config = ConfigDict(
        algorithm="HS256",
        encoding_key=REFRESH_SECRET,
        decoding_key=REFRESH_SECRET,
        verified_only=True,
    )

    sub: str
    exp: Exp = after(days=30)
    jti: str = uuid()


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


app = FastAPI(title="pydantic-jwt example")
bearer_scheme = HTTPBearer(description="A `pydantic-jwt` access token.")

USERS = {"ada": ("password", ["read", "users:write"])}
REVOKED: set[str] = set()


def current_token(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
) -> AccessToken:
    try:
        return AccessToken.from_token(credentials.credentials)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None


CurrentToken = Annotated[AccessToken, Depends(current_token)]


def requires(*scopes: str) -> Callable[[AccessToken], AccessToken]:
    def dependency(token: CurrentToken) -> AccessToken:
        missing = set(scopes) - set(token.scopes)
        if missing:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Missing scope(s): {', '.join(sorted(missing))}",
            )
        return token

    return dependency


def issue(sub: str, scopes: list[str]) -> TokenPair:
    return TokenPair(
        access_token=AccessToken.from_claims(sub=sub, scopes=scopes).generate(),
        refresh_token=RefreshToken.from_claims(sub=sub).generate(),
        expires_in=ACCESS_TTL,
    )


@app.post("/login", response_model=TokenPair)
def login(body: LoginRequest) -> TokenPair:
    record = USERS.get(body.username)
    if record is None or record[0] != body.password:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Bad credentials")
    return issue(body.username, record[1])


@app.post("/refresh", response_model=TokenPair)
def refresh(body: RefreshRequest) -> TokenPair:
    try:
        old = RefreshToken.from_token(body.refresh_token)
    except ValueError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token") from None

    if old.jti in REVOKED:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token revoked")
    REVOKED.add(old.jti)  # single-use: rotate on every refresh

    scopes = USERS[old.sub][1] if old.sub in USERS else []
    return issue(old.sub, scopes)


@app.get("/me")
def me(token: CurrentToken) -> dict[str, object]:
    return {"user": token.sub, "scopes": token.scopes, "expires_at": token.exp}


@app.delete("/users/{user_id}", dependencies=[Depends(requires("users:write"))])
def delete_user(user_id: str) -> dict[str, str]:
    return {"deleted": user_id}
```

Run it with:

```bash
uvicorn app:app --reload
```

then

```bash
TOKEN=$(curl -s localhost:8000/login \
  -H 'Content-Type: application/json' \
  -d '{"username": "ada", "password": "password"}' | jq -r .access_token)

curl localhost:8000/me -H "Authorization: Bearer $TOKEN"
#> {"user":"ada","scopes":["read","users:write"],"expires_at":1788009360}
```
