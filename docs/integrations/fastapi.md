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

Two models, two secrets. Sharing a base class keeps the algorithm in one place;
separate keys mean a refresh token can never be replayed as an access token.

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
    )

    sub: str
    exp: Exp = after(days=30)
    jti: str = uuid()
```

Because the two use different keys, feeding a refresh token to `AccessToken`
fails with `jwt_invalid_signature` — the models cannot be confused for one
another.

## 2. Response models

The wire format is a string, so response models declare `str` and are filled
with `str(token)`. (Serialising the model itself would emit the claims as a JSON
object — see [Serialisation](../guide/models.md#serialisation).)

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

!!! warning "Never take a token from the request body"

    ```python
    @app.post("/admin")
    def admin(token: AccessToken) -> None: ...  # DANGEROUS
    ```

    FastAPI would parse the JSON body straight into the model, and building a
    model from a dict does **not** check a signature — a client could `POST
    {"sub": "admin"}`. Tokens must arrive through the dependency above, or as a
    `str` field you pass to `from_token()` yourself. See
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
        access_token=str(AccessToken(sub=user_id, scopes=scopes_for(user_id))),
        refresh_token=str(RefreshToken(sub=user_id)),
        expires_in=ACCESS_TTL,
    )
```

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
        access_token=str(AccessToken(sub=old.sub, scopes=scopes_for(old.sub))),
        refresh_token=str(RefreshToken(sub=old.sub)),
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
emit the compact token still needs a `str` field assigned `str(token)`, as in
[step 2](#2-response-models).

## Testing

`TestClient` plus the models themselves — no fixtures for signing needed, since
the model is the signer:

```python
from fastapi.testclient import TestClient

client = TestClient(app)


def auth(token: AccessToken) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_me_returns_the_subject() -> None:
    response = client.get("/me", headers=auth(AccessToken(sub="user-42", scopes=["read"])))

    assert response.status_code == 200
    assert response.json()["user"] == "user-42"


def test_expired_token_is_rejected() -> None:
    expired = AccessToken.model_validate(
        {"sub": "user-42", "exp": int(time.time()) - 1},
        context={"validate_claims": False},
    )

    assert client.get("/me", headers=auth(expired)).status_code == 401


def test_refresh_token_is_not_an_access_token() -> None:
    forged = RefreshToken(sub="user-42")

    assert client.get("/me", headers=auth(forged)).status_code == 401
```

Claim markers run on construction too, so `AccessToken(sub="user-42", exp=<past>)`
raises rather than producing an expired token. `model_validate()` with
`context={"validate_claims": False}` is how you build one deliberately — see
[Skipping claim checks](../guide/claims.md#skipping-claim-checks).

The last test relies on the two models using different keys: a `RefreshToken` is
a perfectly well-formed JWT that simply does not verify as an `AccessToken`.

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
        algorithm="HS256", encoding_key=ACCESS_SECRET, decoding_key=ACCESS_SECRET
    )

    sub: str
    scopes: list[str] = []
    exp: Exp = after(seconds=ACCESS_TTL)
    iat: Iat = after()
    jti: str = uuid()


class RefreshToken(JWTModel):
    model_config = ConfigDict(
        algorithm="HS256", encoding_key=REFRESH_SECRET, decoding_key=REFRESH_SECRET
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
        access_token=str(AccessToken(sub=sub, scopes=scopes)),
        refresh_token=str(RefreshToken(sub=sub)),
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
