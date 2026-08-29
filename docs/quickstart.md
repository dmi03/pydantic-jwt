# Quickstart

## 1. Declare the token

A token model is a Pydantic model. Its fields are the claims, and
`model_config` holds the keys used to sign and verify it.

```python
from pydantic_jwt import ConfigDict, Exp, JWTModel, after, uuid

SECRET = "keep-me-out-of-your-source"


class AccessToken(JWTModel):
    model_config = ConfigDict(
        algorithm="HS256",
        encoding_key=SECRET,
        decoding_key=SECRET,
    )

    sub: str
    exp: Exp = after(minutes=15)
    jti: str = uuid()
```

Three things are happening in the field list:

- `sub: str` is an ordinary required field — nothing JWT-specific about it.
- `exp: Exp` is an `int` that refuses to validate once the timestamp is in the
  past, and [`after(minutes=15)`](guide/defaults.md#after) gives it a default
  computed fresh for every instance.
- [`uuid()`](guide/defaults.md#uuid) gives each issued token a unique `jti`.

## 2. Issue a token

Construct the model and turn it into a string:

```python
token = AccessToken(sub="user-42")

raw = str(token)
#> 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTQyIiwi...'
```

`str(token)` calls [`generate()`][pydantic_jwt.JWTModel.generate], which dumps
the model to JSON and signs it with `encoding_key` and `algorithm`. The
[`jwt_str`][pydantic_jwt.JWTModel.jwt_str] property returns the same string as a
[`JWTStr`](guide/jwt-str.md), which can be taken apart:

```python
token.jwt_str.header  #> {'alg': 'HS256', 'typ': 'JWT'}
token.jwt_str.payload  #> {'sub': 'user-42', 'exp': 1788009360, 'jti': '9044...'}
```

## 3. Read one back

[`from_token()`][pydantic_jwt.JWTModel.from_token] parses the string, validates
every claim and verifies the signature against `decoding_key`:

```python
token = AccessToken.from_token(raw)
token.sub  #> 'user-42'
token.exp  #> 1788009360
```

`AccessToken.model_validate(raw)` does the same thing and is what runs when a
token string arrives in a field of some other model.

## 4. Handle the failures

Everything that can go wrong has a distinct error type:

```python
from pydantic import ValidationError

try:
    AccessToken.model_validate(untrusted)
except ValidationError as exc:
    print(exc.errors()[0]["type"])
    #> 'jwt_invalid_signature' — signed with the wrong key
    #> 'jwt_claim_invalid'     — expired, wrong issuer, ...
    #> 'jwt_format'            — not three dot-separated base64url segments
    #> 'extra_forbidden'       — a claim the model does not declare
```

See [Validation and errors](guide/validation.md) for the full list and for the
one case that raises `PydanticCustomError` instead of `ValidationError`.

## 5. Wire it into a framework

The whole point is that a verified token arrives as a typed object:

```python
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import ValidationError

app = FastAPI()
bearer = HTTPBearer()


def current_token(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer)],
) -> AccessToken:
    try:
        return AccessToken.from_token(credentials.credentials)
    except (ValidationError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token") from None


@app.get("/me")
def me(token: Annotated[AccessToken, Depends(current_token)]) -> dict[str, str]:
    return {"user": token.sub}
```

A complete application — login, refresh, scopes, error handling and OpenAPI — is
in the [FastAPI guide](integrations/fastapi.md).

## What to read next

- [Token models](guide/models.md) — the full `JWTModel` surface.
- [Claims](guide/claims.md) — `Exp`, `Nbf`, `Iat`, `iss`, `aud`, custom claims.
- [Security notes](guide/security.md) — the two mistakes worth knowing about
  before this goes near production.
