# pydantic-jwt

Structural JWT validation as a Pydantic type.

`pydantic-jwt` gives you a `JWTStr` type that validates a string is a
well-formed JSON Web Token (RFC 7519) — three base64url segments, valid
JSON header/payload, and a non-empty `alg`. It does **not** verify the
cryptographic signature; use it to catch malformed tokens early, at the
schema layer, before doing real verification with a library like `PyJWT`.

## Install

```bash
pip install pydantic-jwt
```

## Basic usage

```python
from pydantic import BaseModel
from pydantic_jwt import JWTStr


class Auth(BaseModel):
    token: JWTStr


auth = Auth(token="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdA")

print(auth.token.header)  # {'alg': 'HS256'}
print(auth.token.payload)  # {'sub': '1234567890'}
print(auth.token.algorithm)  # 'HS256'
print(auth.token.signature)  # b'test'
```

If the string isn't a valid JWT, Pydantic raises a normal `ValidationError`:

```python
Auth(token="not-a-jwt")
# pydantic_core._pydantic_core.ValidationError: 1 validation error for Auth
# token
#   Value must include header, payload, and signature separated by dots [type=jwt_format, ...]
```

## Additional constraints

For extra checks beyond structural validity — allowed algorithms, token
expiry (`exp`), not-before (`nbf`) — use `JWTConstraints` with `Annotated`:

```python
from typing import Annotated

from pydantic import BaseModel
from pydantic_jwt import JWTStr, JWTConstraints


class Auth(BaseModel):
    token: Annotated[
        JWTStr,
        JWTConstraints(allowed_algorithms=("HS256", "RS256")),
    ]
```

By default, `JWTConstraints()` rejects expired tokens (`exp` in the past)
and tokens that aren't active yet (`nbf` in the future).

### `JWTConstraints` options

| Field                | Default   | Description                                              |
|-----------------------|-----------|------------------------------------------------------------|
| `allowed_algorithms`  | `None`    | Tuple of allowed `alg` values. `None` allows any algorithm. |
| `exp_name`            | `"exp"`   | Payload key used for the expiry check.                     |
| `allow_exp`           | `False`   | If `True`, skip the expiry check entirely.                 |
| `nbf_name`            | `"nbf"`   | Payload key used for the not-before check.                 |
| `allow_nbf`           | `False`   | If `True`, skip the not-before check entirely.              |

```python
# allow expired tokens, only restrict algorithm
token: Annotated[JWTStr, JWTConstraints(allowed_algorithms=("HS256",), allow_exp=True)]

# use non-standard claim names
token: Annotated[JWTStr, JWTConstraints(exp_name="expires_at", nbf_name="not_before")]
```

## What this does *not* do

- **No signature verification.** `JWTStr` only checks structure, not
  authenticity. Anyone can craft a structurally valid JWT with any
  payload they like — never trust claims from an unverified token.
- **No decoding shortcuts for auth.** For real authentication flows,
  verify the signature with a dedicated library (e.g. `PyJWT`,
  `python-jose`) using the correct key and algorithm, then optionally
  layer `JWTStr`/`JWTConstraints` on top for schema-level sanity checks.

## Requirements

- Python >= 3.10
- Pydantic >= 2.10.0

## License

MIT