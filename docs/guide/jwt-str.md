# Working with raw tokens

[`JWTStr`][pydantic_jwt.JWTStr] is a `str` subclass that validates the
*structure* of a JWT and exposes its three parts. It is what
[`JWTModel`](models.md) uses internally to split an incoming token, and it is
usable on its own whenever you need to look at a token without turning it into a
model.

```python
from pydantic_jwt import JWTStr

token = JWTStr("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdA")

token.header  #> {'alg': 'HS256'}
token.algorithm  #> 'HS256'
token.payload  #> {'sub': '1234567890'}
token.signature  #> b'test'
```

Since it *is* a `str`, it can go anywhere a string goes:

```python
len(token)
token.startswith("eyJ")
headers = {"Authorization": f"Bearer {token}"}
```

!!! danger "`JWTStr` verifies nothing"

    Constructing a `JWTStr` checks the *shape* of the token, not its signature
    and not its claims. `token.payload["sub"]` is attacker-controlled data:
    anyone can craft a structurally valid JWT with any payload they like. Use it
    for routing and diagnostics, never for authorisation. Verification happens in
    [`JWTModel.from_token()`][pydantic_jwt.JWTModel.from_token].

## What is checked

Construction raises `PydanticCustomError` unless all of the following hold:

1. the value is a `str` — otherwise `jwt_type`;
2. it splits on `.` into exactly three parts — otherwise `jwt_format`
   ("Value must include header, payload, and signature separated by dots");
3. all three parts decode as urlsafe base64 (padding is added automatically, and
   standard-alphabet characters like `+` and `/` are rejected) — otherwise
   `jwt_format`;
4. header and payload decode as UTF-8 and parse as JSON — otherwise
   `jwt_format`;
5. both are JSON *objects*, not arrays or scalars — otherwise `jwt_type`.

## `validate()`

[`validate()`][pydantic_jwt.JWTStr.validate] is the non-raising form — a
predicate for filtering:

```python
JWTStr.validate("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dGVzdA")  #> True
JWTStr.validate("not-a-token")  #> False
JWTStr.validate(12345)  #> False
```

## As a Pydantic field

`JWTStr` carries its own core schema, so it works as a field type on any model,
and describes itself to JSON Schema as a string with `format: jwt`:

```python
from pydantic import BaseModel

from pydantic_jwt import JWTStr


class LoginResponse(BaseModel):
    access_token: JWTStr
    token_type: str = "bearer"


LoginResponse.model_json_schema()["properties"]["access_token"]
#> {
#>   'type': 'string',
#>   'format': 'jwt',
#>   'title': 'Access Token',
#>   'examples': ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdA'],
#> }
```

That makes it a good type for a response model or a request body that carries a
token this service does not itself verify — a refresh token forwarded to another
service, say. Validation failures come back as a normal `ValidationError`.

## Practical uses

### Routing before verification

A gateway that trusts several issuers can read the header to pick the key, then
verify properly:

```python
raw = JWTStr(authorization.removeprefix("Bearer "))

key = KEYS_BY_KID.get(raw.header.get("kid"))
if key is None:
    raise HTTPException(401, "Unknown key id")

token = AccessToken.from_token(raw, decoding_key=key, algorithm="RS256")
```

The `alg` from the header is deliberately *not* reused —
[`from_token()`][pydantic_jwt.JWTModel.from_token] always takes the algorithm
from your configuration, which is what defeats algorithm confusion. Read
`raw.algorithm` for logging, not for deciding.

### Diagnostics

```python
import logging

logger = logging.getLogger(__name__)


def explain(raw: str) -> None:
    if not JWTStr.validate(raw):
        logger.warning("not a JWT at all")
        return
    token = JWTStr(raw)
    logger.info("alg=%s claims=%s", token.algorithm, sorted(token.payload))
```

Log claim *names*, not values — a payload can hold personal data, and the token
itself is a credential.

### From a model

[`JWTModel.jwt_str`][pydantic_jwt.JWTModel.jwt_str] hands you the signed token
already wrapped:

```python
token = AccessToken(sub="user-42")
token.jwt_str  #> the signed compact token, as a JWTStr
token.jwt_str.payload  #> {'sub': 'user-42', 'exp': 1788009360}
```

Note that `str(token)` on a `JWTModel` is *not* a token — signing is
[`generate()`](models.md#generate) and `jwt_str` only. A `JWTStr`, on the other
hand, really is the string.

## API reference

Full signatures: [`JWTStr`](../api/str.md).
