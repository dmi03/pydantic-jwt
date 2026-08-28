# pydantic-jwt

JWT tokens as Pydantic models.

Declare your token as a model, and get parsing, claim validation, signature
verification and encoding out of it — with the claims typed, autocompleted and
checked like any other Pydantic field.

## Install

```bash
pip install pydantic-jwt
```

## Basic usage

```python
from pydantic_jwt import ConfigDict, Exp, JWTModel, after

SECRET = "keep-me-out-of-your-source"


class AccessToken(JWTModel):
    model_config = ConfigDict(
        algorithm="HS256",
        encoding_key=SECRET,
        decoding_key=SECRET,
    )

    sub: str
    exp: Exp = after(minutes=15)
```

That single class is both ends of the flow.

Issue a token:

```python
token = AccessToken(sub="user-42")
raw = str(token)  # 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
```

Read one back — the string is decoded, the signature is checked against
`decoding_key`, and `exp` is validated:

```python
token = AccessToken.from_token(raw)
token.sub  # 'user-42'
```

Anything wrong with the token raises a normal `ValidationError`, so it fits
wherever Pydantic already does:

```python
AccessToken.from_token(forged)
# jwt_invalid_signature: Invalid token signature for algorithm HS256

AccessToken.from_token(stale)
# exp claim is invalid: 1712345678
```

## Claims

`Exp`, `Nbf` and `Iat` are annotated `int` types that validate themselves
against the current time:

```python
from pydantic_jwt import Exp, Iat, Nbf


class SessionToken(JWTModel):
    sub: str
    exp: Exp
    nbf: Nbf
    iat: Iat
```

Clock skew between servers is handled with `leeway`, in seconds:

```python
from typing import Annotated

from pydantic_jwt import ExpClaim

exp: Annotated[int, ExpClaim(leeway=30)]
```

Don't want a claim checked at all? Annotate it as a plain `int`.

Two helpers build timestamp defaults. They are evaluated per instance, so every
token gets a fresh value:

```python
from datetime import datetime, timezone

from pydantic_jwt import after, at


class SessionToken(JWTModel):
    sub: str
    exp: Exp = after(hours=1, minutes=30)
    nbf: Nbf = at(datetime(2030, 1, 1, tzinfo=timezone.utc))
```

`after()` takes `weeks`, `days`, `hours`, `minutes`, `seconds` and
`milliseconds`.

## With FastAPI

```python
from typing import Annotated

from fastapi import Depends, FastAPI, Header

app = FastAPI()


def current_token(authorization: Annotated[str, Header()]) -> AccessToken:
    return AccessToken.from_token(authorization.removeprefix("Bearer "))


@app.get("/me")
def me(token: Annotated[AccessToken, Depends(current_token)]) -> dict[str, str]:
    return {"user": token.sub}
```

The endpoint body works with a typed object, not a dict of unknown claims.
`AccessToken` also reports itself to OpenAPI as a string with `format: jwt`,
so the schema stays readable.

## Configuration

Everything lives in `model_config`, alongside the usual Pydantic settings:

| Key            | Description                                                              |
|----------------|--------------------------------------------------------------------------|
| `algorithm`    | Algorithm used to sign and verify, e.g. `"HS256"`.                        |
| `encoding_key` | Key used by `generate()`.                                                 |
| `decoding_key` | Key used to verify incoming tokens.                                       |
| `require_keys` | If `False`, tokens are accepted without signature verification when no key is configured. Defaults to `True`. |

`generate()` also takes `encoding_key` and `algorithm` directly, which is handy
for key rotation:

```python
token.generate(encoding_key=next_key, algorithm="HS256")
```

## Good to know

- **Building a model from a dict does not verify anything.**
  `AccessToken(sub="x")` and `AccessToken.model_validate({"sub": "x"})` construct
  a token you are about to sign; only `from_token()` (and validating from a
  token *string*) checks a signature. Don't accept an `AccessToken` straight from
  request data and treat it as authenticated.
- **Unknown claims are rejected.** Models default to `extra="forbid"`, so tokens
  from third-party issuers that add their own claims need
  `model_config = ConfigDict(extra="ignore")` or explicit fields.
- **`require_keys=False` accepts unverified tokens.** It logs a warning and moves
  on. Useful in tests, dangerous everywhere else.

## Requirements

- Python >= 3.10
- Pydantic >= 2.10
- PyJWT >= 2.8

## License

MIT