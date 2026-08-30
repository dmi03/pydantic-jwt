# pydantic-jwt

[![CI](https://github.com/dmi03/pydantic-jwt/actions/workflows/ci.yml/badge.svg)](https://github.com/dmi03/pydantic-jwt/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/pydantic-jwt.svg)](https://pypi.org/project/pydantic-jwt/)
[![Python](https://img.shields.io/pypi/pyversions/pydantic-jwt.svg)](https://pypi.org/project/pydantic-jwt/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**JWT tokens as Pydantic models.**

Declare your token as a model, and get parsing, claim validation, signature
verification and encoding out of it — with the claims typed, autocompleted and
checked like any other Pydantic field.

📖 **[Documentation](https://pydantic-jwt.dmi03.com/)**

## Install

```bash
pip install pydantic-jwt
```

Requires Python 3.10+, Pydantic 2.10+ and PyJWT 2.8+.

## Basic usage

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

That single class is both ends of the flow.

Issue a token:

```python
token = AccessToken(sub="user-42")
raw = token.generate()  # 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
```

Read one back — the string is parsed, `exp` is validated, and the signature is
verified against `decoding_key`:

```python
token = AccessToken.from_token(raw)
token.sub  # 'user-42'
```

Anything wrong with the token is a normal Pydantic error, so it fits wherever
Pydantic already does:

```python
from pydantic import ValidationError

try:
    token = AccessToken.model_validate(untrusted)
except ValidationError as exc:
    {error["type"] for error in exc.errors()}
    # 'jwt_invalid_signature'  — signed with the wrong key
    # 'jwt_claim_invalid'      — expired, wrong issuer, wrong audience
    # 'jwt_format'             — not a JWT at all
    # 'extra_forbidden'        — a claim the model does not declare
    # 'jwt_unverified_payload' — a payload where a verified token was required
```

## Claims

`Exp`, `Nbf` and `Iat` are annotated `int` types that validate themselves
against the current time:

```python
from pydantic_jwt import Exp, Iat, JWTModel, Nbf


class SessionToken(JWTModel):
    sub: str
    exp: Exp
    nbf: Nbf
    iat: Iat
```

`IssClaim` and `AudClaim` check a token was minted by the issuer you expect, for
the service you are:

```python
from typing import Annotated

from pydantic_jwt import AudClaim, IssClaim


class AccessToken(JWTModel):
    sub: str
    iss: Annotated[str, IssClaim("https://auth.example.com")]
    aud: Annotated[str | list[str], AudClaim("billing-api")]
```

Clock skew between servers is handled with `leeway`, in seconds:

```python
from pydantic_jwt import ExpClaim

exp: Annotated[int, ExpClaim(leeway=30)]
```

Don't want a claim checked at all? Annotate it as a plain `int`. Need a rule of
your own? [Subclass `Claim`](https://pydantic-jwt.dmi03.com/guide/claims/#custom-claims).

Three helpers build field defaults. They are evaluated per instance, so every
token gets a fresh value:

```python
from datetime import datetime, timezone

from pydantic_jwt import after, at, uuid


class SessionToken(JWTModel):
    sub: str
    exp: Exp = after(hours=1, minutes=30)
    nbf: Nbf = at(datetime(2030, 1, 1, tzinfo=timezone.utc))
    jti: str = uuid()
```

`after()` takes `weeks`, `days`, `hours`, `minutes`, `seconds` and
`milliseconds`.

## Refusing unverified payloads

By default a `JWTModel` can be built from a dict as well as from a token — the
same class issues and reads, so both are needed. `verified_only=True` closes the
payload branch for models that only ever *consume* tokens:

```python
class AccessToken(JWTModel):
    model_config = ConfigDict(
        algorithm="HS256",
        encoding_key=SECRET,
        decoding_key=SECRET,
        verified_only=True,
    )

    sub: str
    exp: Exp = after(minutes=15)


AccessToken.from_token(raw)  # ✅ signature checked
AccessToken.model_validate(raw)  # ✅ signature checked

AccessToken(sub="admin")  # ❌ ValidationError: jwt_unverified_payload
AccessToken.model_validate({"sub": "admin"})  # ❌ jwt_unverified_payload
```

That includes a nested dict, which is what makes such a model safe to name as a
request-body field type — a client cannot hand you the claims they would like to
have.

On the issuing side, construct one deliberately with `from_claims()`:

```python
raw = AccessToken.from_claims(sub="user-42").generate()
```

It still validates everything — field types, claim markers, `extra` — and takes
an optional positional context first, for building a deliberately invalid token
in a test:

```python
stale = AccessToken.from_claims({"validate_claims": False}, sub="user-42", exp=1)
```

## With FastAPI

```python
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

app = FastAPI()
bearer_scheme = HTTPBearer()


def current_token(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
) -> AccessToken:
    try:
        return AccessToken.from_token(credentials.credentials)
    except ValueError:  # ValidationError and PydanticCustomError are both ValueErrors
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None


CurrentToken = Annotated[AccessToken, Depends(current_token)]


@app.get("/me")
def me(token: CurrentToken) -> dict[str, str]:
    return {"user": token.sub}
```

The endpoint body works with a typed object, not a dict of unknown claims.
`AccessToken` also reports itself to OpenAPI as a string with `format: jwt`, so
the schema stays readable.

A complete application — login, refresh-token rotation, scopes and error
handling — is in the
[FastAPI guide](https://pydantic-jwt.dmi03.com/integrations/fastapi/).

## Configuration

Everything lives in `model_config`, alongside the usual Pydantic settings:

| Key            | Description                                                              |
|----------------|--------------------------------------------------------------------------|
| `algorithm`    | Algorithm used to sign and verify, e.g. `"HS256"`.                        |
| `encoding_key` | Key used by `generate()` and `jwt_str`.                                   |
| `decoding_key` | Key used to verify incoming tokens.                                       |
| `require_keys` | If `False`, tokens are accepted without signature verification when no key is configured. Defaults to `True`. |
| `verified_only` | If `True`, the model refuses to be built from a payload — only a verified token string or `from_claims()`. Defaults to `False`. |

Both directions also take keys per call, which is handy for key rotation and
multi-tenant deployments:

```python
raw = token.generate(encoding_key=next_key, algorithm="HS256")
token = AccessToken.from_token(raw, decoding_key=next_key, algorithm="HS256")
```

## Good to know

- **Building a model from a dict does not verify anything.**
  `AccessToken(sub="x")` and `AccessToken.model_validate({"sub": "x"})` construct
  a token you are about to sign; only `from_token()` (and validating from a
  token *string*) checks a signature. Set `verified_only=True` so the model
  refuses payloads outright — see below.
- **`str(token)` does not sign.** Signing is `generate()` and `jwt_str`, nothing
  else. `str(token)` renders the claims like any Pydantic model, so
  `f"Bearer {token}"` is a bug — write `f"Bearer {token.generate()}"`.
- **Unknown claims are rejected.** Models default to `extra="forbid"`, so tokens
  from third-party issuers that add their own claims need
  `model_config = ConfigDict(extra="ignore")` or explicit fields.
- **The algorithm is never read from the token header.** It always comes from
  your configuration, which is what defeats algorithm-confusion attacks.
- **`require_keys=False` accepts unverified tokens.** It logs a warning and moves
  on. Useful in tests, dangerous everywhere else.

More in the [security notes](https://pydantic-jwt.dmi03.com/guide/security/).

## Documentation

| | |
| --- | --- |
| [Quickstart](https://pydantic-jwt.dmi03.com/quickstart/) | The five-minute tour |
| [Token models](https://pydantic-jwt.dmi03.com/guide/models/) | `JWTModel`, `verified_only`, `from_claims()` |
| [Configuration](https://pydantic-jwt.dmi03.com/guide/configuration/) | Keys, algorithms, rotation |
| [Claims](https://pydantic-jwt.dmi03.com/guide/claims/) | Built-in and custom claim markers |
| [Defaults](https://pydantic-jwt.dmi03.com/guide/defaults/) | `after()`, `at()`, `uuid()` |
| [Validation and errors](https://pydantic-jwt.dmi03.com/guide/validation/) | Error types and validation context |
| [Working with raw tokens](https://pydantic-jwt.dmi03.com/guide/jwt-str/) | `JWTStr` |
| [Security notes](https://pydantic-jwt.dmi03.com/guide/security/) | Sharp edges and scope |
| [FastAPI](https://pydantic-jwt.dmi03.com/integrations/fastapi/) | A complete auth flow |
| [API reference](https://pydantic-jwt.dmi03.com/api/model/) | Generated from the source |

## Development

```bash
uv sync --all-groups
uv run pytest            # tests
uv run ruff check .      # lint
uv run mypy .            # types
uv run mkdocs serve      # docs at http://127.0.0.1:8000
```

The documentation site is built with MkDocs and served by Cloudflare as a
static-asset Worker, rebuilt from this repository on every push. The Worker is
configured in [`wrangler.jsonc`](wrangler.jsonc); CI also runs
`mkdocs build --strict` on every pull request.

## License

MIT — see [LICENSE](LICENSE).
