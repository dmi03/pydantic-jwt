# pydantic-jwt

**JWT tokens as Pydantic models.**

Declare a token as a model, and get parsing, claim validation, signature
verification and encoding out of it — with every claim typed, autocompleted and
checked like any other Pydantic field.

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


raw = AccessToken(sub="user-42").generate()  # issue
token = AccessToken.from_token(raw)  # read back, verified
token.sub  #> 'user-42'
```

## Why

Most JWT code ends up as a dictionary passed around by hand: claims spelled out
as string keys, validated in a helper somewhere, and typed as `dict[str, Any]`
by the time it reaches the code that needs it. `pydantic-jwt` moves the token
into the type system:

- **One class is both ends of the flow.** The same model issues tokens and
  validates incoming ones. There is no second place where the claim set is
  written down and no chance for the two to drift apart.
- **Claims validate themselves.** `Exp`, `Nbf` and `Iat` compare against the
  current clock; `IssClaim` and `AudClaim` compare against expected values. They
  are plain `Annotated` types, so they compose with anything
  else Pydantic can do to a field.
- **Failures are `ValidationError`s.** A stale, forged or malformed token fails
  the same way a bad request body does, so it fits wherever Pydantic already
  does — including a FastAPI dependency.
- **Unverified data can be refused outright.** `verified_only=True` makes the
  model accept nothing but a token whose signature was checked, so "I forgot this
  one came from the request body" stops being a class of bug.
- **Fully typed.** The package ships a `py.typed` marker, is checked under
  `mypy --strict`, and models report themselves to OpenAPI as
  `{"type": "string", "format": "jwt"}`.

## Feature tour

| Feature | Where |
| --- | --- |
| `JWTModel` — issue and verify tokens from one class | [Token models](guide/models.md) |
| `verified_only` and `from_claims()` — refuse unverified payloads | [Token models](guide/models.md#refusing-unverified-payloads) |
| `ConfigDict` — keys, algorithm, `require_keys`, `verified_only` | [Configuration](guide/configuration.md) |
| `Exp`, `Nbf`, `Iat`, `IssClaim`, `AudClaim`, custom `Claim`s | [Claims](guide/claims.md) |
| `after()`, `at()`, `uuid()` field defaults | [Defaults](guide/defaults.md) |
| Error types, validation context, per-call keys | [Validation and errors](guide/validation.md) |
| `JWTStr` — inspect a token without verifying it | [Working with raw tokens](guide/jwt-str.md) |
| What this library does *not* check for you | [Security notes](guide/security.md) |
| A complete auth flow | [FastAPI integration](integrations/fastapi.md) |

## Install

```bash
pip install pydantic-jwt
```

See [Installation](installation.md) for `uv`/Poetry, optional algorithm support
and version requirements, or jump straight into the
[Quickstart](quickstart.md).

## License

MIT. Source on [GitHub](https://github.com/dmi03/pydantic-jwt).
