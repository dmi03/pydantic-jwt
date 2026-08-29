# Token models

[`JWTModel`][pydantic_jwt.JWTModel] is a `pydantic.BaseModel` subclass whose
instances are JWTs. Everything a normal Pydantic model can do — validators,
computed fields, nested models, aliases, inheritance — still applies; the class
adds encoding, decoding and signature verification on top.

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

## Issuing tokens

### `generate()`

[`generate()`][pydantic_jwt.JWTModel.generate] dumps the model with
`model_dump(mode="json")` and signs the result:

```python
raw = AccessToken(sub="user-42").generate()
```

`mode="json"` means every field is serialised the way it would be in JSON — a
`datetime` claim becomes an ISO-8601 string, an `Enum` becomes its value, a
`UUID` becomes a string. Custom serialisers declared with
`@field_serializer` are respected, so you control exactly what lands in the
payload.

Both arguments are optional and override `model_config`:

```python
raw = token.generate(encoding_key=next_key, algorithm="HS512")
```

This is how key rotation is done without declaring a second model — see
[Configuration](configuration.md#per-call-keys).

If neither the argument nor `model_config` supplies a key and an algorithm,
`generate()` raises a `jwt_missing_key` error.

### `str()`

`__str__` is `generate()`, so a token model can be dropped anywhere a string is
expected:

```python
raw = str(token)
headers = {"Authorization": f"Bearer {token}"}
```

!!! warning "`str()` signs the token"

    Because `__str__` signs, printing a model in a log statement or an f-string
    writes a *valid credential* to the log. It also raises `jwt_missing_key` on
    a model without an `encoding_key`, which can turn a debug `print()` into an
    exception. Use `repr(token)` or `token.model_dump()` when you only want to
    look at the claims.

### `jwt_str`

[`jwt_str`][pydantic_jwt.JWTModel.jwt_str] returns the signed token as a
[`JWTStr`](jwt-str.md) — a `str` subclass with `header`, `payload`, `algorithm`
and `signature` properties:

```python
token = AccessToken(sub="user-42")

token.jwt_str == str(token)  #> True
token.jwt_str.header  #> {'alg': 'HS256', 'typ': 'JWT'}
token.jwt_str.payload  #> {'sub': 'user-42', 'exp': 1788009360}
```

It signs on every access, exactly like `str()`.

## Reading tokens

### `from_token()`

[`from_token()`][pydantic_jwt.JWTModel.from_token] is the explicit entry point:

```python
token = AccessToken.from_token(raw)
```

It runs three steps, in this order:

1. **Structural parse.** The string is wrapped in [`JWTStr`](jwt-str.md), which
   checks that it is three base64url segments whose header and payload decode to
   JSON objects.
2. **Claim validation.** The payload is passed to `model_validate()`, so field
   types, `Exp`/`Nbf`/`Iat`/`iss`/`aud` checks, `extra="forbid"` and any
   validators of your own run here.
3. **Signature verification.** The raw string is handed to `jwt.decode()` with
   `decoding_key` and `algorithm`.

!!! note "Claims are checked before the signature"

    A token that is both expired and forged reports the expiry, because step 2
    runs first. Never treat a *specific* error type as evidence about the rest of
    the token — only a `from_token()` call that returns is a token that passed
    everything.

The keyword arguments override `model_config` for one call:

```python
AccessToken.from_token(
    raw,
    decoding_key=old_key,
    algorithm="HS256",
    require_keys=True,
    context={"validate_claims": False},
)
```

The algorithm is **never** taken from the token's own `alg` header. That closes
the classic algorithm-confusion attack, in which an attacker re-signs a token
with `alg: HS256` using a public RSA key as the HMAC secret.

### `model_validate()` on a string

`JWTModel` installs a union core schema — *token string first, then the normal
model schema* — so validating a string does the same work as `from_token()`:

```python
AccessToken.model_validate(raw)  # parses, validates, verifies
AccessToken.model_validate({"sub": "user-42"})  # plain model construction
```

That union is what makes a token model usable as a *field type*:

```python
from pydantic import BaseModel


class Session(BaseModel):
    access_token: AccessToken


session = Session(access_token=raw)  # the string is verified here
session.access_token.sub  #> 'user-42'
```

!!! warning "Only a *string* is verified"

    `AccessToken(sub="x")` and `AccessToken.model_validate({"sub": "x"})` take
    the dictionary branch of the union: no signature is involved, because you
    are building a token to sign, not checking one. Never accept an
    `AccessToken` straight out of a request body and treat it as authenticated —
    see [Security notes](security.md#a-model-built-from-a-dict-is-not-authenticated).

Errors from the string branch are reported by Pydantic as a union failure, so
`exc.errors()` contains one entry per branch. The JWT-specific entry is the one
whose `type` starts with `jwt_`.

## Configuration inheritance

`model_config` follows Pydantic's rules — a subclass merges its parent's
config — which makes a shared base model the natural place to put keys:

```python
class Signed(JWTModel):
    model_config = ConfigDict(algorithm="HS256", encoding_key=SECRET, decoding_key=SECRET)


class AccessToken(Signed):
    sub: str
    exp: Exp = after(minutes=15)


class RefreshToken(Signed):
    model_config = ConfigDict(encoding_key=REFRESH_SECRET, decoding_key=REFRESH_SECRET)

    sub: str
    exp: Exp = after(days=30)
    jti: str = uuid()
```

`RefreshToken` keeps `algorithm="HS256"` from `Signed` and overrides only the
keys.

## Unknown claims

`JWTModel` sets `extra="forbid"` by default, so a token carrying a claim the
model does not declare is rejected with `extra_forbidden`. That is the right
default for tokens you issue yourself: it means the model is an exhaustive
description of the payload.

Third-party issuers (Auth0, Keycloak, Google) add their own claims. Either
declare them, or relax the config:

```python
class GoogleIdToken(JWTModel):
    model_config = ConfigDict(extra="ignore", algorithm="RS256", decoding_key=PUBLIC_KEY)

    sub: str
    email: str
    exp: Exp
```

`extra="allow"` keeps the undeclared claims on the instance and round-trips them
back into a re-signed token.

## JSON Schema and OpenAPI

A `JWTModel` describes itself to JSON Schema as a *string*, not an object,
because that is what travels over the wire:

```python
AccessToken.model_json_schema()
#> {
#>   "type": "string",
#>   "format": "jwt",
#>   "description": "JWT token containing claims: sub, exp"
#> }
```

Used as a field, it keeps that shape:

```json
{
  "type": "object",
  "properties": {
    "access_token": {
      "type": "string",
      "format": "jwt",
      "title": "Access Token",
      "description": "JWT token containing claims: sub, exp"
    }
  },
  "required": ["access_token"]
}
```

The schema says "string", but serialisation does not sign — see below.

## Serialisation

Validation is asymmetric with serialisation, and it is worth knowing exactly
what each call returns:

| Call | Result |
| --- | --- |
| `str(token)`, `token.jwt_str` | the signed compact token |
| `token.model_dump(mode="json")` | `dict[str, Any]` of claims — what `generate()` signs |
| `token.model_dump_json()` | JSON object of claims, e.g. `'{"sub":"user-42"}'` |
| `dict(token)` | `dict` of claims, values unconverted |
| `token.model_dump()` | the model instance itself, **not** a dict |

That last row is a consequence of the token-string-first union schema: the
plain-validator branch carries no serialiser, so Python-mode dumping passes the
object through unchanged. The same applies to a nested field —
`Session(access_token=raw).model_dump()` yields
`{"access_token": AccessToken(...)}`, while `model_dump_json()` yields a nested
JSON *object* of claims rather than the compact token.

So: **use `mode="json"` whenever you want claims as data**, and build the wire
representation explicitly:

```python
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


TokenResponse(access_token=str(AccessToken(sub="user-42")))
```

## API reference

Full signatures: [`JWTModel`](../api/model.md).
