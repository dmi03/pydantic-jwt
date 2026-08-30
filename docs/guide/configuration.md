# Configuration

[`ConfigDict`][pydantic_jwt.ConfigDict] is Pydantic's `ConfigDict` with five
extra keys. Because it subclasses the original, every standard Pydantic setting
keeps working next to the JWT ones:

```python
from pydantic_jwt import ConfigDict, JWTModel


class AccessToken(JWTModel):
    model_config = ConfigDict(
        # JWT keys
        algorithm="HS256",
        encoding_key=SECRET,
        decoding_key=SECRET,
        require_keys=True,
        verified_only=False,
        # ordinary Pydantic keys
        extra="forbid",
        frozen=True,
        populate_by_name=True,
    )

    sub: str
```

## The keys

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `algorithm` | `str` | — | Algorithm used to sign and verify, e.g. `"HS256"`. Passed straight to PyJWT. |
| `encoding_key` | `str \| None` | — | Key used by [`generate()`][pydantic_jwt.JWTModel.generate] and [`jwt_str`][pydantic_jwt.JWTModel.jwt_str]. |
| `decoding_key` | `str \| None` | — | Key used to verify incoming tokens. |
| `require_keys` | `bool` | `True` | Whether a missing key is an error. `False` accepts tokens *without verifying the signature*. |
| `verified_only` | `bool` | `False` | Whether the model refuses to be built from a payload. `True` accepts only verified token strings and [`from_claims()`][pydantic_jwt.JWTModel.from_claims]. |

`ConfigDict` is `total=False`, so any subset is valid — including none of them,
for a model that only ever receives keys per call.

All five are plain `TypedDict` keys, which means a typo like `algorythm=` is
caught by mypy rather than silently ignored at runtime.

## Symmetric keys

For the HMAC family (`HS256`, `HS384`, `HS512`) the same secret signs and
verifies:

```python
import os

SECRET = os.environ["JWT_SECRET"]


class AccessToken(JWTModel):
    model_config = ConfigDict(algorithm="HS256", encoding_key=SECRET, decoding_key=SECRET)

    sub: str
```

Use at least 32 bytes of entropy — `secrets.token_hex(32)` — or PyJWT warns with
`InsecureKeyLengthWarning`.

## Asymmetric algorithms

`RS*`, `ES*`, `PS*` and `EdDSA` need PyJWT's cryptography backend
(`pip install "pyjwt[crypto]"`). The keys are PEM strings: the private key
signs, the public key verifies.

The issuing service holds both, or just the private key:

```python
class AccessToken(JWTModel):
    model_config = ConfigDict(
        algorithm="RS256",
        encoding_key=PRIVATE_KEY_PEM,
        decoding_key=PUBLIC_KEY_PEM,
    )

    sub: str
    exp: Exp = after(minutes=15)
```

A consuming service that only ever *reads* tokens configures the public key and
nothing else. It cannot mint tokens, and `generate()` on it raises
`jwt_missing_key` — which is exactly the desired failure:

```python
class IncomingToken(JWTModel):
    model_config = ConfigDict(algorithm="RS256", decoding_key=PUBLIC_KEY_PEM)

    sub: str
    exp: Exp
```

## Per-call keys

Keys do not have to live in `model_config`. Both directions accept them per
call, which covers key rotation and multi-tenant setups where the key depends on
the request.

**Signing** — [`generate()`][pydantic_jwt.JWTModel.generate]:

```python
raw = token.generate(encoding_key=current_key, algorithm="HS256")
```

**Verifying** — [`from_token()`][pydantic_jwt.JWTModel.from_token]:

```python
token = AccessToken.from_token(raw, decoding_key=current_key, algorithm="HS256")
```

**Verifying through `model_validate()`** — the same values, passed in the
validation context:

```python
token = AccessToken.model_validate(
    raw,
    context={"decoding_key": current_key, "algorithm": "HS256", "require_keys": True},
)
```

The context form is the one to use when the token is a *field* of a larger
model, since there is no `from_token()` call to pass arguments to. Only `str`
values for `decoding_key`/`algorithm` and a `bool` for `require_keys` are read;
anything else in the context is ignored by the signature check (but still
reaches your own validators, and `validate_claims` is read by the
[claim validators](claims.md#skipping-claim-checks)).

### Rotating a signing key

Sign with the newest key, accept any key still in the rotation window:

```python
from pydantic import ValidationError
from pydantic_core import PydanticCustomError

KEYS = {"2024-06": OLD_SECRET, "2024-09": NEW_SECRET}
CURRENT = "2024-09"


def issue(sub: str) -> str:
    return AccessToken(sub=sub).generate(encoding_key=KEYS[CURRENT], algorithm="HS256")


def read(raw: str) -> AccessToken:
    for key in KEYS.values():
        try:
            return AccessToken.from_token(raw, decoding_key=key, algorithm="HS256")
        except (ValidationError, PydanticCustomError):
            continue
    raise ValueError("no configured key verifies this token")
```

Once every token signed with `OLD_SECRET` has expired, drop it from `KEYS`.

!!! tip "Retry only on signature failures"

    The loop above retries on any error, so an expired token is tried against
    every key before failing. To keep the diagnostics sharp, catch
    `jwt_invalid_signature` specifically — see
    [Validation and errors](validation.md#reacting-to-a-specific-error).

## `require_keys`

When a model has no `decoding_key`/`algorithm` and none is supplied per call,
`require_keys` decides what happens:

- `True` (the default) — verification is impossible, so reading the token
  fails with `jwt_missing_key`.
- `False` — the signature is **not checked**. The claims are still validated,
  a warning is logged to the `pydantic_jwt.base` logger, and the model is
  returned.

```python
class UnverifiedToken(JWTModel):
    model_config = ConfigDict(require_keys=False)

    sub: str
    exp: Exp


UnverifiedToken.from_token(anything_at_all)
# WARNING pydantic_jwt.base: JWT token approved without signature verification
```

This is for tests, local development and one-off inspection scripts. In an
application it turns your auth layer into a formality — anybody can forge a
token. See [Security notes](security.md#require_keysfalse-accepts-forged-tokens).

Note that `require_keys` only matters when a key is *missing*. With a key
configured, the signature is always checked, whatever `require_keys` says.

## `verified_only`

`require_keys` governs what happens when a key is missing. `verified_only`
governs something different: whether the model may be built at all from data
that never went through a signature check.

```python
class SessionToken(JWTModel):
    model_config = ConfigDict(algorithm="HS256", decoding_key=SECRET, verified_only=True)

    sub: str
    exp: Exp
```

With it on, a payload — a dict, keyword arguments, a nested object in a request
body — is rejected with `jwt_unverified_payload`. Only a verified token string,
an existing instance, or an explicit
[`from_claims()`][pydantic_jwt.JWTModel.from_claims] call gets through.

This is the setting that makes a token model safe to name as a request-body
field type. The full table of what is and is not accepted is in
[Token models](models.md#refusing-unverified-payloads).

A model that both issues and consumes tokens keeps `verified_only=True` and uses
`from_claims()` on the issuing side:

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


raw = AccessToken.from_claims(sub="user-42").generate()  # issue
token = AccessToken.from_token(raw)  # consume
```

If a model only ever *reads* tokens, `verified_only=True` plus no `encoding_key`
is the tightest configuration available: it can neither be built from a payload
nor sign anything.

## Reading configuration at runtime

`model_config` is a plain dict, so the effective values are readable — handy in
tests and health checks:

```python
AccessToken.model_config["algorithm"]  #> 'HS256'
AccessToken.model_config.get("require_keys", True)  #> True
AccessToken.model_config.get("verified_only", False)  #> False
```

## API reference

Full definition: [`ConfigDict`](../api/config.md).
