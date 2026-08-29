# Validation and errors

Everything this library rejects is reported as a Pydantic error with a stable
`type` string, so you can branch on the reason without matching on message text.

## Error types

| `type` | Raised when | Context (`ctx`) |
| --- | --- | --- |
| `jwt_format` | The string is not three dot-separated segments, the segments are not urlsafe base64, or header/payload are not JSON. | — |
| `jwt_type` | A value has the wrong Python type: a non-string where a token was expected, a non-`int` for a time claim, a non-string `iss`, an `aud` that is neither a string nor a list of strings. | — |
| `jwt_claim_invalid` | A [claim marker](claims.md) rejected the value — expired, not yet valid, issued in the future, wrong issuer or audience. | `{"claim": ..., "value": ...}` |
| `jwt_invalid_signature` | The signature does not verify with the configured key and algorithm. | `{"algorithm": ...}` |
| `jwt_missing_key` | No key/algorithm is available for the operation and `require_keys` is on. | `{"model": ..., "keys": ...}` |
| `extra_forbidden` | The token carries a claim the model does not declare (Pydantic's own error). | — |

Reading them off a `ValidationError`:

```python
from pydantic import ValidationError

try:
    AccessToken.model_validate(raw)
except ValidationError as exc:
    for error in exc.errors():
        print(error["type"], error.get("ctx"))
    #> jwt_claim_invalid {'claim': 'exp', 'value': 1712345678}
```

Which *exception* carries them depends on how you entered — see the next
section.

!!! note "`jwt_claim_invalid` messages are not interpolated"

    The `msg` for a claim failure reads `exp claim is invalid: {value!r}` — the
    `!r` conversion is not applied by `pydantic-core`, so the placeholder is
    shown literally. The real value is in `ctx["value"]`; use that rather than
    the message when you need to display it.

## `ValidationError` vs `PydanticCustomError`

Which exception you catch depends on how you entered:

```python
# model_validate() -> always ValidationError
AccessToken.model_validate(raw)

# from_token() -> ValidationError only for payload/claim failures;
#                 PydanticCustomError for structural, signature and key failures
AccessToken.from_token(raw)
```

Of the three steps `from_token()` runs, only the middle one goes through
Pydantic. The structural parse and the signature check happen outside any
validation pass, so they raise `PydanticCustomError` directly:

| Step | `from_token()` raises |
| --- | --- |
| structural parse | `PydanticCustomError` (`jwt_format`, `jwt_type`) |
| payload validation | `ValidationError` (`jwt_claim_invalid`, `extra_forbidden`, …) |
| signature verification | `PydanticCustomError` (`jwt_invalid_signature`, `jwt_missing_key`) |

`generate()` is in the same position: it raises `jwt_missing_key` as a bare
`PydanticCustomError`.

`model_validate()` calls `from_token()` from inside a validator, which is why
everything comes back wrapped there.

Both `ValidationError` and `PydanticCustomError` subclass `ValueError`, so a
single `except ValueError` catches every rejection this library produces:

```python
try:
    token = AccessToken.from_token(raw)
except ValueError:
    ...  # malformed, expired, forged or misconfigured
```

Catch the two separately only when you want to tell claim failures from
signature failures — see [below](#reacting-to-a-specific-error).

Prefer `model_validate()` when you would rather have one exception type — for
example in a FastAPI dependency.

## Order of checks

`from_token()` runs, in order:

1. structural parse (`jwt_format`, `jwt_type`);
2. payload validation — types, claim markers, `extra` (`jwt_claim_invalid`,
   `extra_forbidden`, ordinary Pydantic errors);
3. signature verification (`jwt_invalid_signature`, `jwt_missing_key`).

A token that fails at step 2 never reaches step 3, so **an expired token that is
also forged reports the expiry**. Do not read anything into which error came
back other than "this token was not accepted"; only a call that *returns* means
the token passed every check.

## Union errors from `model_validate()`

`JWTModel`'s core schema is a left-to-right union — the token-string branch,
then the ordinary model branch. When the input is a string and the string branch
fails, Pydantic reports both branches:

```text
2 validation errors for AccessToken
function-plain[_validate_from_str()]
  Invalid token signature for algorithm HS256 [type=jwt_invalid_signature, ...]
AccessToken
  Input should be a valid dictionary or instance of AccessToken [type=model_type, ...]
```

The second entry is noise from the branch that was never going to match. Filter
on the prefix:

```python
jwt_errors = [e for e in exc.errors() if e["type"].startswith("jwt_")]
```

## Reacting to a specific error

Signature failures deserve different handling from expiry — one is an attack or
a stale key, the other is a routine "go refresh":

```python
from pydantic import ValidationError
from pydantic_core import PydanticCustomError


def classify(raw: str) -> str:
    try:
        AccessToken.from_token(raw)
    except ValidationError as exc:
        types = {error["type"] for error in exc.errors()}
        return "expired-or-wrong-claim" if "jwt_claim_invalid" in types else "bad-payload"
    except PydanticCustomError as exc:
        return {
            "jwt_format": "malformed",
            "jwt_type": "malformed",
            "jwt_invalid_signature": "forged",
            "jwt_missing_key": "misconfigured",
        }.get(exc.type, "rejected")
    return "ok"
```

`PydanticCustomError` exposes `.type` and `.context`, matching the `type` and
`ctx` you would see in `errors()`. Under `model_validate()` the same
information is in `exc.errors()` instead, since every branch is wrapped:

```python
try:
    AccessToken.model_validate(raw)
except ValidationError as exc:
    types = {error["type"] for error in exc.errors()}
    forged = "jwt_invalid_signature" in types
```

## Validation context

The context dict passed to `model_validate()` — or to `from_token(context=...)`
— carries four keys this library reads:

| Key | Type | Effect |
| --- | --- | --- |
| `validate_claims` | `bool` | `False` disables every [claim marker](claims.md#skipping-claim-checks) for this call. |
| `decoding_key` | `str` | Key to verify with, overriding `model_config`. |
| `algorithm` | `str` | Algorithm to verify with, overriding `model_config`. |
| `require_keys` | `bool` | Overrides `model_config` for this call. |

```python
AccessToken.model_validate(
    raw,
    context={"decoding_key": tenant_key, "algorithm": "HS256"},
)
```

Values of the wrong type are ignored rather than raising, and the whole context
is forwarded to your own validators, so you can put unrelated keys in it.

The context is the only way to influence verification when the token is a nested
field, since there is no `from_token()` call to pass arguments to:

```python
class Session(BaseModel):
    access_token: AccessToken


Session.model_validate({"access_token": raw}, context={"decoding_key": tenant_key})
```

## Testing tokens

Two things make tests straightforward:

- `require_keys=False` lets a fixture model read any token without a key.
- `context={"validate_claims": False}` freezes time out of the picture for a
  fixed payload.

```python
import secrets

import pytest

KEY = secrets.token_hex(32)


@pytest.fixture
def token() -> str:
    return AccessToken(sub="user-42").generate(encoding_key=KEY, algorithm="HS256")


def test_rejects_a_forged_token(token: str) -> None:
    forged = AccessToken(sub="attacker").generate(
        encoding_key=secrets.token_hex(32), algorithm="HS256"
    )
    with pytest.raises(ValueError):
        AccessToken.from_token(forged, decoding_key=KEY, algorithm="HS256")
```

Use a 32-byte key even in tests, or PyJWT will warn on every call.
