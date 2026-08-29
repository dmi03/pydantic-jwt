# Claims

A claim marker is a frozen dataclass attached to a field with `Annotated`. It
adds an "after" validator to whatever schema the field already has, so the field
keeps its normal type — an `Exp` really is an `int` — and gains a rule that runs
every time the model validates.

```python
from typing import Annotated

from pydantic_jwt import ExpClaim

exp: Annotated[int, ExpClaim()]
```

Markers are not tied to `JWTModel`. They work on any `BaseModel`, which is
useful when you are validating a payload someone else decoded.

## Time-based claims

Three claims compare an integer timestamp against the current clock. Each has a
ready-made alias so the common case stays short:

| Alias | Expands to | Rule | Registered claim |
| --- | --- | --- | --- |
| [`Exp`](../api/claims.md#aliases) | `Annotated[int, ExpClaim()]` | `value > now` — reject once expired | [RFC 7519 §4.1.4](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4) |
| [`Nbf`](../api/claims.md#aliases) | `Annotated[int, NbfClaim()]` | `value <= now` — reject before it becomes valid | [§4.1.5](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5) |
| [`Iat`](../api/claims.md#aliases) | `Annotated[int, IatClaim()]` | `value <= now` — reject if issued in the future | [§4.1.6](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6) |

```python
from pydantic_jwt import Exp, Iat, JWTModel, Nbf


class SessionToken(JWTModel):
    sub: str
    exp: Exp
    nbf: Nbf
    iat: Iat
```

Each marker also re-checks the type it received and raises `jwt_type` ("Value
must be an integer") for anything that is not an `int`. On the `Exp`/`Nbf`/`Iat`
aliases Pydantic has already produced an `int` by then, so that guard only fires
when you attach a marker to a looser annotation:

```python
exp: Annotated[Any, ExpClaim()]  # 'soon' -> jwt_type, not a crash
```

### Leeway

Server clocks drift. `leeway`, in seconds, widens the accepted window on the
risky side of each check:

```python
from typing import Annotated

from pydantic_jwt import ExpClaim, IatClaim, NbfClaim


class SessionToken(JWTModel):
    exp: Annotated[int, ExpClaim(leeway=30)]  # accept up to 30s after expiry
    nbf: Annotated[int, NbfClaim(leeway=30)]  # accept up to 30s early
    iat: Annotated[int, IatClaim(leeway=30)]  # tolerate a 30s-fast issuer
```

Keep it small — tens of seconds. Leeway on `exp` is extra lifetime granted to
every token, including revoked ones.

### Opting out

A claim you want in the payload but do not want checked is just an `int`:

```python
class SessionToken(JWTModel):
    exp: Exp  # checked
    iat: int  # carried along, never validated
```

## Issuer and audience

[`IssClaim`][pydantic_jwt.IssClaim] and [`AudClaim`][pydantic_jwt.AudClaim] take
the expected value as their argument. They have no aliases, because the value is
specific to your deployment.

```python
from typing import Annotated

from pydantic_jwt import AudClaim, IssClaim, JWTModel

ISSUER = "https://auth.example.com"


class AccessToken(JWTModel):
    sub: str
    iss: Annotated[str, IssClaim(ISSUER)]
    aud: Annotated[str, AudClaim("billing-api")]
```

`iss` is an exact string match — `"https://auth.example.com/"` with a trailing
slash fails.

`aud` follows RFC 7519 and accepts both shapes a token may use. Declare the
field as a union to allow either:

```python
aud: Annotated[str | list[str], AudClaim("billing-api")]
```

- a string — must equal the expected audience;
- a list of strings — the expected audience must be *in* the list.

Anything else raises `jwt_type` ("Value must be a string or a list of
strings").

!!! tip "One issuer, several services"

    Each service declares its own model with its own `AudClaim`, so a token
    minted for `billing-api` is rejected by `reports-api` even though both trust
    the same issuer and key.

## Skipping claim checks

Passing `validate_claims=False` in the validation context disables every claim
marker for one call, while field types, `extra` handling and the signature check
all still run:

```python
token = SessionToken.model_validate(raw, context={"validate_claims": False})
token = SessionToken.from_token(raw, context={"validate_claims": False})
```

Use it to inspect an expired token — logging a stale `sub`, deciding whether to
issue a refresh, writing a test around a fixed payload. It is not a way to
"accept" a token: nothing that comes out of such a call is safe to treat as a
live credential.

Any other context value leaves the checks on:

```python
SessionToken.model_validate(raw, context={"unrelated": True})  # still validated
```

## Custom claims

Subclass [`Claim`][pydantic_jwt.Claim], set `__claim_name__` and implement
`check()`. Return `True` to accept; anything else raises `jwt_claim_invalid` with
the claim name and the offending value in the error context.

```python
import time
from dataclasses import dataclass
from typing import Annotated, Any

from pydantic_core import PydanticCustomError

from pydantic_jwt import Claim


@dataclass(frozen=True)
class AuthTimeClaim(Claim):
    """Reject tokens whose authentication is older than `max_age` seconds."""

    __claim_name__ = "auth_time"

    max_age: float = 3600.0

    def check(self, value: Any) -> bool:
        if not isinstance(value, int):
            raise PydanticCustomError("jwt_type", "Value must be an integer")
        return time.time() - value <= self.max_age


class StepUpToken(JWTModel):
    sub: str
    auth_time: Annotated[int, AuthTimeClaim(max_age=300)]
```

Points worth copying from the built-ins:

- **Keep it `@dataclass(frozen=True)`.** Markers live in `Annotated` metadata,
  which is shared between every instance of the model; a mutable marker is a
  shared mutable global.
- **Validate the type inside `check()`.** Raise `PydanticCustomError("jwt_type", ...)`
  for a value of the wrong shape and reserve the `False` return for a value of
  the right shape that fails the rule. The two produce different error types,
  which callers can tell apart.
- **`check()` sees the value after the field's own validation.** The marker is
  an *after* validator, so on an `Annotated[int, ...]` field Pydantic has already
  produced an `int`. On `Annotated[Any, ...]` it has not, which is why the
  built-ins still check.
- **Respect the context for free.** `validate_claims=False` is handled by the
  base class, not by `check()`.

A custom marker composes with everything else on the field:

```python
from pydantic import Field

jti: Annotated[str, Field(min_length=32), MyClaim()]
```

## API reference

Full signatures: [Claims](../api/claims.md).
