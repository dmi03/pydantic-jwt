# Defaults

Three helpers produce Pydantic field defaults for the values a token needs
generated at issue time. All of them return a `Field(default_factory=...)`, so
the value is computed **per instance** — every token gets its own timestamp and
its own id.

```python
from pydantic_jwt import Exp, Iat, JWTModel, after, at, uuid


class AccessToken(JWTModel):
    sub: str
    exp: Exp = after(minutes=15)
    iat: Iat = after()
    jti: str = uuid()
```

## `after()`

[`after()`][pydantic_jwt.after] returns "now plus a duration", as an integer
epoch second.

```text
after(*, weeks=0, days=0, hours=0, minutes=0, seconds=0, milliseconds=0)
```

All arguments are keyword-only, accept floats, and add up:

```python
exp: Exp = after(hours=1, minutes=30)  # 5400 seconds from now
exp: Exp = after(days=30)  # a refresh-token lifetime
iat: Iat = after()  # no arguments: now
```

The duration is fixed when the class is defined; the *base* is read fresh on
every instantiation:

```python
class SessionToken(JWTModel):
    exp: Exp = after(minutes=5)


first = SessionToken()  # exp = t0 + 300
# ... an hour passes ...
second = SessionToken()  # exp = t0 + 3600 + 300
```

The result is truncated to a whole second with `int()`, as JWT `NumericDate`
requires.

!!! tip "Short access tokens, long refresh tokens"

    A conventional split is `after(minutes=15)` for an access token and
    `after(days=30)` for a refresh token. Since a JWT cannot be revoked before it
    expires, the access token's lifetime is your worst-case exposure window.

## `at()`

[`at()`][pydantic_jwt.at] pins a claim to a fixed moment rather than an offset:

```python
from datetime import datetime, timezone

from pydantic_jwt import Nbf, at


class ScheduledToken(JWTModel):
    sub: str
    nbf: Nbf = at(datetime(2030, 1, 1, tzinfo=timezone.utc))
```

Every instance gets the same timestamp — useful for a token that must not become
valid until a launch date, or for deterministic tests.

!!! warning "Always pass an aware `datetime`"

    `at()` uses `datetime.timestamp()`, and a naive `datetime` is interpreted in
    the *server's* local timezone. The same code then produces different tokens
    on a developer laptop and a UTC container. Pass `tzinfo=timezone.utc` (or
    any explicit zone).

## `uuid()`

[`uuid()`][pydantic_jwt.uuid] returns a fresh UUID4 string per instance —
normally for the `jti` claim, which
[RFC 7519 §4.1.7](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7)
defines as a unique identifier for the token.

```python
class AccessToken(JWTModel):
    sub: str
    jti: str = uuid()  # '9f1c7c9e-2f6b-4f8f-b0d2-0f4a1f3d2a11'
```

Pass `hex_uuid=True` for the 32-character form without hyphens:

```python
jti: str = uuid(hex_uuid=True)  # '9f1c7c9e2f6b4f8fb0d20f4a1f3d2a11'
```

A `jti` is what makes selective revocation possible: store the ids of tokens you
want to reject in a denylist keyed until their `exp`, and check it after
validation.

```python
token = AccessToken.from_token(raw)
if await revoked.exists(token.jti):
    raise PermissionError("token revoked")
```

## Return types

All three are annotated `-> Any`, deliberately: they return a `FieldInfo`, but
annotating them as such would make `exp: Exp = after(minutes=15)` a type error in
every checker. `Any` lets the assignment type-check against the field's real
annotation.

You can therefore combine them with other `Field()` settings only by dropping to
`Field()` directly:

```python
from pydantic import Field

exp: Exp = Field(default_factory=lambda: int(time.time() + 900), description="Expiry")
```

## Anything else Pydantic can do

These helpers are conveniences, not a closed set. Any `default_factory` works:

```python
from pydantic import Field


class AccessToken(JWTModel):
    sub: str
    iss: str = "https://auth.example.com"  # a constant default
    scope: list[str] = Field(default_factory=list)
    kid: str = Field(default_factory=current_key_id)
```

## API reference

Full signatures: [Claims and defaults](../api/claims.md#pydantic_jwt.after).
