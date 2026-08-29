from __future__ import annotations

import time
import uuid as _uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Annotated, Any, ClassVar

from pydantic import Field, GetCoreSchemaHandler
from pydantic_core import PydanticCustomError, core_schema


@dataclass(frozen=True)
class Claim(ABC):
    """Base class for JWT claim validators.

    Subclass it, set `__claim_name__` and implement `check()`, then attach the
    instance to a field with `Annotated`. The marker runs as an "after"
    validator, so `check()` sees the value once the field's own type has been
    applied.

    Validation can be skipped per call by passing
    `context={'validate_claims': False}` to `model_validate()`.

    Attributes:
        __claim_name__: Name of the claim, reported in the error context.

    Examples:
        ```python
        from typing import Annotated


        @dataclass(frozen=True)
        class AuthTimeClaim(Claim):
            __claim_name__ = 'auth_time'

            def check(self, value: Any) -> bool:
                return value <= time.time()


        auth_time: Annotated[int, AuthTimeClaim()]
        ```
    """

    __claim_name__: ClassVar[str]

    @abstractmethod
    def check(self, value: Any) -> bool:
        """Return whether the claim value is acceptable.

        Return `False` for a well-formed value that fails the rule; raise
        `PydanticCustomError('jwt_type', ...)` for a value of the wrong shape,
        so callers can tell the two apart.
        """
        raise NotImplementedError

    def __get_pydantic_core_schema__(self, source: type[Any], handler: GetCoreSchemaHandler) -> core_schema.CoreSchema:
        schema = handler(source)
        return core_schema.with_info_after_validator_function(self._validate, schema)

    def _validate(self, value: Any, info: core_schema.ValidationInfo) -> Any:
        context = info.context
        if isinstance(context, dict) and not context.get("validate_claims", True):
            return value

        if not self.check(value):
            raise PydanticCustomError(
                "jwt_claim_invalid",
                "{claim} claim is invalid: {value!r}",
                {"claim": self.__claim_name__, "value": value},
            )
        return value


@dataclass(frozen=True)
class ExpClaim(Claim):
    """Reject tokens whose expiry time has passed.

    Attributes:
        leeway: Seconds of clock skew to tolerate past the expiry.
    """

    __claim_name__ = "exp"

    leeway: float = 0.0

    def check(self, value: Any) -> bool:
        if not isinstance(value, int):
            raise PydanticCustomError("jwt_type", "Value must be an integer")
        return value > (time.time() - self.leeway)


@dataclass(frozen=True)
class NbfClaim(Claim):
    """Reject tokens that are not valid yet.

    Attributes:
        leeway: Seconds of clock skew to tolerate before the start time.
    """

    __claim_name__ = "nbf"

    leeway: float = 0.0

    def check(self, value: Any) -> bool:
        if not isinstance(value, int):
            raise PydanticCustomError("jwt_type", "Value must be an integer")
        return value <= (time.time() + self.leeway)


@dataclass(frozen=True)
class IatClaim(Claim):
    """Reject tokens issued in the future.

    Attributes:
        leeway: Seconds of clock skew to tolerate on the issuer's clock.
    """

    __claim_name__ = "iat"

    leeway: float = 0.0

    def check(self, value: Any) -> bool:
        if not isinstance(value, int):
            raise PydanticCustomError("jwt_type", "Value must be an integer")
        return value <= (time.time() + self.leeway)


@dataclass(frozen=True)
class IssClaim(Claim):
    """Reject tokens that were not issued by the expected issuer.

    The comparison is an exact string match.

    Attributes:
        issuer: The only accepted `iss` value.
    """

    __claim_name__ = "iss"

    issuer: str

    def check(self, value: Any) -> bool:
        if not isinstance(value, str):
            raise PydanticCustomError("jwt_type", "Value must be a string")
        return value == self.issuer


@dataclass(frozen=True)
class AudClaim(Claim):
    """Reject tokens that are not addressed to the expected audience.

    Per RFC 7519 the claim may be a single string or a list of strings; a list
    is accepted when it contains the expected audience.

    Attributes:
        audience: The audience this application answers to.
    """

    __claim_name__ = "aud"

    audience: str

    def check(self, value: Any) -> bool:
        if isinstance(value, str):
            return value == self.audience
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            return self.audience in value
        raise PydanticCustomError("jwt_type", "Value must be a string or a list of strings")


Exp = Annotated[int, ExpClaim()]
Nbf = Annotated[int, NbfClaim()]
Iat = Annotated[int, IatClaim()]


def after(
    *,
    weeks: float = 0,
    days: float = 0,
    hours: float = 0,
    minutes: float = 0,
    seconds: float = 0,
    milliseconds: float = 0,
) -> Any:
    """Return a field default holding the current time plus the given duration.

    The value is a `default_factory`, so it is recomputed for every instance.
    The result is truncated to whole seconds, as JWT `NumericDate` requires.

    Args:
        weeks: Weeks to add.
        days: Days to add.
        hours: Hours to add.
        minutes: Minutes to add.
        seconds: Seconds to add.
        milliseconds: Milliseconds to add.

    Returns:
        A `Field()` default suitable for an `Exp`, `Nbf` or `Iat` claim.
    """

    delta = timedelta(
        weeks=weeks,
        days=days,
        hours=hours,
        minutes=minutes,
        seconds=seconds,
        milliseconds=milliseconds,
    )
    total = delta.total_seconds()
    return Field(default_factory=lambda: int(time.time() + total))


def at(moment: datetime) -> Any:
    """Return a field default fixed to the given moment.

    Args:
        moment: The instant the claim should carry. Pass an aware `datetime`: a
            naive one is interpreted in the server's local timezone, which makes
            the token depend on where it was issued.

    Returns:
        A `Field()` default that yields the same timestamp for every instance.
    """

    return Field(default_factory=lambda: int(moment.timestamp()))


def uuid(*, hex_uuid: bool = False) -> Any:
    """Return a field default holding a fresh UUID4, as a hyphenated string or as hex.

    Typically used for `jti`, so every issued token carries a unique id.

    Args:
        hex_uuid: Emit the 32-character hex form without hyphens.

    Returns:
        A `Field()` default that yields a new UUID4 for every instance.
    """

    return Field(default_factory=lambda: _uuid.uuid4().hex if hex_uuid else str(_uuid.uuid4()))
