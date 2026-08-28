from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Annotated, Any, ClassVar

from pydantic import Field, GetCoreSchemaHandler
from pydantic_core import PydanticCustomError, core_schema


@dataclass(frozen=True)
class Claim(ABC):
    """Base class for time-based JWT claim validators.

        Subclass it, set `__claim_name__` and implement `check()`, then attach the
        instance to an `int` field with `Annotated`. Validation can be skipped per
        call by passing `context={'validate_claims': False}` to `model_validate()`.

        ## Examples
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
        """Return whether the claim value is acceptable at the current time."""
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
    """Reject tokens whose expiry time has passed."""

    __claim_name__ = "exp"

    leeway: float = 0.0

    def check(self, value: Any) -> bool:
        if not isinstance(value, int):
            raise PydanticCustomError("jwt_type", "Value must be an integer")
        return value > (time.time() - self.leeway)


@dataclass(frozen=True)
class NbfClaim(Claim):
    """Reject tokens that are not valid yet."""

    __claim_name__ = "nbf"

    leeway: float = 0.0

    def check(self, value: Any) -> bool:
        if not isinstance(value, int):
            raise PydanticCustomError("jwt_type", "Value must be an integer")
        return value <= (time.time() + self.leeway)


@dataclass(frozen=True)
class IatClaim(Claim):
    """Reject tokens issued in the future."""

    __claim_name__ = "iat"

    leeway: float = 0.0

    def check(self, value: Any) -> bool:
        if not isinstance(value, int):
            raise PydanticCustomError("jwt_type", "Value must be an integer")
        return value <= (time.time() + self.leeway)


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
    """Return a field default that expires the given duration from now."""

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

    A naive `datetime` is interpreted in the server's local timezone.
    """

    return Field(default_factory=lambda: int(moment.timestamp()))
