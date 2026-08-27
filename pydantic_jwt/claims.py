import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Annotated, Any, ClassVar

from pydantic import Field, GetCoreSchemaHandler
from pydantic_core import PydanticCustomError, core_schema


@dataclass(frozen=True)
class Claim(ABC):
    __claim_name__: ClassVar[str]

    validate: bool = True

    @abstractmethod
    def check(self, value: Any) -> bool:
        raise NotImplementedError

    def __get_pydantic_core_schema__(self, source: type[Any], handler: GetCoreSchemaHandler) -> core_schema.CoreSchema:
        schema = handler(source)
        if not self.validate:
            return schema
        return core_schema.with_info_after_validator_function(self._validate, schema)

    def _validate(self, value: Any, info: core_schema.ValidationInfo) -> Any:
        context = info.context
        if isinstance(context, dict) and not context.get("validate_claims", True):
            return value
        if not self.validate:
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
    __claim_name__ = "exp"

    leeway: float = 0.0

    def check(self, value: Any) -> bool:
        if not isinstance(value, int):
            raise PydanticCustomError("jwt_type", "Value must be an integer")
        return value > (time.time() - self.leeway)


@dataclass(frozen=True)
class NbfClaim(Claim):
    __claim_name__ = "nbf"

    leeway: float = 0.0

    def check(self, value: Any) -> bool:
        if not isinstance(value, int):
            raise PydanticCustomError("jwt_type", "Value must be an integer")
        return value <= (time.time() + self.leeway)


@dataclass(frozen=True)
class IatClaim(Claim):
    __claim_name__ = "iat"

    leeway: float = 0.0

    def check(self, value: Any) -> bool:
        if not isinstance(value, int):
            raise PydanticCustomError("jwt_type", "Value must be an integer")
        return value <= (time.time() + self.leeway)


Exp = Annotated[int, ExpClaim()]
Nbf = Annotated[int, NbfClaim()]
Iat = Annotated[int, IatClaim()]


_ALIASES = {
    "sec": "seconds",
    "secs": "seconds",
    "s": "seconds",
    "min": "minutes",
    "mins": "minutes",
    "m": "minutes",
    "hour": "hours",
    "h": "hours",
    "day": "days",
    "d": "days",
    "week": "weeks",
    "w": "weeks",
    "ms": "milliseconds",
}


def after(**duration: float) -> Any:
    delta = timedelta(**{_ALIASES.get(k, k): v for k, v in duration.items()})
    seconds = delta.total_seconds()
    return Field(default_factory=lambda: int(time.time() + seconds))


def at(moment: datetime) -> Any:
    return Field(default_factory=lambda: int(moment.timestamp()))
