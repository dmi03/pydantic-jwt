import time
from dataclasses import dataclass
from typing import Any

from pydantic import GetCoreSchemaHandler
from pydantic_core import PydanticCustomError, core_schema

from .type import JWTStr


@dataclass(frozen=True)
class JWTConstraints:
    """Additional validation constraints for JWTStr, applied via Annotated."""

    allowed_algorithms: tuple[str] | None = None
    exp_name: str = "exp"
    allow_exp: bool = False
    nbf_name: str = "nbf"
    allow_nbf: bool = False

    def __get_pydantic_core_schema__(self, source: type[Any], handler: GetCoreSchemaHandler) -> core_schema.CoreSchema:
        schema = handler(source)
        return core_schema.with_info_after_validator_function(self._validate, schema)

    def _validate(self, value: JWTStr, _: core_schema.ValidationInfo) -> JWTStr:
        if self.allowed_algorithms and value.algorithm not in self.allowed_algorithms:
            raise PydanticCustomError("jwt_format", "Algorithm is not available")

        payload = value.payload

        exp = payload.get(self.exp_name)
        if not self.allow_exp and exp is not None and exp <= time.time():
            raise PydanticCustomError("jwt_expired", "Token is expired")

        nbf = payload.get(self.nbf_name)
        if not self.allow_nbf and nbf is not None and nbf > time.time():
            raise PydanticCustomError("jwt_not_yet_valid", "Token is not yet valid")

        return value
