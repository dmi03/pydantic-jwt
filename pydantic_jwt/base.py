import logging
from typing import Any, TypedDict, TypeVar

import jwt
from pydantic import BaseModel, GetCoreSchemaHandler, GetJsonSchemaHandler
from pydantic_core import PydanticCustomError, core_schema

from .config import ConfigDict
from .markers import ClaimName, Marker
from .str import JWTStr

T = TypeVar("T", bound="BasePayload")
logger = logging.getLogger(__name__)


class _ClaimMeta(TypedDict):
    claim: ClaimName
    valid: bool
    value: Any


class BasePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @classmethod
    def __get_pydantic_json_schema__(
        cls, schema: core_schema.CoreSchema, handler: GetJsonSchemaHandler
    ) -> dict[str, Any]:
        return {
            "type": "string",
            "format": "jwt",
            "description": f"JWT token containing claims: {', '.join(cls.model_fields.keys())}",
        }

    @classmethod
    def __get_pydantic_core_schema__(cls, source: type[Any], handler: GetCoreSchemaHandler) -> core_schema.CoreSchema:
        return core_schema.no_info_plain_validator_function(cls._validate_from_str)

    @classmethod
    def _validate_from_str(cls: type[T], value: Any) -> T:
        if not isinstance(value, str):
            raise PydanticCustomError("jwt_type", "Value must be a string")
        return cls.from_token(value)

    @classmethod
    def from_token(cls: type[T], jwt_str: str) -> T:
        jwt_obj = JWTStr(jwt_str)
        instance = cls.model_validate(jwt_obj.payload)
        instance._verify_metadata()
        instance._verify_signature(jwt_str)
        return instance

    def _verify_signature(self, jwt_str: str) -> None:
        decoding_key = self.model_config.get("decoding_key")
        algorithm = self.model_config.get("algorithm")
        require_keys = self.model_config.get("require_keys", True)

        if decoding_key is None or algorithm is None:
            if require_keys:
                raise PydanticCustomError("jwt_missing_key", "decoding_key and algorithm must be set in model_config")
            logger.warning("JWT token approved without signature verification")
            return

        try:
            jwt.decode(
                jwt_str,
                decoding_key,
                algorithms=[algorithm],
                options={
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "verify_aud": False,
                    "verify_iss": False,
                },
            )
        except (jwt.InvalidSignatureError, jwt.DecodeError):
            raise PydanticCustomError("jwt_invalid_signature", "Invalid token signature") from None

    def __str__(self) -> str:
        return self.generate()

    def generate(self, *, encoding_key: str | None = None, algorithm: str | None = None) -> str:
        if encoding_key is None:
            encoding_key = self.model_config.get("encoding_key")
        if algorithm is None:
            algorithm = self.model_config.get("algorithm")

        if encoding_key is None or algorithm is None:
            raise PydanticCustomError(
                "jwt_missing_key", "encoding_key and algorithm must be set in model_config to generate a token"
            )

        payload = self.model_dump(mode="json")
        return jwt.encode(payload, encoding_key, algorithm=algorithm)

    def _verify_metadata(self) -> None:
        for name, meta in self._load_metadata().items():
            if not meta["valid"]:
                raise PydanticCustomError(
                    "jwt_claim_invalid",
                    "Claim {claim!r} (field {field!r}) is invalid: {value!r}",
                    {"claim": meta["claim"].value, "field": name, "value": meta["value"]},
                )

    def _load_metadata(self) -> dict[str, _ClaimMeta]:
        dumped = self.model_dump(mode="json")
        metadata: dict[str, _ClaimMeta] = {}

        for field_name, field_info in self.model_fields.items():
            annotation = field_info.annotation

            if isinstance(annotation, type) and issubclass(annotation, Marker):
                value = dumped.get(field_name)

                if value is None and not field_info.is_required():
                    continue

                is_valid = value is not None and annotation.validate(value)

                metadata[field_name] = {
                    "claim": annotation.__key__,
                    "valid": is_valid,
                    "value": value,
                }

        return metadata
