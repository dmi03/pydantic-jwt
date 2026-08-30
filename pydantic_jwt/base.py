from __future__ import annotations

import logging
from typing import Any, TypeVar

import jwt
from pydantic import BaseModel, GetCoreSchemaHandler, GetJsonSchemaHandler
from pydantic_core import PydanticCustomError, core_schema

from .config import ConfigDict
from .str import JWTStr

T = TypeVar("T", bound="JWTModel")
logger = logging.getLogger(__name__)


class JWTModel(BaseModel):
    """A Pydantic model that is also a JWT.

    Declare the claims as fields and set the keys in `model_config`; the model
    then both issues tokens (`generate()`, `str()`) and validates incoming ones
    (`from_token()`, or by validating a token string into the field).

    Reading a token string verifies its signature; building a model from a
    dict does not, so never treat a model built from request data as
    authenticated.

    Unknown claims are rejected by default (`extra='forbid'`); set
    `extra='ignore'` for tokens from third-party issuers.

    Examples:
        ```python
        from pydantic_jwt import ConfigDict, Exp, JWTModel, after


        class AccessToken(JWTModel):
            model_config = ConfigDict(algorithm='HS256', encoding_key=SECRET, decoding_key=SECRET)

            sub: str
            exp: Exp = after(minutes=15)


        raw = str(AccessToken(sub='user-42'))
        token = AccessToken.from_token(raw)
        print(token.sub)
        #> 'user-42'
        ```
    """

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
        default_schema = handler(source)
        payload_schema = core_schema.with_info_before_validator_function(cls._reject_unverified_payload, default_schema)
        jwt_schema = core_schema.with_info_plain_validator_function(cls._validate_from_str)
        return core_schema.union_schema([jwt_schema, payload_schema], mode="left_to_right")

    @classmethod
    def _reject_unverified_payload(cls, value: Any, info: core_schema.ValidationInfo) -> Any:
        if not cls.model_config.get("verified_only", False):
            return value
        if isinstance(value, cls):
            return value

        context = info.context if isinstance(info.context, dict) else {}
        if context.get("allow_unverified_payload", False):
            return value

        raise PydanticCustomError(
            "jwt_unverified_payload",
            "{model} only accepts a verified token string",
            {"model": cls.__name__},
        )

    @classmethod
    def _validate_from_str(cls: type[T], value: Any, info: core_schema.ValidationInfo) -> T:
        if not isinstance(value, str):
            raise PydanticCustomError("jwt_type", "Value must be a string")

        context = info.context if isinstance(info.context, dict) else {}
        decoding_key = context.get("decoding_key")
        algorithm = context.get("algorithm")
        require_keys = context.get("require_keys")
        decoding_key = decoding_key if isinstance(decoding_key, str) else None
        algorithm = algorithm if isinstance(algorithm, str) else None
        require_keys = require_keys if isinstance(require_keys, bool) else None

        return cls.from_token(
            value, decoding_key=decoding_key, algorithm=algorithm, require_keys=require_keys, context=context
        )

    @classmethod
    def from_token(
        cls: type[T],
        jwt_str: str,
        *,
        decoding_key: str | None = None,
        algorithm: str | None = None,
        require_keys: bool | None = None,
        context: Any | None = None,
    ) -> T:
        """Parse a token string, validate its claims and verify its signature.

        Runs in three steps: structural parse, payload validation, then signature
        verification. A token that fails claim validation never reaches the
        signature check.

        Args:
            jwt_str: The compact token to read.
            decoding_key: Key to verify with, overriding `model_config`.
            algorithm: Algorithm to verify with, overriding `model_config`. It is
                never taken from the token's own `alg` header, which is what
                prevents algorithm-confusion attacks.
            require_keys: Overrides `model_config` for this call.
            context: Validation context forwarded to `model_validate()`. Pass
                `{'validate_claims': False}` to skip the claim markers.

        Returns:
            The validated model.

        Raises:
            ValidationError: The payload is malformed or a claim was rejected.
            PydanticCustomError: The signature does not verify
                (`jwt_invalid_signature`), or no key is available and
                `require_keys` is on (`jwt_missing_key`).
        """

        jwt_obj = JWTStr(jwt_str)
        instance = cls.model_validate(jwt_obj.payload, context={**(context or {}), "allow_unverified_payload": True})
        instance._verify_signature(jwt_str, decoding_key, algorithm, require_keys)
        return instance

    def _verify_signature(
        self, jwt_str: str, decoding_key: str | None, algorithm: str | None, require_keys: bool | None
    ) -> None:
        if not decoding_key:
            decoding_key = self.model_config.get("decoding_key")
        if not algorithm:
            algorithm = self.model_config.get("algorithm")
        if require_keys is None:
            require_keys = self.model_config.get("require_keys", True)

        if decoding_key is None or algorithm is None:
            if require_keys:
                raise PydanticCustomError(
                    "jwt_missing_key",
                    "decoding_key and algorithm must be set in model_config",
                    {"model": self.__class__.__name__, "keys": "decoding_key, algorithm"},
                )
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
        except jwt.InvalidSignatureError:
            raise PydanticCustomError(
                "jwt_invalid_signature", "Invalid token signature for algorithm {algorithm}", {"algorithm": algorithm}
            ) from None

    @property
    def jwt_str(self) -> JWTStr:
        """Return the signed token as a `JWTStr`.

        Signs on every access, exactly like `str()`.
        """
        return JWTStr(self.generate())

    def __str__(self) -> str:
        return self.generate()

    def generate(self, *, encoding_key: str | None = None, algorithm: str | None = None) -> str:
        """Encode the model as a signed token.

        The payload is `model_dump(mode='json')`, so custom field serialisers
        decide what lands in the token.

        Args:
            encoding_key: Key to sign with, overriding `model_config`. Useful
                during key rotation.
            algorithm: Algorithm to sign with, overriding `model_config`.

        Returns:
            The compact, signed token.

        Raises:
            PydanticCustomError: No key or algorithm is available
                (`jwt_missing_key`).
        """

        if encoding_key is None:
            encoding_key = self.model_config.get("encoding_key")
        if algorithm is None:
            algorithm = self.model_config.get("algorithm")

        if encoding_key is None or algorithm is None:
            raise PydanticCustomError(
                "jwt_missing_key",
                "encoding_key and algorithm must be set in model_config to generate a token",
                {"model": self.__class__.__name__, "keys": "encoding_key, algorithm"},
            )

        payload = self.model_dump(mode="json")
        return jwt.encode(payload, encoding_key, algorithm=algorithm)
