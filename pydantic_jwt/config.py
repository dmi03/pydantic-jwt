from __future__ import annotations

from pydantic import ConfigDict as PydanticConfigDict


class ConfigDict(PydanticConfigDict, total=False):
    """Pydantic's `ConfigDict` extended with the keys `JWTModel` reads.

    Set it as `model_config` on your token model; the standard Pydantic keys
    keep working alongside these. Every key is optional.

    Examples:
        ```python
        from pydantic_jwt import ConfigDict, JWTModel


        class AccessToken(JWTModel):
            model_config = ConfigDict(algorithm='HS256', encoding_key=SECRET, decoding_key=SECRET)

            sub: str
        ```

    Attributes:
        algorithm: Algorithm used to sign and verify tokens, e.g. `'HS256'`.
        encoding_key: Key used to sign tokens in `generate()`.
        decoding_key: Key used to verify incoming tokens.
        require_keys: Whether a missing key is an error. Defaults to `True`. When
            `False`, tokens are accepted without signature verification and a
            warning is logged.
    """

    algorithm: str
    encoding_key: str | None
    decoding_key: str | None
    require_keys: bool
