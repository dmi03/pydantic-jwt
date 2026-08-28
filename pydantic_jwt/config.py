from __future__ import annotations

from pydantic import ConfigDict as PydanticConfigDict


class ConfigDict(PydanticConfigDict, total=False):
    algorithm: str
    encoding_key: str | None
    decoding_key: str | None
    require_keys: bool
