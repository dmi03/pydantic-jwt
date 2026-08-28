from __future__ import annotations

from pydantic import ConfigDict as PydanticConfigDict

from pydantic_jwt import ConfigDict


def test_config_dict_accepts_known_keys():
    config = ConfigDict(
        algorithm="HS256",
        encoding_key="secret",
        decoding_key="secret",
        require_keys=True,
    )
    assert config["algorithm"] == "HS256"
    assert config["encoding_key"] == "secret"
    assert config["decoding_key"] == "secret"
    assert config["require_keys"] is True


def test_config_dict_is_partial():
    # total=False — any subset of keys should be valid
    config: ConfigDict = ConfigDict(algorithm="HS256")
    assert config == {"algorithm": "HS256"}


def test_config_dict_empty_is_valid():
    config: ConfigDict = ConfigDict()
    assert config == {}


def test_config_dict_extends_pydantic_config_dict_keys():
    pydantic_keys = set(PydanticConfigDict.__annotations__)
    my_keys = set(ConfigDict.__annotations__)
    assert pydantic_keys.issubset(my_keys)
