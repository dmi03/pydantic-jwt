from __future__ import annotations

import logging
import secrets
import time
from collections.abc import Callable
from typing import Any

import jwt
import pytest
from pydantic import ValidationError
from pydantic_core import PydanticCustomError

from pydantic_jwt import ConfigDict, Exp, JWTModel, JWTStr

KEY = secrets.token_hex(32) + "-1"
OTHER_KEY = secrets.token_hex(32) + "-2"
ALGORITHM = "HS256"


class Token(JWTModel):
    model_config = ConfigDict(
        extra="forbid",
        encoding_key=KEY,
        decoding_key=KEY,
        algorithm=ALGORITHM,
    )

    sub: str


class StrictToken(JWTModel):
    sub: str


class UnsignedToken(JWTModel):
    model_config = ConfigDict(require_keys=False)

    sub: str


class ExpiringToken(Token):
    exp: Exp


class KeylessToken(JWTModel):
    sub: str


def encode(key: str = KEY, **kwargs) -> str:
    return jwt.encode({**kwargs}, key, algorithm=ALGORITHM)


def test_json_schema_describes_a_jwt_string() -> None:
    schema = Token.model_json_schema()

    assert schema["type"] == "string"
    assert schema["format"] == "jwt"
    assert "sub" in schema["description"]


def test_token_survives_a_full_round_trip() -> None:
    token = Token(sub="user")

    assert Token.model_validate(str(token)) == token


def test_union_falls_back_to_regular_model_validation() -> None:
    assert Token.model_validate({"sub": "user"}).sub == "user"

    with pytest.raises(ValidationError) as exc_info:
        Token.model_validate(42)

    assert "jwt_type" in {error["type"] for error in exc_info.value.errors()}


def test_jwt_str_property_returns_a_parsed_token() -> None:
    token = Token(sub="user")

    assert isinstance(token.jwt_str, JWTStr)
    assert token.jwt_str == str(token)
    assert token.jwt_str.payload == {"sub": "user"}


def test_generate_prefers_explicit_arguments_over_config() -> None:
    raw = StrictToken(sub="user").generate(encoding_key=KEY, algorithm=ALGORITHM)

    assert jwt.decode(raw, KEY, algorithms=[ALGORITHM]) == {"sub": "user"}


def test_signature_forged_with_another_key_is_rejected() -> None:
    with pytest.raises(PydanticCustomError) as exc_info:
        Token.from_token(encode(OTHER_KEY, sub="user"))

    assert exc_info.value.type == "jwt_invalid_signature"
    assert exc_info.value.context == {"algorithm": ALGORITHM}


def test_context_can_skip_claim_checks_for_a_token_string() -> None:
    expired = int(time.time() - 999)
    raw = encode(sub="user", exp=expired)

    with pytest.raises(ValidationError):
        ExpiringToken.model_validate(raw)

    skipped = ExpiringToken.model_validate(raw, context={"validate_claims": False})

    assert skipped.sub == "user"
    assert skipped.exp == expired


@pytest.mark.parametrize(
    "decode",
    [
        pytest.param(
            lambda raw: KeylessToken.from_token(raw, decoding_key=KEY, algorithm=ALGORITHM, require_keys=True),
            id="arguments",
        ),
        pytest.param(
            lambda raw: KeylessToken.model_validate(raw, context={"decoding_key": KEY, "algorithm": ALGORITHM}),
            id="context",
        ),
    ],
)
def test_keys_can_be_supplied_per_call(decode: Callable[[str], Any]) -> None:
    raw = encode(sub="user")

    assert decode(raw).sub == "user"

    forged = encode(OTHER_KEY, sub="user")
    with pytest.raises((ValidationError, PydanticCustomError)) as exc_info:
        decode(forged)

    assert "jwt_invalid_signature" in repr(exc_info.value)


@pytest.mark.parametrize(
    ("action", "keys"),
    [
        pytest.param(lambda: StrictToken.from_token(encode(sub="user")), "decoding_key, algorithm", id="decoding"),
        pytest.param(lambda: StrictToken(sub="user").generate(), "encoding_key, algorithm", id="encoding"),
    ],
)
def test_missing_keys_are_reported(action, keys: str) -> None:
    with pytest.raises(PydanticCustomError) as exc_info:
        action()

    assert exc_info.value.type == "jwt_missing_key"
    assert exc_info.value.context == {"model": "StrictToken", "keys": keys}


def test_signature_check_is_skipped_when_keys_are_not_required(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        token = UnsignedToken.from_token(encode(OTHER_KEY, sub="user"))

    assert token.sub == "user"
    assert "without signature verification" in caplog.text
