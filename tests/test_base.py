from __future__ import annotations

import logging
import secrets
import time
from collections.abc import Callable
from typing import Any

import jwt
import pytest
from pydantic import BaseModel, ValidationError
from pydantic_core import PydanticCustomError

from pydantic_jwt import ConfigDict, Exp, JWTModel, JWTStr

KEY = secrets.token_hex(32)
OTHER_KEY = secrets.token_hex(32)
ALGORITHM = "HS256"

SUBJECT = "user"
VALID_EXP = int(time.time()) + 999
EXPIRED_EXP = int(time.time()) - 999


class Token(JWTModel):
    model_config = ConfigDict(
        extra="forbid",
        encoding_key=KEY,
        decoding_key=KEY,
        algorithm=ALGORITHM,
    )

    sub: str


class ExpiringToken(Token):
    exp: Exp


class BareToken(JWTModel):
    sub: str


class UnsignedToken(JWTModel):
    model_config = ConfigDict(require_keys=False)

    sub: str


class VerifiedToken(JWTModel):
    model_config = ConfigDict(algorithm=ALGORITHM, decoding_key=KEY, verified_only=True)

    sub: str
    exp: Exp


class Envelope(BaseModel):
    token: VerifiedToken


def encode(claims: dict[str, Any], key: str = KEY) -> str:
    return jwt.encode(claims, key, algorithm=ALGORITHM)


def test_json_schema_describes_a_jwt_string() -> None:
    schema = Token.model_json_schema()

    assert schema["type"] == "string"
    assert schema["format"] == "jwt"
    assert "sub" in schema["description"]


def test_token_round_trips_through_its_jwt_string() -> None:
    token = Token(sub=SUBJECT)
    raw = token.jwt_str

    assert isinstance(raw, JWTStr)
    assert raw == str(token)
    assert raw.payload == {"sub": SUBJECT}
    assert Token.model_validate(str(token)) == token


def test_union_falls_back_to_regular_model_validation() -> None:
    assert Token.model_validate({"sub": SUBJECT}).sub == SUBJECT

    with pytest.raises(ValidationError) as exc_info:
        Token.model_validate(42)

    assert "jwt_type" in {error["type"] for error in exc_info.value.errors()}


def test_generate_prefers_explicit_arguments_over_config() -> None:
    raw = BareToken(sub=SUBJECT).generate(encoding_key=KEY, algorithm=ALGORITHM)

    assert jwt.decode(raw, KEY, algorithms=[ALGORITHM]) == {"sub": SUBJECT}


def test_signature_forged_with_another_key_is_rejected() -> None:
    with pytest.raises(PydanticCustomError) as exc_info:
        Token.from_token(encode({"sub": SUBJECT}, OTHER_KEY))

    assert exc_info.value.type == "jwt_invalid_signature"
    assert exc_info.value.context == {"algorithm": ALGORITHM}


def test_context_can_skip_claim_checks_for_a_token_string() -> None:
    raw = encode({"sub": SUBJECT, "exp": EXPIRED_EXP})

    with pytest.raises(ValidationError):
        ExpiringToken.model_validate(raw)

    skipped = ExpiringToken.model_validate(raw, context={"validate_claims": False})

    assert skipped.sub == SUBJECT
    assert skipped.exp == EXPIRED_EXP


@pytest.mark.parametrize(
    "decode",
    [
        pytest.param(
            lambda raw: BareToken.from_token(raw, decoding_key=KEY, algorithm=ALGORITHM, require_keys=True),
            id="arguments",
        ),
        pytest.param(
            lambda raw: BareToken.model_validate(raw, context={"decoding_key": KEY, "algorithm": ALGORITHM}),
            id="context",
        ),
    ],
)
def test_keys_can_be_supplied_per_call(decode: Callable[[str], BareToken]) -> None:
    assert decode(encode({"sub": SUBJECT})).sub == SUBJECT

    with pytest.raises((ValidationError, PydanticCustomError)) as exc_info:
        decode(encode({"sub": SUBJECT}, OTHER_KEY))

    assert "jwt_invalid_signature" in repr(exc_info.value)


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda: VerifiedToken(sub=SUBJECT, exp=VALID_EXP), id="constructor"),
        pytest.param(lambda: VerifiedToken.model_validate({"sub": SUBJECT, "exp": VALID_EXP}), id="dict"),
        pytest.param(
            lambda: Envelope.model_validate({"token": {"sub": SUBJECT, "exp": VALID_EXP}}),
            id="nested-dict",
        ),
    ],
)
def test_verified_only_rejects_payloads_without_a_token(build: Callable[[], Any]) -> None:
    with pytest.raises(ValidationError) as exc_info:
        build()

    assert "jwt_unverified_payload" in {error["type"] for error in exc_info.value.errors()}


def test_verified_only_accepts_token_strings() -> None:
    raw = encode({"sub": SUBJECT, "exp": VALID_EXP})

    assert VerifiedToken.from_token(raw).sub == SUBJECT
    assert Envelope.model_validate({"token": raw}).token.sub == SUBJECT


def test_from_claims_builds_a_model_and_still_checks_claims() -> None:
    assert VerifiedToken.from_claims(sub=SUBJECT, exp=VALID_EXP).sub == SUBJECT

    with pytest.raises(ValidationError):
        VerifiedToken.from_claims(sub=SUBJECT, exp=EXPIRED_EXP)

    skipped = VerifiedToken.from_claims({"validate_claims": False}, sub=SUBJECT, exp=EXPIRED_EXP)

    assert skipped.exp == EXPIRED_EXP


def test_an_existing_instance_passes_through() -> None:
    token = VerifiedToken.from_token(encode({"sub": SUBJECT, "exp": VALID_EXP}))

    assert Envelope(token=token).token is token
    assert Envelope.model_validate({"token": token}).token is token


@pytest.mark.parametrize(
    ("action", "keys"),
    [
        pytest.param(
            lambda: BareToken.from_token(encode({"sub": SUBJECT})),
            "decoding_key, algorithm",
            id="decoding",
        ),
        pytest.param(
            lambda: BareToken(sub=SUBJECT).generate(),
            "encoding_key, algorithm",
            id="encoding",
        ),
    ],
)
def test_missing_keys_are_reported(action: Callable[[], Any], keys: str) -> None:
    with pytest.raises(PydanticCustomError) as exc_info:
        action()

    assert exc_info.value.type == "jwt_missing_key"
    assert exc_info.value.context == {"model": "BareToken", "keys": keys}


def test_signature_check_is_skipped_when_keys_are_not_required(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        token = UnsignedToken.from_token(encode({"sub": SUBJECT}, OTHER_KEY))

    assert token.sub == SUBJECT
    assert "without signature verification" in caplog.text
