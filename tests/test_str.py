from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError
from pydantic_core import PydanticCustomError

from pydantic_jwt import JWTStr


class JWTTest(BaseModel):
    token: JWTStr


@pytest.mark.parametrize(
    "jwt, valid",
    [
        (
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdA",
            True,
        ),
        (
            123456789,  # not a string
            False,
        ),
        (
            "invalid_jwt",  # no dots, not 3 parts
            False,
        ),
        (
            "!!!.eyJhbGciOiJIUzI1NiJ9.dGVzdA",  # invalid base64url characters
            False,
        ),
        (
            "eyJhbGciOiJIUzI1NiJ9+.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdA",  # contains standard base64 char, not urlsafe
            False,
        ),
        (
            "invalid_b64.invalid_b64.invalid_b64",  # valid base64url, but not valid UTF-8/JSON
            False,
        ),
        (
            "Njc.Njc.Njc",  # valid JSON, but not a dict
            False,
        ),
        (
            "eyJhbGciOiJIUzI1NiJ9.Njc.Njc",  # valid JSON, but not a dict
            False,
        ),
    ],
)
def test_jwt(jwt: str, valid: bool):
    if valid:
        assert JWTTest(token=jwt).token == jwt
        assert JWTStr(jwt) == jwt
        assert JWTStr.validate(jwt) is True
    else:
        with pytest.raises(ValidationError):
            JWTTest(token=jwt)
        with pytest.raises(PydanticCustomError):
            JWTStr(jwt)
        assert JWTStr.validate(jwt) is False


def test_jwt_params():
    auth = JWTTest(token="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdA")
    assert auth.token.header == {"alg": "HS256"}
    assert auth.token.algorithm == "HS256"
    assert auth.token.payload == {"sub": "1234567890"}
    assert auth.token.signature == b"test"


def test_jwt_json_schema():
    schema = JWTTest.model_json_schema()
    token_schema = schema["properties"]["token"]
    assert token_schema["type"] == "string"
    assert token_schema["format"] == "jwt"
    assert token_schema["examples"] == ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdA"]
