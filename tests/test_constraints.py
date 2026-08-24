import base64
import json
import time
from typing import Annotated

import pytest
from pydantic import BaseModel, ValidationError

from pydantic_jwt import JWTConstraints, JWTStr


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


HEADER_HS256 = _b64({"alg": "HS256"})
HEADER_RS256 = _b64({"alg": "RS256"})
SIGNATURE = "dGVzdA"


class TokenDefault(BaseModel):
    token: Annotated[JWTStr, JWTConstraints()]


class TokenAllowedAlgorithms(BaseModel):
    token: Annotated[JWTStr, JWTConstraints(allowed_algorithms=("HS256",))]


class TokenAllowExpired(BaseModel):
    token: Annotated[JWTStr, JWTConstraints(allow_exp=True)]


class TokenAllowNbf(BaseModel):
    token: Annotated[JWTStr, JWTConstraints(allow_nbf=True)]


class TokenCustomClaimNames(BaseModel):
    token: Annotated[JWTStr, JWTConstraints(exp_name="expires_at", nbf_name="not_before")]


@pytest.mark.parametrize(
    "payload, valid",
    [
        ({"sub": "123"}, True),
        ({"exp": int(time.time()) + 3600}, True),
        ({"exp": int(time.time()) - 3600}, False),
        ({"nbf": int(time.time()) - 3600}, True),
        ({"nbf": int(time.time()) + 3600}, False),
        ({"exp": int(time.time()) + 3600, "nbf": int(time.time()) - 3600}, True),
    ],
)
def test_default_constraints_exp_nbf(payload: dict, valid: bool):
    token = f"{HEADER_HS256}.{_b64(payload)}.{SIGNATURE}"
    if valid:
        assert TokenDefault(token=token).token == token
    else:
        with pytest.raises(ValidationError):
            TokenDefault(token=token)


def test_allowed_algorithm_passes():
    token = f"{HEADER_HS256}.{_b64({'sub': '123'})}.{SIGNATURE}"
    assert TokenAllowedAlgorithms(token=token).token == token


def test_disallowed_algorithm_raises():
    token = f"{HEADER_RS256}.{_b64({'sub': '123'})}.{SIGNATURE}"
    with pytest.raises(ValidationError):
        TokenAllowedAlgorithms(token=token)


def test_expired_token_raises_by_default():
    token = f"{HEADER_HS256}.{_b64({'exp': int(time.time()) - 3600})}.{SIGNATURE}"
    with pytest.raises(ValidationError):
        TokenDefault(token=token)


def test_expired_token_allowed_with_allow_exp():
    token = f"{HEADER_HS256}.{_b64({'exp': int(time.time()) - 3600})}.{SIGNATURE}"
    assert TokenAllowExpired(token=token).token == token


def test_not_yet_valid_token_raises_by_default():
    token = f"{HEADER_HS256}.{_b64({'nbf': int(time.time()) + 3600})}.{SIGNATURE}"
    with pytest.raises(ValidationError):
        TokenDefault(token=token)


def test_not_yet_valid_token_allowed_with_allow_nbf():
    token = f"{HEADER_HS256}.{_b64({'nbf': int(time.time()) + 3600})}.{SIGNATURE}"
    assert TokenAllowNbf(token=token).token == token


def test_custom_claim_names_are_respected():
    token = f"{HEADER_HS256}.{_b64({'expires_at': int(time.time()) - 3600})}.{SIGNATURE}"
    with pytest.raises(ValidationError):
        TokenCustomClaimNames(token=token)


def test_custom_claim_names_ignore_standard_exp():
    # standard "exp" is expired, but constraint checks "expires_at" instead — should pass
    token = f"{HEADER_HS256}.{_b64({'exp': int(time.time()) - 3600})}.{SIGNATURE}"
    assert TokenCustomClaimNames(token=token).token == token
