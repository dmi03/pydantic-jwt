from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Annotated, Any
from uuid import UUID

import pytest
from pydantic import BaseModel, ValidationError

from pydantic_jwt import AudClaim, Claim, Exp, ExpClaim, Iat, IatClaim, IssClaim, Nbf, NbfClaim, after, at, uuid

NOW = int(time.time())
DELTA = 60
LEEWAY = 120
ISSUER = "https://auth.example.com"
AUDIENCE = "test-api"


class ExpModel(BaseModel):
    exp: Exp


class NbfModel(BaseModel):
    nbf: Nbf


class IatModel(BaseModel):
    iat: Iat


class IssModel(BaseModel):
    iss: Annotated[str, IssClaim(ISSUER)]


class AudModel(BaseModel):
    aud: Annotated[str | list[str], AudClaim(AUDIENCE)]


class LeewayModel(BaseModel):
    exp: Annotated[int, ExpClaim(leeway=LEEWAY)]
    nbf: Annotated[int, NbfClaim(leeway=LEEWAY)]
    iat: Annotated[int, IatClaim(leeway=LEEWAY)]


class UntypedModel(BaseModel):
    exp: Annotated[Any, ExpClaim()]
    nbf: Annotated[Any, NbfClaim()]
    iat: Annotated[Any, IatClaim()]
    iss: Annotated[Any, IssClaim(ISSUER)]
    aud: Annotated[Any, AudClaim(AUDIENCE)]


class DefaultsModel(BaseModel):
    exp: Exp = after(minutes=5)


class UUIDModel(BaseModel):
    jti: str = uuid()


class HexUUIDModel(BaseModel):
    jti: str = uuid(hex_uuid=True)


CLAIM_CASES = [
    pytest.param(ExpModel, "exp", NOW + DELTA, NOW - DELTA, id="exp"),
    pytest.param(NbfModel, "nbf", NOW - DELTA, NOW + DELTA, id="nbf"),
    pytest.param(IatModel, "iat", NOW - DELTA, NOW + DELTA, id="iat"),
]


@pytest.mark.parametrize(
    ("model", "field", "valid", "invalid"),
    [
        pytest.param(ExpModel, "exp", NOW + DELTA, NOW - DELTA, id="exp"),
        pytest.param(NbfModel, "nbf", NOW - DELTA, NOW + DELTA, id="nbf"),
        pytest.param(IatModel, "iat", NOW - DELTA, NOW + DELTA, id="iat"),
    ],
)
def test_claim_accepts_valid_and_rejects_invalid(model: type[BaseModel], field: str, valid: int, invalid: int) -> None:
    assert getattr(model(**{field: valid}), field) == valid

    with pytest.raises(ValidationError) as exc_info:
        model(**{field: invalid})

    error = exc_info.value.errors()[0]
    assert error["type"] == "jwt_claim_invalid"
    assert error["ctx"] == {"claim": field, "value": invalid}


def test_iss_requires_an_exact_match() -> None:
    assert IssModel(iss=ISSUER).iss == ISSUER

    with pytest.raises(ValidationError) as exc_info:
        IssModel(iss=f"{ISSUER}/")

    error = exc_info.value.errors()[0]
    assert error["type"] == "jwt_claim_invalid"
    assert error["ctx"] == {"claim": "iss", "value": f"{ISSUER}/"}


@pytest.mark.parametrize(
    ("valid", "invalid"),
    [
        pytest.param(AUDIENCE, "other-api", id="string"),
        pytest.param(["other-api", AUDIENCE], ["other-api"], id="list"),
    ],
)
def test_aud_accepts_both_string_and_list_forms(valid: str | list[str], invalid: str | list[str]) -> None:
    assert AudModel(aud=valid).aud == valid

    with pytest.raises(ValidationError) as exc_info:
        AudModel(aud=invalid)

    assert exc_info.value.errors()[0]["type"] == "jwt_claim_invalid"


def test_leeway_widens_the_accepted_window() -> None:
    model = LeewayModel(exp=NOW - DELTA, nbf=NOW + DELTA, iat=NOW + DELTA)

    assert (model.exp, model.nbf, model.iat) == (NOW - DELTA, NOW + DELTA, NOW + DELTA)


def test_validation_context_toggles_the_check() -> None:
    skipped = ExpModel.model_validate({"exp": NOW - DELTA}, context={"validate_claims": False})
    assert skipped.exp == NOW - DELTA

    with pytest.raises(ValidationError):
        ExpModel.model_validate({"exp": NOW - DELTA}, context={"unrelated": True})


def test_wrong_types_are_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        UntypedModel(exp="soon", nbf="later", iat="never", iss=1, aud=[1])

    errors = exc_info.value.errors()
    assert len(errors) == 5
    assert {error["type"] for error in errors} == {"jwt_type"}


def test_base_check_is_not_implemented() -> None:
    class CustomClaim(Claim):
        __claim_name__ = "custom"

        def check(self, value: Any) -> bool:
            return super().check(value)

    with pytest.raises(NotImplementedError):
        CustomClaim().check(NOW)


@pytest.mark.parametrize(
    ("duration", "offset"),
    [
        pytest.param({"minutes": 5}, 300, id="single-unit"),
        pytest.param({"hours": 1, "seconds": 30}, 3630, id="multiple-units"),
    ],
)
def test_after_offsets_the_current_time(
    monkeypatch: pytest.MonkeyPatch, duration: dict[str, float], offset: int
) -> None:
    monkeypatch.setattr(time, "time", lambda: 1_000.0)

    class Model(BaseModel):
        exp: Exp = after(**duration)

    assert Model().exp == 1_000 + offset


def test_after_default_is_recomputed_per_instance(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = {"now": 1_000.0}
    monkeypatch.setattr(time, "time", lambda: clock["now"])

    first = DefaultsModel().exp
    clock["now"] = 2_000.0
    second = DefaultsModel().exp

    assert second - first == 1_000


def test_at_pins_the_default_to_a_fixed_moment() -> None:
    moment = datetime(2030, 1, 1, tzinfo=timezone.utc)

    class Model(BaseModel):
        iat: Iat = at(moment)

    assert Model().iat == Model().iat == int(moment.timestamp())


def test_uuid_generates_a_fresh_value_per_instance() -> None:
    first, second = UUIDModel().jti, UUIDModel().jti
    assert first != second
    assert UUID(first).version == 4
    assert UUID(second).version == 4

    hex_first, hex_second = HexUUIDModel().jti, HexUUIDModel().jti
    assert hex_first != hex_second
    assert "-" not in hex_first
    assert "-" not in hex_second
    assert UUID(hex_first).version == 4
    assert UUID(hex_second).version == 4
