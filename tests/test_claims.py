from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Annotated, Any

import pytest
from pydantic import BaseModel, ValidationError

from pydantic_jwt import Claim, Exp, ExpClaim, Iat, IatClaim, Nbf, NbfClaim, after, at

NOW = int(time.time())
DELTA = 60
LEEWAY = 120


class ExpModel(BaseModel):
    exp: Exp


class NbfModel(BaseModel):
    nbf: Nbf


class IatModel(BaseModel):
    iat: Iat


class LeewayModel(BaseModel):
    exp: Annotated[int, ExpClaim(leeway=LEEWAY)]
    nbf: Annotated[int, NbfClaim(leeway=LEEWAY)]
    iat: Annotated[int, IatClaim(leeway=LEEWAY)]


class UntypedModel(BaseModel):
    exp: Annotated[Any, ExpClaim()]
    nbf: Annotated[Any, NbfClaim()]
    iat: Annotated[Any, IatClaim()]


class DefaultsModel(BaseModel):
    exp: Exp = after(minutes=5)


CLAIM_CASES = [
    pytest.param(ExpModel, "exp", NOW + DELTA, NOW - DELTA, id="exp"),
    pytest.param(NbfModel, "nbf", NOW - DELTA, NOW + DELTA, id="nbf"),
    pytest.param(IatModel, "iat", NOW - DELTA, NOW + DELTA, id="iat"),
]


@pytest.mark.parametrize(("model", "field", "valid", "invalid"), CLAIM_CASES)
def test_claim_accepts_valid_and_rejects_invalid(model: type[BaseModel], field: str, valid: int, invalid: int) -> None:
    assert getattr(model(**{field: valid}), field) == valid

    with pytest.raises(ValidationError) as exc_info:
        model(**{field: invalid})

    error = exc_info.value.errors()[0]
    assert error["type"] == "jwt_claim_invalid"
    assert error["ctx"] == {"claim": field, "value": invalid}


def test_leeway_widens_the_accepted_window() -> None:
    model = LeewayModel(exp=NOW - DELTA, nbf=NOW + DELTA, iat=NOW + DELTA)

    assert (model.exp, model.nbf, model.iat) == (NOW - DELTA, NOW + DELTA, NOW + DELTA)


def test_validation_context_toggles_the_check() -> None:
    skipped = ExpModel.model_validate({"exp": NOW - DELTA}, context={"validate_claims": False})
    assert skipped.exp == NOW - DELTA

    with pytest.raises(ValidationError):
        ExpModel.model_validate({"exp": NOW - DELTA}, context={"unrelated": True})


def test_non_integer_values_are_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        UntypedModel(exp="soon", nbf="later", iat="never")

    errors = exc_info.value.errors()
    assert len(errors) == 3
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
