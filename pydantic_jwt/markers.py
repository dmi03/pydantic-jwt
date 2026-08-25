import time
from abc import ABC, abstractmethod
from enum import Enum
from typing import Generic, TypeVar

T = TypeVar("T")


class ClaimName(str, Enum):
    EXP = "exp"
    NBF = "nbf"


class Marker(Generic[T], ABC):
    __key__: ClaimName

    @classmethod
    @abstractmethod
    def validate(cls, value: T) -> bool:
        raise NotImplementedError()


class Exp(Marker[int], int):
    __key__ = ClaimName.EXP

    @classmethod
    def validate(cls, value: int) -> bool:
        return value > time.time()


class Nbf(Marker[int], int):
    __key__ = ClaimName.NBF

    @classmethod
    def validate(cls, value: int) -> bool:
        return value <= time.time()
