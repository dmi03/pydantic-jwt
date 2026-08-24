import sys
from pathlib import Path

import pytest

from pydantic_jwt.version import __version__


def test_version_is_string():
    assert isinstance(__version__, str)


@pytest.mark.skipif(sys.version_info < (3, 11), reason="tomllib requires Python 3.11+")
def test_version_matches_pyproject():
    import tomllib

    pyproject = Path(__file__).parent.parent / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text())
    assert __version__ == data["project"]["version"]
