from pathlib import Path

import tomllib

from pydantic_jwt.version import __version__


def test_version_is_string():
    assert isinstance(__version__, str)


def test_version_matches_pyproject():
    pyproject = Path(__file__).parent.parent / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text())
    assert __version__ == data["project"]["version"]
