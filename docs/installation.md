# Installation

```bash
pip install pydantic-jwt
```

=== "uv"

    ```bash
    uv add pydantic-jwt
    ```

=== "Poetry"

    ```bash
    poetry add pydantic-jwt
    ```

=== "PDM"

    ```bash
    pdm add pydantic-jwt
    ```

## Requirements

| Requirement | Version |
| --- | --- |
| Python | `>= 3.10` |
| [Pydantic](https://docs.pydantic.dev/) | `>= 2.10` |
| [PyJWT](https://pyjwt.readthedocs.io/) | `>= 2.8` |

Both dependencies are installed automatically. Pydantic v1 is not supported.

## Algorithm support

Signing and verification are delegated to PyJWT, so the set of usable
`algorithm` values is PyJWT's.

The HMAC family — `HS256`, `HS384`, `HS512` — works out of the box with no
extra packages.

Asymmetric algorithms (`RS*`, `ES*`, `PS*`, `EdDSA`) need PyJWT's optional
cryptography backend:

```bash
pip install "pyjwt[crypto]"
```

Without it, PyJWT raises `NotImplementedError: Algorithm 'RS256' could not be
found` the first time you try to sign or verify. See
[Configuration](guide/configuration.md#asymmetric-algorithms) for how to pass
PEM keys.

## Type checking

The package ships a [`py.typed`](https://peps.python.org/pep-0561/) marker and
is developed under `mypy --strict`, so your token models are checked without
any extra stub package.

## Verifying the install

```python
from pydantic_jwt import ConfigDict, JWTModel

SECRET = "a" * 32


class Ping(JWTModel):
    model_config = ConfigDict(algorithm="HS256", encoding_key=SECRET, decoding_key=SECRET)

    sub: str


assert Ping.from_token(Ping(sub="ok").generate()).sub == "ok"
```

!!! tip "Key length"

    PyJWT emits an `InsecureKeyLengthWarning` for HMAC keys shorter than 32
    bytes with SHA-256. Use `secrets.token_hex(32)` (or longer) for real
    secrets — including in tests.
