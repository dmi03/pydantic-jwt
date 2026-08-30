# Security notes

`pydantic-jwt` verifies signatures and validates the claims you declare.
Everything below is either a sharp edge in the API or a part of token security
the library deliberately leaves to you.

## A model built from a dict is not authenticated

This is the one to internalise. By default the signature is checked only when a
**token string** is validated:

```python
AccessToken.from_token(raw)  # verified
AccessToken.model_validate(raw)  # verified (raw is a str)

AccessToken(sub="admin")  # NOT verified — you are building a token
AccessToken.model_validate({"sub": "admin"})  # NOT verified
```

Both behaviours are needed — the same class issues and reads tokens — but it
means a plain `JWTModel` used directly as a **request body type** is a hole:

```python
# DANGEROUS on a model without verified_only: FastAPI parses the JSON body
# straight into it, and no signature is involved
@app.post("/admin")
def admin(token: AccessToken) -> None: ...
```

A client can `POST {"sub": "admin"}` and get an `AccessToken` instance.

**The fix is `verified_only=True`.** With it set, the payload branch is closed:
only a verified token string, an existing instance, or an explicit
[`from_claims()`](models.md#from_claims) call produces a model.

```python
class AccessToken(JWTModel):
    model_config = ConfigDict(
        algorithm="HS256",
        encoding_key=SECRET,
        decoding_key=SECRET,
        verified_only=True,
    )

    sub: str
    exp: Exp = after(minutes=15)


AccessToken(sub="admin")
# ValidationError: AccessToken only accepts a verified token string
#                  [type=jwt_unverified_payload]

raw = AccessToken.from_claims(sub="user-42").generate()  # issuing, deliberately
```

Turn it on for every model that reads tokens from outside. The cost is one extra
call on the issuing side; the benefit is that the dangerous shape above stops
compiling into working code.

It is a guard, not a proof: `model_construct()` skips all validation and so
skips this too, and the flag says nothing about *which* issuer signed the token
— that is what [`iss`/`aud` markers](claims.md#issuer-and-audience) are for.

Without it, take tokens from a header through a dependency, or type the body
field as `str` and call `from_token()` yourself. See the
[FastAPI guide](../integrations/fastapi.md) for the shape that is safe.

## `require_keys=False` accepts forged tokens

With `require_keys=False` and no key configured, `from_token()` skips signature
verification entirely, logs a warning and returns the model:

```python
class UnsafeToken(JWTModel):
    model_config = ConfigDict(require_keys=False)

    sub: str


UnsafeToken.from_token(anything).sub  # attacker-chosen
```

Anybody can mint a token your application accepts. Keep it to tests and local
inspection scripts, and make the default the other way round in shared code — it
is `True` unless you say otherwise, so simply never write `require_keys=False`
in application configuration.

If you use it in tests, assert on the warning so it cannot spread silently:

```python
def test_helper_is_unverified(caplog):
    with caplog.at_level(logging.WARNING):
        UnsafeToken.from_token(raw)
    assert "without signature verification" in caplog.text
```

## Only `generate()` and `jwt_str` produce a credential

Signing is explicit: [`generate()`](models.md#generate) and
[`jwt_str`](models.md#jwt_str), nothing else. `str(token)` and
`logger.info("token=%s", token)` render the *claims*, not a usable token — which
is the point. Earlier releases signed in `__str__`, and that turned every log
line into a potential credential leak.

Claims are not nothing, though: a `sub`, an email or a scope list in a log is
still personal data. Log the `jti` and treat the payload as sensitive.

The rule for the value `generate()` returns is unchanged — it is a bearer
credential. Never put it in a log, an error response, a URL or an analytics
event.

## The algorithm never comes from the token

`from_token()` passes `algorithms=[algorithm]` from your configuration to PyJWT
and ignores the token's `alg` header. This is what prevents *algorithm
confusion*, where an attacker takes an `RS256` deployment, re-signs a token as
`HS256` using the well-known public key as the HMAC secret, and has it accepted.

The corollary: if you read `JWTStr.algorithm` off an incoming token, use it for
logging only. Never feed it back into `from_token(algorithm=...)`.

## Claim checks are opt-in

A claim is validated only if you declare it with a marker. A model that omits
`exp` accepts tokens that never expire; a model that declares `exp: int` instead
of `exp: Exp` carries the value without checking it.

For a token you accept from outside, the baseline is:

```python
class IncomingToken(JWTModel):
    model_config = ConfigDict(algorithm="RS256", decoding_key=PUBLIC_KEY)

    sub: str
    exp: Exp
    iss: Annotated[str, IssClaim(ISSUER)]
    aud: Annotated[str | list[str], AudClaim("billing-api")]
```

`iss` and `aud` matter as soon as more than one service shares a signing key:
without `aud`, a token minted for the low-privilege service is accepted by the
high-privilege one.

## What the library does not do

Not bugs — scope. You need to handle these yourself:

- **Revocation.** A JWT is valid until it expires. Give tokens a
  [`jti`](defaults.md#uuid), keep short lifetimes, and check a denylist after
  validation if you need to cut a session short.
- **Key discovery (JWKS).** There is no JWKS client. Fetch and cache the key
  set yourself and pass the right key via
  [`decoding_key=`](configuration.md#per-call-keys), selecting it on the `kid`
  header — see [Working with raw tokens](jwt-str.md#routing-before-verification).
- **Encryption (JWE).** Tokens are signed, not encrypted. Anyone holding a token
  can read its claims: `JWTStr(raw).payload` is one line. Do not put secrets or
  unnecessary personal data in a payload.
- **`typ`/`cty` header checks and header claims generally.** Only `alg` is
  constrained, by your configuration.
- **Distinguishing token kinds.** An access token and a refresh token signed
  with the same key are interchangeable unless you make them differ. Either use
  separate keys per kind, or add a discriminating claim:

  ```python
  class RefreshToken(JWTModel):
      model_config = ConfigDict(algorithm="HS256", decoding_key=SECRET)

      sub: str
      exp: Exp = after(days=30)
      jti: str = uuid()
      typ: Annotated[str, IssClaim("refresh")] = "refresh"
  ```

  (`IssClaim` is just an exact-string-match claim; give it its own
  `__claim_name__` by [subclassing `Claim`](claims.md#custom-claims) if the error
  message matters.)

## Checklist

- [ ] Keys come from the environment or a secret manager, never from source.
- [ ] HMAC secrets are at least 32 bytes; asymmetric keys are RSA-2048+ or an EC/Ed curve.
- [ ] Every externally issued token model declares `exp`, and `iss`/`aud` where a key is shared.
- [ ] Every model that reads tokens from outside sets `verified_only=True`.
- [ ] `require_keys=False` appears nowhere outside tests.
- [ ] No `JWTModel` without `verified_only` is used as a request-body type.
- [ ] The output of `generate()` is not written to logs or error responses.
- [ ] Access-token lifetimes are minutes, not days.
