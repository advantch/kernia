"""Unit tests for the JWT plugin.

Exercises key generation, signing, JWKS publication, and rotation directly via
the plugin's helper functions (no router).
"""

from __future__ import annotations

import json
from datetime import UTC

import pytest
from authlib.jose import JsonWebKey
from authlib.jose import jwt as jose_jwt
from better_auth.auth import init
from better_auth.plugins.jwt import jwt as jwt_plugin
from better_auth.plugins.jwt import plugin as jwt_mod
from better_auth.plugins.jwt.plugin import (
    JwtOptions,
    _create_key,
    _get_active_key,
    issue_jwt,
    sign_jwt,
    to_exp_jwt,
    verify_local_jwt,
)
from better_auth.types.adapter import Where
from better_auth.types.init_options import BetterAuthOptions
from better_auth_memory_adapter import memory_adapter


def _auth(opts: JwtOptions | None = None):
    return init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="test-secret",
            plugins=[jwt_plugin(opts)],
        )
    )


@pytest.mark.parametrize("alg", ["ES256", "RS256", "EdDSA"])
async def test_issue_and_verify_round_trip(alg: str) -> None:
    auth = _auth(JwtOptions(algorithm=alg, issuer="https://test", audience="aud-x"))
    token, kid = await issue_jwt(auth.context, payload={"sub": "user-1"})
    assert kid
    claims = await verify_local_jwt(
        auth.context, token, audience="aud-x", issuer="https://test"
    )
    assert claims["sub"] == "user-1"
    assert claims["iss"] == "https://test"
    assert claims["aud"] == "aud-x"
    assert "iat" in claims
    assert "exp" in claims


async def test_rotation_keeps_old_keys_verifiable() -> None:
    auth = _auth(JwtOptions(algorithm="ES256"))
    # First key
    token_a, kid_a = await issue_jwt(auth.context, payload={"sub": "u1"})
    # Rotate (mark inactive, create new)
    await auth.context.adapter.update_many(
        model="jwk",
        where=(Where(field="isActive", value=True),),
        update={"isActive": False},
    )
    await _create_key(auth.context, alg="ES256")
    token_b, kid_b = await issue_jwt(auth.context, payload={"sub": "u2"})
    assert kid_b != kid_a

    # Both tokens verify
    claims_a = await verify_local_jwt(auth.context, token_a)
    claims_b = await verify_local_jwt(auth.context, token_b)
    assert claims_a["sub"] == "u1"
    assert claims_b["sub"] == "u2"


async def test_get_active_key_returns_one_active() -> None:
    auth = _auth()
    k1 = await _get_active_key(auth.context)
    rows = await auth.context.adapter.find_many(model="jwk")
    # Bootstrap inserted exactly one active key
    assert len(rows) == 1
    assert k1["isActive"] is True


async def test_unsupported_alg_raises() -> None:
    auth = _auth(JwtOptions(algorithm="HS999"))
    with pytest.raises(ValueError, match="unsupported"):
        await _create_key(auth.context, alg="HS999")


async def test_jwks_doc_omits_private_material() -> None:
    auth = _auth()
    await _create_key(auth.context, alg="ES256")
    rows = await auth.context.adapter.find_many(model="jwk")
    for row in rows:
        pub = json.loads(row["publicKey"])
        # Private parameters must not leak into the public JWK
        assert "d" not in pub


async def test_external_verification_against_jwks(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sign with our plugin → verify with authlib using only the public JWKS."""
    auth = _auth(JwtOptions(algorithm="RS256"))
    token, kid = await issue_jwt(auth.context, payload={"sub": "u-x"})
    rows = await auth.context.adapter.find_many(model="jwk")
    jwks = {
        "keys": [
            {**json.loads(r["publicKey"]), "kid": r["keyId"], "alg": r["algorithm"]}
            for r in rows
        ]
    }
    decoded = jose_jwt.decode(token, JsonWebKey.import_key_set(jwks))
    assert decoded["sub"] == "u-x"


# ----- ported from reference jwt.test.ts -----


# Default algorithm is EdDSA (ported from "Get JWKS": keys[0].alg == "EdDSA").
async def test_default_algorithm_is_eddsa() -> None:
    auth = _auth()
    await _get_active_key(auth.context)
    rows = await auth.context.adapter.find_many(model="jwk")
    assert rows[0]["algorithm"] == "EdDSA"


@pytest.mark.parametrize(
    ("alg", "kty", "crv"),
    [
        ("EdDSA", "OKP", "Ed25519"),
        ("ES256", "EC", "P-256"),
        ("ES512", "EC", "P-521"),
        ("PS256", "RSA", None),
        ("RS256", "RSA", None),
    ],
)
async def test_algorithm_jwks_shape(alg: str, kty: str, crv: str | None) -> None:
    """Ported from the "<alg> algorithm can be used to generate JWKS" matrix."""
    auth = _auth(JwtOptions(algorithm=alg))
    token, _ = await issue_jwt(auth.context, payload={"sub": "u"})
    rows = await auth.context.adapter.find_many(model="jwk")
    pub = json.loads(rows[0]["publicKey"])
    assert pub["kty"] == kty
    if crv is not None:
        assert pub["crv"] == crv
    # The public JWK must verify the issued token.
    jwks = {
        "keys": [
            {**json.loads(r["publicKey"]), "kid": r["keyId"], "alg": r["algorithm"]}
            for r in rows
        ]
    }
    decoded = jose_jwt.decode(token, JsonWebKey.import_key_set(jwks))
    assert decoded["sub"] == "u"


@pytest.mark.parametrize("alg", ["EdDSA", "ES256", "ES512", "PS256", "RS256"])
async def test_sign_jwt_round_trip(alg: str) -> None:
    """Ported from "signJWT - alg: $alg" / "should be a valid JWT"."""
    import time as _time

    auth = _auth(JwtOptions(algorithm=alg))
    now = int(_time.time())
    token = await sign_jwt(
        auth.context,
        payload={
            "sub": "123",
            "exp": now + 600,
            "iat": now,
            "iss": "https://example.com",
            "aud": "https://example.com",
            "custom": "custom",
        },
    )
    assert token.count(".") == 2

    jwks = await _jwks_doc(auth)
    decoded = jose_jwt.decode(token, JsonWebKey.import_key_set(jwks))
    assert decoded["iss"] == "https://example.com"
    assert decoded["aud"] == "https://example.com"
    assert decoded["sub"] == "123"
    assert decoded["custom"] == "custom"

    # The kid in the header is present in the JWKS.
    header = _decode_header(token)
    assert any(k["kid"] == header["kid"] for k in jwks["keys"])


async def _jwks_doc(auth) -> dict:
    rows = await auth.context.adapter.find_many(model="jwk")
    return {
        "keys": [
            {**json.loads(r["publicKey"]), "kid": r["keyId"], "alg": r["algorithm"]}
            for r in rows
        ]
    }


def _decode_header(token: str) -> dict:
    import base64

    h = token.split(".", 1)[0]
    pad = "=" * (-len(h) % 4)
    return json.loads(base64.urlsafe_b64decode(h + pad))


async def test_sign_jwt_custom_sign_function() -> None:
    """Ported from "should work with custom sign function and remoteUrl".

    A custom sign function (requires remote_url) is used verbatim.
    """

    def mock_sign(payload: dict) -> str:
        return "header.body.mock-signature"

    auth = _auth(
        JwtOptions(
            algorithm="ES256",
            remote_url="https://example.com/.well-known/jwks.json",
            sign=mock_sign,
        )
    )
    token = await sign_jwt(auth.context, payload={"sub": "123"})
    assert "mock-signature" in token


# ----- remote signing / remote url validation -----


def test_sign_requires_remote_url() -> None:
    """Ported from "should fail if sign is defined and remoteUrl is not"."""
    with pytest.raises(ValueError, match="remoteUrl must be set"):
        JwtOptions(sign=lambda _p: "123")


def test_remote_url_accepts_alg() -> None:
    """Ported from "should accept remoteUrl with alg specified"."""
    opts = JwtOptions(
        algorithm="ES256",
        remote_url="https://example.com/.well-known/jwks.json",
    )
    assert opts.remote_url


@pytest.mark.parametrize("alg", ["ES256", "ES512", "RS256", "PS256", "EdDSA"])
def test_remote_url_works_with_algorithms(alg: str) -> None:
    """Ported from "should work with different algorithms when remoteUrl is set"."""
    opts = JwtOptions(
        algorithm=alg, remote_url="https://example.com/.well-known/jwks.json"
    )
    assert opts.algorithm == alg


def test_remote_url_disables_jwks_endpoint() -> None:
    """Ported from "should disable /jwks endpoint when remoteUrl is configured"."""
    p = jwt_plugin(
        JwtOptions(
            algorithm="ES256",
            remote_url="https://example.com/.well-known/jwks.json",
        )
    )
    paths = {ep.path for ep in p.endpoints}  # type: ignore[union-attr]
    assert "/jwks" not in paths
    assert "/token" in paths


def test_custom_jwks_path() -> None:
    """Ported from "should use custom jwksPath when specified"."""
    p = jwt_plugin(JwtOptions(jwks_path="/.well-known/jwks.json"))
    paths = {ep.path for ep in p.endpoints}  # type: ignore[union-attr]
    assert "/.well-known/jwks.json" in paths
    assert "/jwks" not in paths


# ----- toExpJWT (ported from describe("toExpJWT")) -----


def test_to_exp_jwt_number_input() -> None:
    iat = 1000
    assert to_exp_jwt(3600, iat) == 3600
    assert to_exp_jwt(0, iat) == 0
    assert to_exp_jwt(9999999, iat) == 9999999


def test_to_exp_jwt_date_input() -> None:
    from datetime import datetime

    iat = 1000
    date = datetime(2024, 1, 1, tzinfo=UTC)
    assert to_exp_jwt(date, iat) == int(date.timestamp())


def test_to_exp_jwt_short_format() -> None:
    iat = 1000
    assert to_exp_jwt("1h", iat) == iat + 3600
    assert to_exp_jwt("7d", iat) == iat + 604800
    assert to_exp_jwt("30m", iat) == iat + 1800
    assert to_exp_jwt("1s", iat) == iat + 1


def test_to_exp_jwt_long_format() -> None:
    iat = 1000
    assert to_exp_jwt("1 hour", iat) == iat + 3600
    assert to_exp_jwt("7 days", iat) == iat + 604800
    assert to_exp_jwt("30 minutes", iat) == iat + 1800


def test_to_exp_jwt_negative() -> None:
    iat = 1000
    assert to_exp_jwt("-1h", iat) == iat - 3600
    assert to_exp_jwt("1h ago", iat) == iat - 3600


def test_to_exp_jwt_invalid() -> None:
    iat = 1000
    for bad in ("invalid", "", "abc123"):
        with pytest.raises(TypeError):
            to_exp_jwt(bad, iat)


# ----- rotation (ported from rotation.test.ts) -----


async def test_rotation_creates_new_key_when_expired(monkeypatch) -> None:
    """Ported from "should rotate keys when expired"."""
    auth = _auth(JwtOptions(algorithm="ES256", rotation_interval=1))

    fake_now = [1_000_000]
    monkeypatch.setattr(jwt_mod.time, "time", lambda: fake_now[0])

    await sign_jwt(auth.context, payload={"sub": "user1"})
    rows = await auth.context.adapter.find_many(model="jwk")
    assert len(rows) == 1
    first_kid = rows[0]["keyId"]

    # Advance past the rotation interval.
    fake_now[0] += 2
    await sign_jwt(auth.context, payload={"sub": "user1"})
    rows = await auth.context.adapter.find_many(model="jwk")
    assert len(rows) == 2
    assert rows[-1]["keyId"] != first_kid


async def test_rotation_grace_period(monkeypatch) -> None:
    """Ported from "should return keys within grace period"."""
    auth = _auth(
        JwtOptions(algorithm="ES256", rotation_interval=1, grace_period=1)
    )

    fake_now = [1_000_000]
    monkeypatch.setattr(jwt_mod.time, "time", lambda: fake_now[0])

    # First key.
    await sign_jwt(auth.context, payload={"sub": "user1"})

    # Past rotation interval but within grace: signing rotates -> 2 keys.
    fake_now[0] += 2
    await sign_jwt(auth.context, payload={"sub": "user1"})
    rows = await auth.context.adapter.find_many(model="jwk")
    assert len(rows) == 2

    # Both keys present in the JWKS while in grace.
    jwks = await _get_jwks_via_handler(auth, fake_now)
    assert len(jwks["keys"]) == 2

    # Past the grace period: the first key drops out.
    fake_now[0] += 2
    jwks = await _get_jwks_via_handler(auth, fake_now)
    assert len(jwks["keys"]) == 1


async def _get_jwks_via_handler(auth, fake_now) -> dict:
    from better_auth.plugins.jwt.plugin import _get_jwks

    class _Ctx:
        def __init__(self, a):
            self.auth = a

    return await _get_jwks(_Ctx(auth.context))
