"""Unit tests for the JWT plugin.

Exercises key generation, signing, JWKS publication, and rotation directly via
the plugin's helper functions (no router).
"""

from __future__ import annotations

import json

import pytest
from authlib.jose import JsonWebKey
from authlib.jose import jwt as jose_jwt
from better_auth.auth import init
from better_auth.plugins.jwt import jwt as jwt_plugin
from better_auth.plugins.jwt.plugin import (
    JwtOptions,
    _create_key,
    _get_active_key,
    issue_jwt,
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
