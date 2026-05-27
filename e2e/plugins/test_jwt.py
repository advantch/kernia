"""E2E test for the JWT plugin via ASGI router.

Signs up, hits /token, fetches /jwks, verifies the issued token against the
published JWKS. Also exercises rotation: a token issued before rotation still
verifies; new tokens use a new kid.
"""

from __future__ import annotations

import base64
import json

import pytest
from authlib.jose import JsonWebKey, jwt as jose_jwt

from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.plugins.jwt import JwtOptions, jwt
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_test_utils import ASGIDriver


def _decode_header(token: str) -> dict:
    h, _, _ = token.partition(".")
    pad = "=" * (-len(h) % 4)
    return json.loads(base64.urlsafe_b64decode(h + pad))


@pytest.fixture
def driver() -> ASGIDriver:
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret",
            plugins=[
                email_and_password(),
                jwt(JwtOptions(algorithm="ES256", issuer="https://test", audience="aud-x")),
            ],
        )
    )
    return ASGIDriver(app=auth.router.mount())


async def _signup(d: ASGIDriver) -> None:
    r = await d.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "jwt@test", "password": "correcthorse"},
    )
    assert r.status == 200, r.json()


async def test_token_then_jwks_verifies(driver: ASGIDriver) -> None:
    await _signup(driver)
    r = await driver.request("GET", "/token")
    assert r.status == 200, r.json()
    token = r.json()["token"]
    assert isinstance(token, str) and token.count(".") == 2

    r = await driver.request("GET", "/jwks")
    assert r.status == 200
    jwks = r.json()
    assert "keys" in jwks
    assert len(jwks["keys"]) >= 1
    # Token's kid must be in the JWKS
    header = _decode_header(token)
    assert any(k["kid"] == header["kid"] for k in jwks["keys"])

    claims = jose_jwt.decode(token, JsonWebKey.import_key_set(jwks))
    assert claims["sub"]
    assert claims["iss"] == "https://test"
    assert claims["aud"] == "aud-x"


async def test_rotation_old_token_still_verifies(driver: ASGIDriver) -> None:
    await _signup(driver)
    r = await driver.request("GET", "/token")
    old_token = r.json()["token"]
    old_kid = _decode_header(old_token)["kid"]

    # Rotate (no admin token configured by default → allowed because session exists)
    r = await driver.request("POST", "/jwks/rotate")
    assert r.status == 200, r.json()
    new_kid = r.json()["kid"]
    assert new_kid != old_kid

    # New token uses new kid
    r = await driver.request("GET", "/token")
    new_token = r.json()["token"]
    assert _decode_header(new_token)["kid"] == new_kid

    # JWKS contains both keys; both tokens verify
    r = await driver.request("GET", "/jwks")
    jwks = r.json()
    kids = {k["kid"] for k in jwks["keys"]}
    assert old_kid in kids and new_kid in kids

    claims_old = jose_jwt.decode(old_token, JsonWebKey.import_key_set(jwks))
    claims_new = jose_jwt.decode(new_token, JsonWebKey.import_key_set(jwks))
    assert claims_old["sub"] == claims_new["sub"]


async def test_token_requires_session() -> None:
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="s",
            plugins=[email_and_password(), jwt()],
        )
    )
    d = ASGIDriver(app=auth.router.mount())
    r = await d.request("GET", "/token")
    assert r.status == 401
