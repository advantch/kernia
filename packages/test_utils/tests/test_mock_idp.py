"""MockIdP verification: JWKS round-trips through the core verifier."""

from __future__ import annotations

import httpx

from kernia.oauth2 import verify_id_token
from kernia_test_utils import MockIdP


async def test_jwks_endpoint_serves_valid_keys() -> None:
    idp = MockIdP(issuer="https://idp.test", audience="client-1")
    async with httpx.AsyncClient(transport=idp.mock_transport()) as client:
        r = await client.get("https://idp.test/.well-known/jwks.json")
        assert r.status_code == 200
        jwks = r.json()
        assert len(jwks["keys"]) == 1
        key = jwks["keys"][0]
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert key["kid"] == idp.kid


async def test_discovery_doc_advertises_endpoints() -> None:
    idp = MockIdP(issuer="https://idp.test")
    async with httpx.AsyncClient(transport=idp.mock_transport()) as client:
        r = await client.get("https://idp.test/.well-known/openid-configuration")
        assert r.status_code == 200
        body = r.json()
        assert body["issuer"] == "https://idp.test"
        assert body["jwks_uri"].endswith("/.well-known/jwks.json")
        assert "RS256" in body["id_token_signing_alg_values_supported"]


async def test_id_token_verifies_under_core_verifier() -> None:
    idp = MockIdP(issuer="https://idp.test", audience="client-1")
    token = idp.id_token_for("user-1", email="a@b.c", name="A")
    async with httpx.AsyncClient(transport=idp.mock_transport()) as client:
        claims = await verify_id_token(
            id_token=token,
            jwks_url="https://idp.test/.well-known/jwks.json",
            audience="client-1",
            issuer="https://idp.test",
            http_client=client,
        )
    assert claims["sub"] == "user-1"
    assert claims["email"] == "a@b.c"


async def test_token_endpoint_returns_signed_id_token_and_userinfo() -> None:
    idp = MockIdP(issuer="https://idp.test", audience="client-1")
    idp.create_user(sub="u42", email="x@y.z", name="X Y")
    async with httpx.AsyncClient(transport=idp.mock_transport()) as client:
        tok = await client.post(
            "https://idp.test/token",
            data={"grant_type": "authorization_code", "code": "any"},
        )
        assert tok.status_code == 200
        body = tok.json()
        assert "id_token" in body
        assert body["token_type"] == "Bearer"

        # id_token verifies
        claims = await verify_id_token(
            id_token=body["id_token"],
            jwks_url="https://idp.test/.well-known/jwks.json",
            audience="client-1",
            issuer="https://idp.test",
            http_client=client,
        )
        assert claims["sub"] == "u42"

        # userinfo authenticated with the bearer token
        ui = await client.get(
            "https://idp.test/userinfo",
            headers={"authorization": f"Bearer {body['access_token']}"},
        )
        assert ui.status_code == 200
        assert ui.json()["sub"] == "u42"
        assert ui.json()["email"] == "x@y.z"


async def test_userinfo_rejects_unknown_token() -> None:
    idp = MockIdP()
    async with httpx.AsyncClient(transport=idp.mock_transport()) as client:
        r = await client.get(
            "https://test-idp/userinfo",
            headers={"authorization": "Bearer bogus"},
        )
        assert r.status_code == 401
