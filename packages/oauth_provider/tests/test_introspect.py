"""Ported from reference/packages/oauth-provider/src/introspect.test.ts.

The Python port issues self-contained JWT access tokens, so the upstream
"opaque" / "jwt" duplicated cases collapse into one each. The `sid` claim and
the logged-out-user cases are not portable (stateless JWT, no session linkage).
The token_type_hint matrix (the spec-relevant behavior) is ported faithfully.
"""

from __future__ import annotations

from .conftest import get_tokens


async def _introspect(driver, client, token, hint=None):
    body = {
        "client_id": client.client_id,
        "client_secret": client.client_secret,
        "token": token,
    }
    if hint is not None:
        body["token_type_hint"] = hint
    return await driver.request("POST", "/oauth2/introspect", json_body=body)


async def test_fail_unauthenticated_no_client_credentials(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client)
    r = await driver.request(
        "POST", "/oauth2/introspect", json_body={"token": tokens["access_token"]}
    )
    assert r.status == 401


async def test_hint_access_token_with_access_token(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client)
    r = await _introspect(driver, client, tokens["access_token"], "access_token")
    assert r.status == 200, r.json()
    data = r.json()
    assert data["active"] is True
    assert data["client_id"] == client.client_id
    assert data["scope"] == "openid profile email offline_access"
    assert isinstance(data["sub"], str)
    assert data["iss"] == "https://issuer.test"
    assert isinstance(data["exp"], int)
    assert isinstance(data["iat"], int)


async def test_hint_access_token_with_refresh_token_inactive(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client)
    r = await _introspect(driver, client, tokens["refresh_token"], "access_token")
    assert r.status == 200, r.json()
    assert not r.json()["active"]


async def test_hint_refresh_token_with_refresh_token(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client)
    r = await _introspect(driver, client, tokens["refresh_token"], "refresh_token")
    assert r.status == 200, r.json()
    data = r.json()
    assert data["active"] is True
    assert data["client_id"] == client.client_id
    assert data["scope"] == "openid profile email offline_access"
    assert isinstance(data["sub"], str)


async def test_hint_refresh_token_with_access_token_inactive(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client)
    r = await _introspect(driver, client, tokens["access_token"], "refresh_token")
    assert r.status == 200, r.json()
    assert not r.json()["active"]


async def test_no_hint_with_access_token(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client)
    r = await _introspect(driver, client, tokens["access_token"])
    assert r.status == 200, r.json()
    data = r.json()
    assert data["active"] is True
    assert data["client_id"] == client.client_id
    assert data["scope"] == "openid profile email offline_access"
    assert isinstance(data["sub"], str)
    assert data["iss"] == "https://issuer.test"


async def test_no_hint_with_refresh_token(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client)
    r = await _introspect(driver, client, tokens["refresh_token"])
    assert r.status == 200, r.json()
    data = r.json()
    assert data["active"] is True
    assert data["client_id"] == client.client_id
    assert data["scope"] == "openid profile email offline_access"
    assert isinstance(data["sub"], str)
