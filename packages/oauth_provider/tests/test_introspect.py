"""Ported from reference/packages/oauth-provider/src/introspect.test.ts.

The Python port issues self-contained JWT access tokens by default, so the
upstream "opaque" / "jwt" duplicated cases collapse into one each. The
token_type_hint matrix (the spec-relevant behavior), the `sid` claim, and the
logged-out-user cases are ported: access tokens carry the issuing session id,
and introspection surfaces it as `sid` only while the session is still live —
mirroring upstream's `validateJwtAccessToken` / `validateOpaqueAccessToken`
session-liveness check.
"""

from __future__ import annotations

from better_auth.types.adapter import Where

from .conftest import authorize_code, exchange_code, get_tokens


async def _session_id(driver) -> str:
    r = await driver.request("GET", "/get-session")
    assert r.status == 200, r.json()
    return r.json()["session"]["id"]


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


# ----- the `sid` claim (session linkage) -----


async def test_access_token_carries_sid(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client)
    r = await _introspect(driver, client, tokens["access_token"], "access_token")
    assert r.status == 200, r.json()
    assert r.json()["sid"] == await _session_id(driver)


async def test_no_hint_access_token_carries_sid(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client)
    r = await _introspect(driver, client, tokens["access_token"])
    assert r.status == 200, r.json()
    assert r.json()["sid"] == await _session_id(driver)


async def test_refresh_token_carries_sid(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client)
    r = await _introspect(driver, client, tokens["refresh_token"], "refresh_token")
    assert r.status == 200, r.json()
    assert r.json()["sid"] == await _session_id(driver)


async def test_access_token_sid_dropped_for_logged_out_user(confidential) -> None:
    # After the backing session is terminated the token stays active (the JWT is
    # stateless), but introspection no longer reports a `sid`.
    auth, driver, client = confidential
    sid = await _session_id(driver)
    code, verifier = await authorize_code(
        driver, client, scope="openid profile email offline_access"
    )
    tokens = (
        await exchange_code(
            driver, client, code, verifier, scope="openid profile email offline_access"
        )
    ).json()
    await auth.context.adapter.delete(
        model="session", where=(Where(field="id", value=sid),)
    )
    r = await _introspect(driver, client, tokens["access_token"], "access_token")
    assert r.status == 200, r.json()
    assert r.json()["active"] is True
    assert "sid" not in r.json()


async def test_refresh_token_sid_dropped_for_logged_out_user(confidential) -> None:
    auth, driver, client = confidential
    sid = await _session_id(driver)
    tokens = await get_tokens(driver, client)
    await auth.context.adapter.delete(
        model="session", where=(Where(field="id", value=sid),)
    )
    r = await _introspect(driver, client, tokens["refresh_token"], "refresh_token")
    assert r.status == 200, r.json()
    assert r.json()["active"] is True
    assert "sid" not in r.json()
