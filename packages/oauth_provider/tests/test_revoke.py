"""Ported from reference/packages/oauth-provider/src/revoke.test.ts.

JWT access tokens collapse the upstream opaque/jwt duplication into one case
each. The spec-relevant token_type_hint mismatch behavior (RFC 7009) is ported:
a hint that contradicts the presented token yields 400.
"""

from __future__ import annotations

from .conftest import get_tokens


async def _revoke(driver, client, token, hint=None):
    body = {
        "client_id": client.client_id,
        "client_secret": client.client_secret,
        "token": token,
    }
    if hint is not None:
        body["token_type_hint"] = hint
    return await driver.request("POST", "/oauth2/revoke", json_body=body)


async def test_fail_unauthenticated_request(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client)
    r = await driver.request(
        "POST", "/oauth2/revoke", json_body={"token": tokens["access_token"]}
    )
    assert r.status == 401


async def test_hint_access_token_with_access_token(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client)
    r = await _revoke(driver, client, tokens["access_token"], "access_token")
    assert r.status == 200, r.json()


async def test_hint_access_token_with_refresh_token_fails(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client)
    r = await _revoke(driver, client, tokens["refresh_token"], "access_token")
    assert r.status == 400


async def test_hint_refresh_token_with_refresh_token(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client)
    r = await _revoke(driver, client, tokens["refresh_token"], "refresh_token")
    assert r.status == 200, r.json()


async def test_hint_refresh_token_with_access_token_fails(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client)
    r = await _revoke(driver, client, tokens["access_token"], "refresh_token")
    assert r.status == 400


async def test_no_hint_with_access_token(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client)
    r = await _revoke(driver, client, tokens["access_token"])
    assert r.status == 200, r.json()


async def test_no_hint_with_refresh_token(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client)
    r = await _revoke(driver, client, tokens["refresh_token"])
    assert r.status == 200, r.json()
    # Refresh token is now dead.
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": client.client_id,
            "client_secret": client.client_secret,
        },
    )
    assert r.status == 400
