"""Ported from reference/packages/oauth-provider/src/userinfo.test.ts.

The Python port issues self-contained JWT access tokens (no opaque-vs-jwt split),
so the upstream "opaque" / "jwt" duplicated cases collapse into one each. The
"logged out user" cases are not portable: the Python access token is a stateless
JWT not tied to a session row, so signing the user out does not invalidate it
(see the skip below).
"""

from __future__ import annotations

import pytest

from .conftest import get_tokens


async def _userinfo(driver, token):
    return await driver.request(
        "GET", "/oauth2/userinfo", headers={"authorization": f"Bearer {token}"}
    )


async def test_fail_unauthenticated_request(confidential) -> None:
    _, driver, _ = confidential
    r = await driver.request("GET", "/oauth2/userinfo")
    assert r.status == 401
    assert r.json()["data"]["error"] == "invalid_request"
    assert r.json()["data"]["error_description"] == "authorization header not found"


async def test_fail_without_openid_scope(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client, scope="profile")
    r = await _userinfo(driver, tokens["access_token"])
    assert r.status == 400


async def test_provide_all_user_information(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client)
    r = await _userinfo(driver, tokens["access_token"])
    assert r.status == 200, r.json()
    info = r.json()
    assert info["sub"]
    assert info["name"] == "Test User"
    assert info["given_name"] == "Test"
    assert info["family_name"] == "User"
    assert info["email"] == "u@test"
    assert info["email_verified"] is False


async def test_scoped_sub_only(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client, scope="openid")
    r = await _userinfo(driver, tokens["access_token"])
    assert r.status == 200, r.json()
    info = r.json()
    assert info["sub"]
    assert "name" not in info
    assert "given_name" not in info
    assert "family_name" not in info
    assert "email" not in info
    assert "email_verified" not in info


async def test_scoped_profile_only(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client, scope="openid profile")
    r = await _userinfo(driver, tokens["access_token"])
    assert r.status == 200, r.json()
    info = r.json()
    assert info["sub"]
    assert info["name"] == "Test User"
    assert info["given_name"] == "Test"
    assert info["family_name"] == "User"
    assert "email" not in info
    assert "email_verified" not in info


async def test_scoped_email_only(confidential) -> None:
    _, driver, client = confidential
    tokens = await get_tokens(driver, client, scope="openid email")
    r = await _userinfo(driver, tokens["access_token"])
    assert r.status == 200, r.json()
    info = r.json()
    assert info["sub"]
    assert info["email"] == "u@test"
    assert info["email_verified"] is False
    assert "name" not in info
    assert "given_name" not in info
    assert "family_name" not in info


@pytest.mark.skip(
    reason="Python access tokens are stateless JWTs not bound to a session row; "
    "signing the user out does not invalidate an already-issued access token "
    "(upstream uses opaque DB-backed tokens for the logged-out cases)."
)
async def test_userinfo_with_logged_out_user() -> None:
    ...
