"""Ported from reference/packages/oauth-provider/src/pkce-optional.test.ts.

Upstream returns errors as a redirect with `?error=...&error_description=...`;
the Python authorize endpoint returns JSON `{error, error_description}` with a
4xx status. Assertions target the equivalent error envelope. PKCE-requirement
logic (`_pkce_required`) and the token-side consistency checks mirror upstream
`isPKCERequired` / token.ts exactly.
"""

from __future__ import annotations

import pytest
from kernia.oauth2 import pkce_challenge, pkce_verifier
from kernia_oauth_provider.plugin import create_client
from kernia_test_utils import ASGIDriver

from .conftest import REDIRECT_URI, SCOPES, exchange_code, make_auth, signup


async def _authorize(driver, client, *, scope="openid", challenge=None):
    query = (
        f"response_type=code&client_id={client.client_id}"
        f"&redirect_uri={client.redirect_uris[0]}&scope={scope.replace(' ', '%20')}&state=123"
    )
    if challenge:
        query += f"&code_challenge={challenge}&code_challenge_method=S256"
    return await driver.request("GET", "/oauth2/authorize", query=query)


@pytest.fixture
async def clients():
    auth = make_auth()
    driver = ASGIDriver(app=auth.router.mount())
    await signup(driver)
    confidential = await create_client(
        auth.context, name="conf", redirect_uris=[REDIRECT_URI], allowed_scopes=SCOPES
    )
    public = await create_client(
        auth.context,
        name="pub",
        redirect_uris=[REDIRECT_URI],
        allowed_scopes=SCOPES,
        token_endpoint_auth_method="none",
    )
    confidential_no_pkce = await create_client(
        auth.context,
        name="conf-no-pkce",
        redirect_uris=[REDIRECT_URI],
        allowed_scopes=SCOPES,
        require_pkce=False,
    )
    return auth, driver, confidential, public, confidential_no_pkce


# ----- default behavior -----


async def test_public_client_without_pkce_fails(clients) -> None:
    _, driver, _, public, _ = clients
    r = await _authorize(driver, public, scope="openid")
    assert r.status == 400
    assert r.json()["data"]["error"] == "invalid_request"
    assert r.json()["data"]["error_description"] == "pkce is required for public clients"


async def test_confidential_without_pkce_fails_default(clients) -> None:
    _, driver, conf, _, _ = clients
    r = await _authorize(driver, conf, scope="openid")
    assert r.status == 400
    assert r.json()["data"]["error"] == "invalid_request"
    assert r.json()["data"]["error_description"] == "pkce is required for this client"


async def test_confidential_with_pkce_succeeds(clients) -> None:
    _, driver, conf, _, _ = clients
    verifier = pkce_verifier()
    r = await _authorize(driver, conf, scope="openid", challenge=pkce_challenge(verifier))
    assert r.status == 200, r.json()
    assert r.json()["code"]


# ----- per-client opt-out -----


async def test_public_without_pkce_always_fails(clients) -> None:
    _, driver, _, public, _ = clients
    r = await _authorize(driver, public, scope="openid")
    assert r.status == 400
    assert r.json()["data"]["error_description"] == "pkce is required for public clients"


async def test_confidential_no_pkce_succeeds(clients) -> None:
    _, driver, _, _, conf_no_pkce = clients
    r = await _authorize(driver, conf_no_pkce, scope="openid")
    assert r.status == 200, r.json()
    code = r.json()["code"]
    tr = await exchange_code(driver, conf_no_pkce, code, None, scope="openid")
    assert tr.status == 200, tr.json()
    assert tr.json()["access_token"]
    assert tr.json()["id_token"]


# ----- offline_access scope -----


async def test_offline_access_without_pkce_fails(clients) -> None:
    _, driver, _, _, conf_no_pkce = clients
    r = await _authorize(driver, conf_no_pkce, scope="openid offline_access")
    assert r.status == 400
    assert (
        r.json()["data"]["error_description"]
        == "pkce is required when requesting offline_access scope"
    )


async def test_offline_access_with_pkce_succeeds(clients) -> None:
    _, driver, _, _, conf_no_pkce = clients
    verifier = pkce_verifier()
    r = await _authorize(
        driver, conf_no_pkce, scope="openid offline_access", challenge=pkce_challenge(verifier)
    )
    assert r.status == 200, r.json()
    code = r.json()["code"]
    tr = await exchange_code(driver, conf_no_pkce, code, verifier, scope="openid offline_access")
    assert tr.status == 200, tr.json()
    assert tr.json()["access_token"]
    assert tr.json()["refresh_token"]


# ----- consistency checks -----


async def test_pkce_in_auth_not_in_token_fails(clients) -> None:
    _, driver, _, _, conf_no_pkce = clients
    verifier = pkce_verifier()
    r = await _authorize(driver, conf_no_pkce, scope="openid", challenge=pkce_challenge(verifier))
    code = r.json()["code"]
    tr = await exchange_code(driver, conf_no_pkce, code, None, scope="openid")
    assert tr.status == 401
    assert (
        "code_verifier required because PKCE was used in authorization"
        in tr.json()["data"]["error_description"]
    )


async def test_pkce_not_in_auth_but_in_token_fails(clients) -> None:
    _, driver, _, _, conf_no_pkce = clients
    r = await _authorize(driver, conf_no_pkce, scope="openid")
    code = r.json()["code"]
    tr = await exchange_code(driver, conf_no_pkce, code, pkce_verifier(), scope="openid")
    assert tr.status == 401
    assert (
        "code_verifier provided but PKCE was not used in authorization"
        in tr.json()["data"]["error_description"]
    )


async def test_mismatched_pkce_challenge_fails(clients) -> None:
    _, driver, _, _, conf_no_pkce = clients
    verifier = pkce_verifier()
    r = await _authorize(driver, conf_no_pkce, scope="openid", challenge=pkce_challenge(verifier))
    code = r.json()["code"]
    tr = await exchange_code(driver, conf_no_pkce, code, pkce_verifier(), scope="openid")
    assert tr.status == 401
    assert "code verification failed" in tr.json()["data"]["error_description"]
