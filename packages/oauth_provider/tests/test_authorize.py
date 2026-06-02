"""Ported from reference/packages/oauth-provider/src/authorize.test.ts.

Portability notes:

* The Python `_authorize` endpoint returns JSON `{redirect, code, state}` with a
  4xx + JSON `{error, error_description}` envelope on failure, rather than HTTP
  302 redirects with `?error=...&iss=...`. The success-path RFC 9207 `iss`
  behavior is portable and asserted by parsing the returned `redirect` URL.
* `validateIssuerUrl` (HTTP->HTTPS coercion, query/fragment/trailing-slash
  stripping, localhost exemption) has no equivalent in the Python port -- the
  issuer is consumed exactly as configured -- so that describe-block is skipped.
* `prompt=none` -> `login_required`/`consent_required` redirects, the unauth ->
  `/login` redirect, and PAR `request_uri` resolution depend on session-gated
  authorize + login/consent pages + a PAR resolver the port does not implement.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest
from kernia.oauth2 import pkce_challenge, pkce_verifier
from kernia_oauth_provider.plugin import create_client
from kernia_test_utils import ASGIDriver

from .conftest import ISSUER, REDIRECT_URI, SCOPES, make_auth, signup


@pytest.fixture
async def setup():
    auth = make_auth()
    driver = ASGIDriver(app=auth.router.mount())
    await signup(driver)
    client = await create_client(
        auth.context, name="conf", redirect_uris=[REDIRECT_URI], allowed_scopes=SCOPES
    )
    return auth, driver, client


async def _authorize(driver, client, *, scope="openid", state="123", challenge=None):
    query = (
        f"response_type=code&client_id={client.client_id}"
        f"&redirect_uri={client.redirect_uris[0]}"
        f"&scope={scope.replace(' ', '%20')}&state={state}"
    )
    if challenge:
        query += f"&code_challenge={challenge}&code_challenge_method=S256"
    return await driver.request("GET", "/oauth2/authorize", query=query)


# ----- success path (RFC 9207 iss) -----


async def test_authorize_redirect_includes_code_state_and_iss(setup) -> None:
    _, driver, client = setup
    verifier = pkce_verifier()
    r = await _authorize(
        driver, client, scope="openid", state="123", challenge=pkce_challenge(verifier)
    )
    assert r.status == 200, r.json()
    body = r.json()
    redirect = body["redirect"]
    assert redirect.startswith(REDIRECT_URI)
    qs = parse_qs(urlsplit(redirect).query)
    assert qs["code"] == [body["code"]]
    assert qs["state"] == ["123"]
    assert qs["iss"] == [ISSUER]


async def test_iss_matches_advertised_metadata_issuer(setup) -> None:
    # RFC 9207: the iss in the authorization response must equal the issuer in
    # the discovery metadata.
    _, driver, client = setup
    metadata = (
        await driver.request("GET", "/.well-known/openid-configuration")
    ).json()
    verifier = pkce_verifier()
    r = await _authorize(
        driver, client, scope="openid", challenge=pkce_challenge(verifier)
    )
    qs = parse_qs(urlsplit(r.json()["redirect"]).query)
    assert qs["iss"] == [metadata["issuer"]]


# ----- error path -----


async def test_unregistered_redirect_uri_rejected(setup) -> None:
    _, driver, client = setup
    query = (
        f"response_type=code&client_id={client.client_id}"
        f"&redirect_uri=https://evil.test/cb&scope=openid&state=123"
    )
    r = await driver.request("GET", "/oauth2/authorize", query=query)
    assert r.status == 400
    # redirect_uri validation predates client resolution, so it uses the core
    # APIError envelope ({code, message}) rather than the OAuth error envelope.
    assert "redirect_uri" in r.json()["message"]


async def test_missing_pkce_is_invalid_request(setup) -> None:
    # Mirrors upstream "error=invalid_request" + "pkce"; the port returns the
    # same error code in its JSON envelope rather than an error redirect.
    _, driver, client = setup
    r = await _authorize(driver, client, scope="openid")
    assert r.status == 400
    assert r.json()["data"]["error"] == "invalid_request"
    assert "pkce" in r.json()["data"]["error_description"]


@pytest.mark.skip(
    reason="validateIssuerUrl (HTTP->HTTPS coercion, query/fragment/trailing-slash "
    "stripping, localhost exemption) has no equivalent in the Python port -- the "
    "issuer is used exactly as configured."
)
async def test_validate_issuer_url_cases() -> None:
    ...


@pytest.mark.skip(
    reason="prompt=none login_required/consent_required redirects, the "
    "unauthenticated -> /login redirect, and PAR request_uri resolution require "
    "session-gated authorize + login/consent pages + a PAR resolver not "
    "implemented in the Python port."
)
async def test_prompt_none_and_par_cases() -> None:
    ...
