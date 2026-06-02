"""Ported from reference/packages/oauth-provider/src/logout.test.ts.

OIDC RP-initiated logout (`end_session_endpoint`). Upstream drives a live
browser flow against `/api/auth/oauth2/...`; here we exercise the same endpoints
through the ASGI test driver, which auto-tracks the session cookie.

Port divergences (kept behaviour-identical, asserted 1:1 where it matters):

* This port serialises JSON rather than emitting a real HTTP 302; the
  post-logout redirect is returned as a `{"redirect": ...}` body plus a
  `Location` response header (the same convention the authorize endpoint uses),
  so the redirection cases assert on those instead of `error.status === 302`.
* The port always issues JWT id_tokens; there is no `disableJwtPlugin` option,
  so the second upstream describe (`oauth logout - disableJwtPlugin`) reduces to
  the already-covered JWT path and is marked skipped.
"""

from __future__ import annotations

import pytest
from kernia_oauth_provider.plugin import create_client
from kernia_test_utils import ASGIDriver

from .conftest import (
    REDIRECT_URI,
    SCOPES,
    authorize_code,
    decode_jwt_payload,
    exchange_code,
    make_auth,
    signup,
)

LOGOUT_REDIRECT_URI = "https://client.test/cb/logout"


async def _logged_in():
    """A freshly signed-in user (session cookie set on the driver)."""
    auth = make_auth()
    driver = ASGIDriver(app=auth.router.mount())
    await signup(driver)
    return auth, driver


async def _tokens(driver, client):
    code, verifier = await authorize_code(driver, client, scope=" ".join(SCOPES))
    r = await exchange_code(driver, client, code, verifier, scope=" ".join(SCOPES))
    assert r.status == 200, r.json()
    return r.json()


async def _session_id(driver) -> str:
    r = await driver.request("GET", "/get-session")
    assert r.status == 200, r.json()
    return r.json()["session"]["id"]


# ----- describe("oauth logout") -----


async def test_should_fail_with_invalid_id_token_hint() -> None:
    _, driver = await _logged_in()
    r = await driver.request(
        "GET", "/oauth2/end-session", query="id_token_hint="
    )
    assert r.status == 401, r.json()


async def test_should_not_allow_registration_of_rp_initiated_clients() -> None:
    """Dynamic registration may set post_logout_redirect_uris but NOT
    enable_end_session (privileged, admin-only)."""
    _, driver = await _logged_in()
    r = await driver.request(
        "POST",
        "/oauth2/register",
        json_body={
            "name": "rp",
            "redirect_uris": [REDIRECT_URI],
            "post_logout_redirect_uris": [LOGOUT_REDIRECT_URI],
            "enable_end_session": True,
        },
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["client_id"]
    assert body["client_secret"]
    assert body["redirect_uris"] == [REDIRECT_URI]
    assert body["post_logout_redirect_uris"] == [LOGOUT_REDIRECT_URI]
    assert "enable_end_session" not in body


async def test_should_fail_for_clients_without_enable_end_session_access() -> None:
    auth, driver = await _logged_in()
    client = await create_client(
        auth.context,
        name="no-logout",
        redirect_uris=[REDIRECT_URI],
        allowed_scopes=SCOPES,
    )
    tokens = await _tokens(driver, client)
    assert tokens["access_token"]
    assert tokens["id_token"]
    assert tokens["refresh_token"]
    # Id token must NOT carry an sid claim for a non-opted-in client.
    assert "sid" not in decode_jwt_payload(tokens["id_token"])

    r = await driver.request(
        "GET",
        "/oauth2/end-session",
        query=f"id_token_hint={tokens['id_token']}",
    )
    assert r.status == 401, r.json()


async def test_should_pass_for_clients_with_enable_end_session_access() -> None:
    auth, driver = await _logged_in()
    client = await create_client(
        auth.context,
        name="logout-ok",
        redirect_uris=[REDIRECT_URI],
        allowed_scopes=SCOPES,
        enable_end_session=True,
    )
    tokens = await _tokens(driver, client)
    # Id token should carry an sid claim equal to the active session id.
    session_id = decode_jwt_payload(tokens["id_token"]).get("sid")
    assert session_id
    assert session_id == await _session_id(driver)

    r = await driver.request(
        "GET",
        "/oauth2/end-session",
        query=f"id_token_hint={tokens['id_token']}",
    )
    assert r.status == 200, r.json()
    assert r.json() is None

    # The session has been terminated.
    after = await driver.request("GET", "/get-session")
    assert after.status == 200
    assert after.json() is None


async def test_should_pass_with_redirection() -> None:
    auth, driver = await _logged_in()
    client = await create_client(
        auth.context,
        name="logout-redirect",
        redirect_uris=[REDIRECT_URI],
        allowed_scopes=SCOPES,
        enable_end_session=True,
        post_logout_redirect_uris=[LOGOUT_REDIRECT_URI],
    )
    tokens = await _tokens(driver, client)
    assert decode_jwt_payload(tokens["id_token"]).get("sid")

    r = await driver.request(
        "GET",
        "/oauth2/end-session",
        query=(
            f"id_token_hint={tokens['id_token']}"
            f"&post_logout_redirect_uri={LOGOUT_REDIRECT_URI}&state=123"
        ),
    )
    assert r.status == 200, r.json()
    redirect = r.json()["redirect"]
    assert LOGOUT_REDIRECT_URI in redirect
    assert "state=123" in redirect
    assert dict(r.headers).get("Location") == redirect


@pytest.mark.skip(
    reason="`disableJwtPlugin` is a JS-only option; this port always issues JWT "
    "id_tokens, so the upstream `oauth logout - disableJwtPlugin` describe "
    "reduces to the JWT path already covered above."
)
async def test_disable_jwt_plugin_logout_variants() -> None:
    ...
