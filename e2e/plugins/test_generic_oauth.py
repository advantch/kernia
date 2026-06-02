"""End-to-end OIDC flow against the in-process `MockIdP`.

Wires the `generic_oauth` plugin against a `MockIdP`, then drives the full
sign-in flow through `ASGIDriver`:

  1. GET  /oauth2/sign-in/<id>  → 302 to MockIdP's authorize endpoint
  2. POST /oauth2/callback/<id>  with the code → 302 to the configured
     callbackURL, with the session cookie attached
  3. The created user/account is observable via /list-accounts.

We patch the global `httpx.AsyncClient` constructor to inject the MockIdP
transport — that's the same pattern the existing OIDC tests use.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.plugins.generic_oauth import GenericOAuthConfig, generic_oauth
from kernia.plugins.generic_oauth.routes import _DISCOVERY_CACHE
from kernia.types.adapter import Where
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_test_utils import ASGIDriver
from kernia_test_utils.mock_idp import MockIdP


@pytest.fixture(autouse=True)
def _clear_discovery_cache() -> None:
    _DISCOVERY_CACHE.clear()


@pytest.fixture
def idp() -> MockIdP:
    return MockIdP(issuer="https://idp.test", audience="cid")


@pytest.fixture
def patched_httpx(idp: MockIdP, monkeypatch: pytest.MonkeyPatch):
    transport = idp.mock_transport()
    original_init = httpx.AsyncClient.__init__

    def patched(self, *args, **kwargs):  # type: ignore[no-redef]
        kwargs["transport"] = transport
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched)
    return transport


def _build_driver(adapter):
    cfg = GenericOAuthConfig(
        provider_id="mockoidc",
        client_id="cid",
        client_secret="csec",
        discovery_url="https://idp.test/.well-known/openid-configuration",
        scopes=("openid", "email", "profile"),
    )
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="test-secret",
            base_url="http://localhost",
            plugins=[email_and_password(), generic_oauth([cfg])],
        )
    )
    return auth, ASGIDriver(app=auth.router.mount())


async def test_full_oidc_signin_flow(patched_httpx, idp: MockIdP) -> None:
    adapter = memory_adapter()
    auth, driver = _build_driver(adapter)
    idp.create_user(sub="u-1", email="alice@example.com", name="Alice")

    # 1. Sign-in: builds authorize URL + state, returns 302.
    r = await driver.request("GET", "/oauth2/sign-in/mockoidc")
    assert r.status == 302
    loc = next(v for k, v in r.headers if k.lower() == "location")
    parsed = urlparse(loc)
    qs = parse_qs(parsed.query)
    state_token = qs["state"][0]

    # 2. Simulate the IdP redirect back to our callback. MockIdP issues a code
    # on /token, but for our purposes the callback handler doesn't need a real
    # code: it just forwards it to `exchange_code`, and MockIdP's /token
    # endpoint always returns success regardless of the code value.
    r2 = await driver.request(
        "GET",
        "/oauth2/callback/mockoidc",
        query=f"code=abc&state={state_token}",
    )
    assert r2.status == 302, r2.json() if r2.body else r2.status
    # Session cookie should be set on the response.
    assert any(k.lower() == "set-cookie" for k, _ in r2.headers)

    # 3. The user should now exist in the adapter.
    rows = await adapter.find_many(model="user", where=())
    assert len(rows) == 1
    assert rows[0]["email"] == "alice@example.com"

    accounts = await adapter.find_many(
        model="account",
        where=(Where(field="providerId", value="mockoidc"),),
    )
    assert len(accounts) == 1
    assert accounts[0]["accountId"] == "u-1"


async def test_link_account_flow(patched_httpx, idp: MockIdP) -> None:
    adapter = memory_adapter()
    auth, driver = _build_driver(adapter)

    # First: sign up via email/password to get a session.
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "bob@example.com", "password": "longpassword"},
    )
    assert r.status == 200
    user = r.json()["user"]

    # Now ask /oauth2/link for an authorize URL (requires session).
    r2 = await driver.request(
        "POST",
        "/oauth2/link",
        json_body={
            "provider_id": "mockoidc",
            "callback_url": "http://localhost/after-link",
        },
    )
    assert r2.status == 200
    url = r2.json()["url"]
    state_token = parse_qs(urlparse(url).query)["state"][0]

    # Pretend the user came back from the IdP. Upstream rejects linking when the
    # OAuth email differs from the signed-in user's email (unless
    # allowDifferentEmails is set), so use the same email here.
    idp.create_user(sub="u-link", email="bob@example.com", name="Bob")
    r3 = await driver.request(
        "GET",
        "/oauth2/callback/mockoidc",
        query=f"code=abc&state={state_token}",
    )
    assert r3.status == 302

    # The new account row should be linked to bob.
    accounts = await adapter.find_many(
        model="account",
        where=(Where(field="userId", value=user["id"]),),
    )
    provider_ids = {a["providerId"] for a in accounts}
    assert "mockoidc" in provider_ids
    assert "credential" in provider_ids


# ---------------------------------------------------------------------------
# Upstream parity ports — mirrors
# reference/packages/better-auth/src/plugins/generic-oauth/generic-oauth.test.ts
#
# The upstream suite drives the flow through `signIn.oauth2` (POST
# /sign-in/oauth2 → {url, redirect}) then `simulateOAuthFlow`, which GETs the
# authorization URL on a *live* mock IdP that 302s back to the callback. Our
# in-process MockIdP has no redirecting /authorize, so we instead extract the
# signed `state` from the returned `url` and invoke the callback directly with
# `code=...&state=...` — the same pattern the two original tests above use.
# Everything downstream (token exchange, userinfo, user/account creation,
# error redirects) is exercised identically.
# ---------------------------------------------------------------------------


def _location(resp) -> str:
    return next((v for k, v in resp.headers if k.lower() == "location"), "")


def _state_from_url(url: str) -> str:
    return parse_qs(urlparse(url).query)["state"][0]


def _make_auth(adapter, *configs):
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="test-secret",
            base_url="http://localhost",
            plugins=[email_and_password(), generic_oauth(list(configs))],
        )
    )
    return auth, ASGIDriver(app=auth.router.mount())


async def _signin(driver, provider_id: str, **body):
    payload = {"providerId": provider_id, **body}
    return await driver.request("POST", "/sign-in/oauth2", json_body=payload)


async def _callback(driver, provider_id: str, state: str, code: str = "abc", extra: str = ""):
    query = f"code={code}&state={state}"
    if extra:
        query += f"&{extra}"
    return await driver.request("GET", f"/oauth2/callback/{provider_id}", query=query)


def _discovery_cfg(provider_id="test", **overrides) -> GenericOAuthConfig:
    base = dict(
        provider_id=provider_id,
        client_id="test-client-id",
        client_secret="test-client-secret",
        discovery_url="https://idp.test/.well-known/openid-configuration",
        scopes=("openid", "email", "profile"),
        pkce=True,
    )
    base.update(overrides)
    return GenericOAuthConfig(**base)


# ----- core sign-in flows -----


async def test_redirect_to_provider_and_handle_response(patched_httpx, idp: MockIdP) -> None:
    """Existing user → callbackURL (dashboard)."""
    adapter = memory_adapter()
    auth, driver = _make_auth(adapter, _discovery_cfg())
    # Pre-create the user so this sign-in resolves an existing account/user.
    idp.create_user(sub="oauth2", email="oauth2@test.com", name="OAuth2 Test")
    # First sign-in creates them.
    res = await _signin(
        driver, "test", callbackURL="http://localhost/dashboard",
        newUserCallbackURL="http://localhost/new_user",
    )
    assert res.status == 200
    assert "https://idp.test/authorize" in res.json()["url"]
    assert res.json()["redirect"] is True
    state = _state_from_url(res.json()["url"])
    cb = await _callback(driver, "test", state)
    assert cb.status == 302
    assert _location(cb) == "http://localhost/new_user"

    # Second sign-in: now an existing user → dashboard.
    idp.create_user(sub="oauth2", email="oauth2@test.com", name="OAuth2 Test")
    res2 = await _signin(
        driver, "test", callbackURL="http://localhost/dashboard",
        newUserCallbackURL="http://localhost/new_user",
    )
    cb2 = await _callback(driver, "test", _state_from_url(res2.json()["url"]))
    assert _location(cb2) == "http://localhost/dashboard"


async def test_redirect_for_new_user_creates_account(patched_httpx, idp: MockIdP) -> None:
    adapter = memory_adapter()
    auth, driver = _make_auth(adapter, _discovery_cfg())
    idp.create_user(sub="oauth2-2", email="oauth2-2@test.com", name="OAuth2 Test 2")
    res = await _signin(
        driver, "test", callbackURL="http://localhost/dashboard",
        newUserCallbackURL="http://localhost/new_user",
    )
    cb = await _callback(driver, "test", _state_from_url(res.json()["url"]))
    assert _location(cb) == "http://localhost/new_user"

    accounts = await adapter.find_many(
        model="account",
        where=(Where(field="providerId", value="test"),),
    )
    assert len(accounts) == 1
    acc = accounts[0]
    assert acc["accountId"] == "oauth2-2"
    assert isinstance(acc["accessToken"], str)
    assert acc["accessToken"]
    assert acc["idToken"]


async def test_invalid_provider_id_returns_400(patched_httpx, idp: MockIdP) -> None:
    adapter = memory_adapter()
    auth, driver = _make_auth(adapter, _discovery_cfg())
    res = await _signin(driver, "invalid-provider", callbackURL="http://localhost/dashboard")
    assert res.status == 400


async def test_server_error_during_oauth_flow(patched_httpx, idp: MockIdP) -> None:
    """Provider yields no userinfo → callback redirects with ?error=."""
    async def _no_userinfo(_tokens):
        return None

    adapter = memory_adapter()
    auth, driver = _make_auth(
        adapter, _discovery_cfg("test-err", get_user_info=_no_userinfo)
    )
    res = await _signin(driver, "test-err", callbackURL="http://localhost/dashboard")
    cb = await _callback(driver, "test-err", _state_from_url(res.json()["url"]))
    assert cb.status == 302
    assert "?error=" in _location(cb) or "&error=" in _location(cb)


async def test_custom_redirect_uri(patched_httpx, idp: MockIdP) -> None:
    adapter = memory_adapter()
    auth, driver = _make_auth(
        adapter,
        _discovery_cfg("test2", redirect_uri="http://localhost/api/auth/callback/test2"),
    )
    idp.create_user(sub="cru", email="cru@test.com", name="Custom Redirect")
    res = await _signin(
        driver, "test2", callbackURL="http://localhost/dashboard",
        newUserCallbackURL="http://localhost/new_user",
    )
    url = res.json()["url"]
    assert "https://idp.test/authorize" in url
    assert "redirect_uri=http%3A%2F%2Flocalhost%2Fapi%2Fauth%2Fcallback%2Ftest2" in url
    cb = await _callback(driver, "test2", _state_from_url(url))
    assert _location(cb) == "http://localhost/new_user"


# ----- sign-up gating -----


async def test_no_user_when_signups_disabled(patched_httpx, idp: MockIdP) -> None:
    adapter = memory_adapter()
    auth, driver = _make_auth(
        adapter, _discovery_cfg("test2", disable_implicit_sign_up=True)
    )
    idp.create_user(
        sub="oauth2-signup-disabled",
        email="oauth2-signup-disabled@test.com",
        name="OAuth2 Test Signup Disabled",
    )
    res = await _signin(
        driver, "test2", callbackURL="http://localhost/dashboard",
        errorCallbackURL="http://localhost/error",
    )
    cb = await _callback(driver, "test2", _state_from_url(res.json()["url"]))
    assert _location(cb) == "http://localhost/error?error=signup_disabled"

    users = await adapter.find_many(model="user", where=())
    assert users == []


async def test_create_user_when_signup_requested(patched_httpx, idp: MockIdP) -> None:
    adapter = memory_adapter()
    auth, driver = _make_auth(
        adapter, _discovery_cfg("test2", disable_implicit_sign_up=True)
    )
    idp.create_user(
        sub="oauth2-signup-requested",
        email="oauth2-signup-requested@test.com",
        name="Requested",
    )
    res = await _signin(
        driver, "test2", callbackURL="http://localhost/dashboard",
        errorCallbackURL="http://localhost/error", requestSignUp=True,
    )
    cb = await _callback(driver, "test2", _state_from_url(res.json()["url"]))
    assert _location(cb) == "http://localhost/dashboard"
    users = await adapter.find_many(model="user", where=())
    assert len(users) == 1


# ----- numeric IDs -----


async def test_numeric_account_id_dedup(patched_httpx, idp: MockIdP) -> None:
    numeric = 123456789
    adapter = memory_adapter()
    auth, driver = _make_auth(adapter, _discovery_cfg("numeric-test"))
    idp.create_user(sub=numeric, email="numeric-id@test.com", name="Numeric")
    res = await _signin(
        driver, "numeric-test", callbackURL="http://localhost/dashboard",
        newUserCallbackURL="http://localhost/new_user",
    )
    cb = await _callback(driver, "numeric-test", _state_from_url(res.json()["url"]))
    assert _location(cb) == "http://localhost/new_user"
    accounts = await adapter.find_many(
        model="account", where=(Where(field="providerId", value="numeric-test"),)
    )
    assert len(accounts) == 1
    assert accounts[0]["accountId"] == str(numeric)

    # Second sign-in with the same numeric id must not duplicate the account.
    idp.create_user(sub=numeric, email="numeric-id@test.com", name="Numeric")
    res2 = await _signin(driver, "numeric-test", callbackURL="http://localhost/dashboard")
    cb2 = await _callback(driver, "numeric-test", _state_from_url(res2.json()["url"]))
    assert _location(cb2) == "http://localhost/dashboard"
    accounts2 = await adapter.find_many(
        model="account", where=(Where(field="providerId", value="numeric-test"),)
    )
    assert len(accounts2) == 1


async def test_custom_get_user_info_numeric_id(patched_httpx, idp: MockIdP) -> None:
    numeric = 987654321

    async def _get_user_info(_tokens):
        return {
            "id": numeric,
            "email": "custom-numeric@test.com",
            "name": "Custom Numeric User",
            "emailVerified": True,
            "image": "https://test.com/avatar.png",
        }

    adapter = memory_adapter()
    cfg = GenericOAuthConfig(
        provider_id="custom-numeric",
        client_id="cid",
        client_secret="csec",
        authorization_url="https://idp.test/authorize",
        token_url="https://idp.test/token",
        pkce=True,
        get_user_info=_get_user_info,
    )
    auth, driver = _make_auth(adapter, cfg)
    idp.create_user(sub="ignored", email="ignored@test.com", name="ignored")
    res = await _signin(
        driver, "custom-numeric", callbackURL="http://localhost/dashboard",
        newUserCallbackURL="http://localhost/new_user",
    )
    cb = await _callback(driver, "custom-numeric", _state_from_url(res.json()["url"]))
    assert _location(cb) == "http://localhost/new_user"
    accounts = await adapter.find_many(
        model="account", where=(Where(field="providerId", value="custom-numeric"),)
    )
    assert accounts[0]["accountId"] == str(numeric)


async def test_map_profile_to_user_numeric_id(patched_httpx, idp: MockIdP) -> None:
    numeric = 111222333

    def _map(profile):
        return {
            "id": profile["user_id"],
            "email": profile["email"],
            "name": profile["name"],
            "emailVerified": profile.get("email_verified"),
        }

    adapter = memory_adapter()
    auth, driver = _make_auth(
        adapter, _discovery_cfg("map-profile-numeric", map_profile_to_user=_map)
    )
    idp.create_user(
        sub="string-sub-id",
        email="map-profile-numeric@test.com",
        name="Map Profile Numeric User",
        user_id=numeric,
    )
    res = await _signin(
        driver, "map-profile-numeric", callbackURL="http://localhost/dashboard",
        newUserCallbackURL="http://localhost/new_user",
    )
    cb = await _callback(driver, "map-profile-numeric", _state_from_url(res.json()["url"]))
    assert _location(cb) == "http://localhost/new_user"
    accounts = await adapter.find_many(
        model="account", where=(Where(field="providerId", value="map-profile-numeric"),)
    )
    assert accounts[0]["accountId"] == str(numeric)


async def test_await_async_map_profile_to_user(patched_httpx, idp: MockIdP) -> None:
    """Upstream: 'should await async mapProfileToUser'.

    An async mapProfileToUser is awaited (not stored as a coroutine), so its
    returned fields land on the created user.
    """

    async def _map(profile):
        return {
            "id": profile["user_id"],
            "email": profile["email"],
            "name": "Async Mapped Name",
            "emailVerified": profile.get("email_verified"),
        }

    adapter = memory_adapter()
    auth, driver = _make_auth(
        adapter, _discovery_cfg("map-profile-async", map_profile_to_user=_map)
    )
    idp.create_user(
        sub="async-sub-id",
        email="map-profile-async@test.com",
        name="Original Name",
        user_id=777,
    )
    res = await _signin(
        driver, "map-profile-async", callbackURL="http://localhost/dashboard",
        newUserCallbackURL="http://localhost/new_user",
    )
    cb = await _callback(driver, "map-profile-async", _state_from_url(res.json()["url"]))
    assert _location(cb) == "http://localhost/new_user"
    users = await adapter.find_many(
        model="user", where=(Where(field="email", value="map-profile-async@test.com"),)
    )
    assert users and users[0]["name"] == "Async Mapped Name"


async def test_strava_map_profile_to_user(patched_httpx, idp: MockIdP) -> None:
    strava_id = 12345678

    def _map(profile):
        full = f"{profile['firstname']} {profile['lastname']}"
        return {
            "id": profile["id"],
            "email": f"{profile['id']}@strava.local",
            "name": full,
            "image": profile["profile"],
            "emailVerified": True,
        }

    async def _get_user_info(_tokens):
        return {
            "id": strava_id,
            "firstname": "John",
            "lastname": "Doe",
            "profile": "https://example.com/strava-avatar.jpg",
            "email_verified": True,
        }

    adapter = memory_adapter()
    cfg = GenericOAuthConfig(
        provider_id="strava",
        client_id="STRAVA_CLIENT_ID",
        client_secret="STRAVA_CLIENT_SECRET",
        authorization_url="https://idp.test/authorize",
        token_url="https://idp.test/token",
        user_info_url="https://idp.test/userinfo",
        scopes=("read", "activity:read_all"),
        pkce=True,
        map_profile_to_user=_map,
        get_user_info=_get_user_info,
    )
    auth, driver = _make_auth(adapter, cfg)
    idp.create_user(sub="ignored")
    res = await _signin(
        driver, "strava", callbackURL="http://localhost/dashboard",
        newUserCallbackURL="http://localhost/new_user",
    )
    url = res.json()["url"]
    assert "https://idp.test/authorize" in url
    assert "scope=read+activity" in url
    cb = await _callback(driver, "strava", _state_from_url(url))
    assert _location(cb) == "http://localhost/new_user"
    users = await adapter.find_many(model="user", where=())
    user = users[0]
    assert user["email"] == f"{strava_id}@strava.local"
    assert user["name"] == "John Doe"
    assert user["image"] == "https://example.com/strava-avatar.jpg"


async def test_email_is_missing_redirect(patched_httpx, idp: MockIdP) -> None:
    """Both provider userinfo and mapProfileToUser omit email → email_is_missing."""
    adapter = memory_adapter()
    auth, driver = _make_auth(adapter, _discovery_cfg("no-email-unresolved"))
    # No email enqueued → id_token has no email claim, userinfo has none either.
    idp.create_user(sub="no-email-no-synthesis", name="No Email User")
    res = await _signin(driver, "no-email-unresolved", callbackURL="http://localhost/dashboard")
    cb = await _callback(driver, "no-email-unresolved", _state_from_url(res.json()["url"]))
    assert "error=email_is_missing" in _location(cb)


# ----- CSRF / state handling -----


async def test_state_mismatch_rejected(patched_httpx, idp: MockIdP) -> None:
    adapter = memory_adapter()
    auth, driver = _make_auth(adapter, _discovery_cfg("test-cookie-csrf", pkce=False))
    await _signin(driver, "test-cookie-csrf", callbackURL="http://localhost/dashboard")
    cb = await driver.request(
        "GET",
        "/oauth2/callback/test-cookie-csrf",
        query="code=dummy&state=attacker-controlled-state",
    )
    assert cb.status == 302
    assert "state_mismatch" in _location(cb)
    users = await adapter.find_many(model="user", where=())
    assert users == []


async def test_callback_without_state(patched_httpx, idp: MockIdP) -> None:
    adapter = memory_adapter()
    auth, driver = _make_auth(adapter, _discovery_cfg())
    cb = await driver.request(
        "GET", "/oauth2/callback/test", query="code=dummy"
    )
    assert cb.status == 302
    assert "please_restart_the_process" in _location(cb)


# ----- custom getToken -----


async def test_custom_get_token(patched_httpx, idp: MockIdP) -> None:
    captured = {}

    async def _get_token(code, redirect_uri, code_verifier):
        captured["called"] = True
        captured["code"] = code
        return {
            "access_token": "custom-access-token",
            "refresh_token": "custom-refresh-token",
            "expires_in": 3600,
            "scope": "snsapi_login",
            "raw": {"openid": "custom-openid-123", "unionid": "custom-unionid-456"},
        }

    async def _get_user_info(tokens):
        raw = tokens.get("raw") or {}
        assert raw.get("openid") == "custom-openid-123"
        return {
            "id": raw.get("unionid") or raw.get("openid"),
            "name": "Custom Provider User",
            "email": "custom@test.com",
            "emailVerified": True,
        }

    adapter = memory_adapter()
    auth, driver = _make_auth(
        adapter,
        _discovery_cfg(
            "custom-provider", scopes=("snsapi_login",),
            get_token=_get_token, get_user_info=_get_user_info,
        ),
    )
    res = await _signin(
        driver, "custom-provider", callbackURL="http://localhost/dashboard",
        newUserCallbackURL="http://localhost/new_user",
    )
    cb = await _callback(driver, "custom-provider", _state_from_url(res.json()["url"]))
    assert captured.get("called") is True
    assert captured.get("code")
    assert _location(cb) == "http://localhost/new_user"


async def test_custom_get_token_error(patched_httpx, idp: MockIdP) -> None:
    async def _get_token(code, redirect_uri, code_verifier):
        raise RuntimeError("Token exchange failed")

    adapter = memory_adapter()
    auth, driver = _make_auth(
        adapter, _discovery_cfg("error-provider", get_token=_get_token)
    )
    res = await _signin(
        driver, "error-provider", callbackURL="http://localhost/dashboard",
        errorCallbackURL="http://localhost/error",
    )
    cb = await _callback(driver, "error-provider", _state_from_url(res.json()["url"]))
    loc = _location(cb)
    assert "http://localhost/error" in loc
    assert "error=" in loc


async def test_get_based_token_endpoint(patched_httpx, idp: MockIdP) -> None:
    mock = {
        "access_token": "custom-access-token-xyz",
        "refresh_token": "custom-refresh-token-xyz",
        "expires_in": 7200,
        "user_id": "user_12345",
        "custom_field": "custom_value",
        "scope": "profile email",
    }

    async def _get_token(code, redirect_uri, code_verifier):
        return {
            "access_token": mock["access_token"],
            "refresh_token": mock["refresh_token"],
            "expires_in": mock["expires_in"],
            "scope": mock["scope"],
            "raw": mock,
        }

    async def _get_user_info(tokens):
        raw = tokens.get("raw") or {}
        assert raw.get("user_id") == mock["user_id"]
        return {
            "id": raw["user_id"],
            "name": "Test User",
            "email": f"{raw['user_id']}@example.com",
            "image": "https://example.com/avatar.png",
            "emailVerified": True,
        }

    adapter = memory_adapter()
    auth, driver = _make_auth(
        adapter,
        _discovery_cfg(
            "custom-get-provider", scopes=("profile", "email"),
            get_token=_get_token, get_user_info=_get_user_info,
        ),
    )
    res = await _signin(
        driver, "custom-get-provider", callbackURL="http://localhost/dashboard",
        newUserCallbackURL="http://localhost/welcome",
    )
    assert "scope=profile" in res.json()["url"]
    cb = await _callback(driver, "custom-get-provider", _state_from_url(res.json()["url"]))
    assert _location(cb) == "http://localhost/welcome"
    users = await adapter.find_many(model="user", where=())
    assert users[0]["name"] == "Test User"
    assert users[0]["image"] == "https://example.com/avatar.png"


# ----- duplicate provider id detection -----


def test_duplicate_provider_ids_rejected() -> None:
    cfg1 = GenericOAuthConfig(
        provider_id="duplicate-id", client_id="c1", client_secret="s1",
        discovery_url="https://idp.test/.well-known/openid-configuration",
    )
    cfg2 = GenericOAuthConfig(
        provider_id="duplicate-id", client_id="c2", client_secret="s2",
        discovery_url="https://idp.test/.well-known/openid-configuration",
    )
    with pytest.raises(ValueError, match="duplicate"):
        generic_oauth([cfg1, cfg2])


def test_unique_provider_ids_ok() -> None:
    cfg1 = GenericOAuthConfig(
        provider_id="unique-1", client_id="c1", client_secret="s1",
        discovery_url="https://idp.test/.well-known/openid-configuration",
    )
    cfg2 = GenericOAuthConfig(
        provider_id="unique-2", client_id="c2", client_secret="s2",
        discovery_url="https://idp.test/.well-known/openid-configuration",
    )
    plugin = generic_oauth([cfg1, cfg2])
    assert plugin.endpoints


# ----- RFC 9207 issuer validation -----


async def test_iss_matches_configured_issuer(patched_httpx, idp: MockIdP) -> None:
    adapter = memory_adapter()
    auth, driver = _make_auth(
        adapter, _discovery_cfg("iss-test", issuer="https://idp.test")
    )
    idp.create_user(sub="iss-match", email="iss-match@test.com", name="Issuer Match")
    res = await _signin(
        driver, "iss-test", callbackURL="http://localhost/dashboard",
        newUserCallbackURL="http://localhost/new_user",
    )
    cb = await _callback(
        driver, "iss-test", _state_from_url(res.json()["url"]),
        extra="iss=https%3A%2F%2Fidp.test",
    )
    assert _location(cb) == "http://localhost/new_user"
    assert "error=" not in _location(cb)


async def test_iss_mismatch_rejected(patched_httpx, idp: MockIdP) -> None:
    adapter = memory_adapter()
    auth, driver = _make_auth(
        adapter, _discovery_cfg("iss-mismatch", issuer="https://idp.test")
    )
    idp.create_user(sub="iss-x", email="iss-x@test.com", name="X")
    res = await _signin(
        driver, "iss-mismatch", callbackURL="http://localhost/dashboard",
        errorCallbackURL="http://localhost/error",
    )
    cb = await _callback(
        driver, "iss-mismatch", _state_from_url(res.json()["url"]),
        extra="iss=https%3A%2F%2Fevil-server.com",
    )
    loc = _location(cb)
    assert "http://localhost/error" in loc
    assert "error=issuer_mismatch" in loc


async def test_iss_from_discovery_document(patched_httpx, idp: MockIdP) -> None:
    """No issuer configured → fall back to discovery `issuer` for validation."""
    adapter = memory_adapter()
    auth, driver = _make_auth(adapter, _discovery_cfg("iss-discovery"))
    idp.create_user(sub="iss-disc", email="iss-disc@test.com", name="Disc")
    res = await _signin(
        driver, "iss-discovery", callbackURL="http://localhost/dashboard",
        newUserCallbackURL="http://localhost/new_user",
    )
    cb = await _callback(
        driver, "iss-discovery", _state_from_url(res.json()["url"]),
        extra="iss=https%3A%2F%2Fidp.test",
    )
    assert _location(cb) == "http://localhost/new_user"


async def test_no_iss_validation_when_unconfigured(patched_httpx, idp: MockIdP) -> None:
    """Explicit endpoints, no discovery/issuer → iss is never validated."""
    adapter = memory_adapter()
    cfg = GenericOAuthConfig(
        provider_id="no-iss-test",
        client_id="cid",
        client_secret="csec",
        authorization_url="https://idp.test/authorize",
        token_url="https://idp.test/token",
        user_info_url="https://idp.test/userinfo",
        pkce=True,
    )
    auth, driver = _make_auth(adapter, cfg)
    idp.create_user(sub="no-iss", email="no-iss@test.com", name="No Iss")
    res = await _signin(
        driver, "no-iss-test", callbackURL="http://localhost/dashboard",
        newUserCallbackURL="http://localhost/new_user",
    )
    cb = await _callback(driver, "no-iss-test", _state_from_url(res.json()["url"]))
    assert _location(cb) == "http://localhost/new_user"


async def test_require_issuer_validation_missing_iss(patched_httpx, idp: MockIdP) -> None:
    adapter = memory_adapter()
    auth, driver = _make_auth(
        adapter,
        _discovery_cfg(
            "strict-iss", issuer="https://idp.test", require_issuer_validation=True
        ),
    )
    idp.create_user(sub="strict", email="strict@test.com", name="Strict")
    res = await _signin(
        driver, "strict-iss", callbackURL="http://localhost/dashboard",
        errorCallbackURL="http://localhost/error",
    )
    cb = await _callback(driver, "strict-iss", _state_from_url(res.json()["url"]))
    loc = _location(cb)
    assert "http://localhost/error" in loc
    assert "error=issuer_missing" in loc


async def test_lenient_issuer_validation_allows_missing_iss(patched_httpx, idp: MockIdP) -> None:
    adapter = memory_adapter()
    auth, driver = _make_auth(
        adapter,
        _discovery_cfg(
            "lenient-iss", issuer="https://idp.test", require_issuer_validation=False
        ),
    )
    idp.create_user(sub="lenient", email="lenient@test.com", name="Lenient")
    res = await _signin(
        driver, "lenient-iss", callbackURL="http://localhost/dashboard",
        newUserCallbackURL="http://localhost/new_user",
    )
    cb = await _callback(driver, "lenient-iss", _state_from_url(res.json()["url"]))
    assert _location(cb) == "http://localhost/new_user"


# ----- provider helper config (pure construction) -----


def test_okta_helper_config() -> None:
    from kernia.plugins.generic_oauth import okta

    cfg = okta(
        client_id="okta-client-id", client_secret="okta-client-secret",
        issuer="https://dev-12345.okta.com/oauth2/default",
    )
    assert cfg.provider_id == "okta"
    assert cfg.discovery_url == (
        "https://dev-12345.okta.com/oauth2/default/.well-known/openid-configuration"
    )
    assert cfg.scopes == ("openid", "profile", "email")
    assert cfg.get_user_info is None


def test_okta_helper_trailing_slash() -> None:
    from kernia.plugins.generic_oauth import okta

    cfg = okta(
        client_id="x", client_secret="y",
        issuer="https://dev-12345.okta.com/oauth2/default/",
    )
    assert cfg.discovery_url == (
        "https://dev-12345.okta.com/oauth2/default/.well-known/openid-configuration"
    )


def test_auth0_helper_config() -> None:
    from kernia.plugins.generic_oauth import auth0

    cfg = auth0(
        client_id="auth0-client-id", client_secret="auth0-client-secret",
        domain="dev-xxx.eu.auth0.com",
    )
    assert cfg.provider_id == "auth0"
    assert cfg.discovery_url == "https://dev-xxx.eu.auth0.com/.well-known/openid-configuration"
    assert cfg.scopes == ("openid", "profile", "email")
    assert cfg.get_user_info is None


def test_auth0_helper_protocol_prefix() -> None:
    from kernia.plugins.generic_oauth import auth0

    cfg = auth0(
        client_id="x", client_secret="y", domain="https://dev-xxx.eu.auth0.com",
    )
    assert cfg.discovery_url == "https://dev-xxx.eu.auth0.com/.well-known/openid-configuration"


def test_microsoft_entra_id_helper_config() -> None:
    from kernia.plugins.generic_oauth import microsoft_entra_id

    cfg = microsoft_entra_id(
        client_id="ms-client-id", client_secret="ms-client-secret", tenant_id="common",
    )
    assert cfg.provider_id == "microsoft-entra-id"
    assert cfg.authorization_url == (
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    )
    assert cfg.token_url == (
        "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    )
    assert cfg.user_info_url == "https://graph.microsoft.com/oidc/userinfo"
    assert cfg.scopes == ("openid", "profile", "email")
    assert cfg.get_user_info is not None


def test_microsoft_entra_id_helper_guid_tenant() -> None:
    from kernia.plugins.generic_oauth import microsoft_entra_id

    tenant = "12345678-1234-1234-1234-123456789012"
    cfg = microsoft_entra_id(
        client_id="x", client_secret="y", tenant_id=tenant,
    )
    assert cfg.authorization_url == (
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
    )


def test_slack_helper_config() -> None:
    from kernia.plugins.generic_oauth import slack_generic

    cfg = slack_generic(client_id="slack-client-id", client_secret="slack-client-secret")
    assert cfg.provider_id == "slack"
    assert cfg.authorization_url == "https://slack.com/openid/connect/authorize"
    assert cfg.token_url == "https://slack.com/api/openid.connect.token"
    assert cfg.user_info_url == "https://slack.com/api/openid.connect.userInfo"
    assert cfg.scopes == ("openid", "profile", "email")
    assert cfg.get_user_info is not None


def test_keycloak_helper_config() -> None:
    from kernia.plugins.generic_oauth import keycloak

    cfg = keycloak(
        client_id="keycloak-client-id", client_secret="keycloak-client-secret",
        issuer="https://my-domain.com/realms/MyRealm",
    )
    assert cfg.provider_id == "keycloak"
    assert cfg.discovery_url == (
        "https://my-domain.com/realms/MyRealm/.well-known/openid-configuration"
    )
    assert cfg.scopes == ("openid", "profile", "email")
    assert cfg.get_user_info is None


def test_keycloak_helper_trailing_slash() -> None:
    from kernia.plugins.generic_oauth import keycloak

    cfg = keycloak(
        client_id="x", client_secret="y",
        issuer="https://my-domain.com/realms/MyRealm/",
    )
    assert cfg.discovery_url == (
        "https://my-domain.com/realms/MyRealm/.well-known/openid-configuration"
    )


def test_helper_overrides_scopes_and_options() -> None:
    from kernia.plugins.generic_oauth import keycloak, okta

    o = okta(
        client_id="x", client_secret="y",
        issuer="https://dev-12345.okta.com/oauth2/default",
        scopes=("openid", "profile"), pkce=True, disable_implicit_sign_up=True,
    )
    assert o.scopes == ("openid", "profile")
    assert o.pkce is True
    assert o.disable_implicit_sign_up is True

    k = keycloak(
        client_id="x", client_secret="y",
        issuer="https://my-domain.com/realms/MyRealm",
        scopes=("openid", "profile"),
    )
    assert k.scopes == ("openid", "profile")


def test_helpers_integrate_with_generic_oauth() -> None:
    from kernia.plugins.generic_oauth import (
        auth0,
        keycloak,
        microsoft_entra_id,
        okta,
        slack_generic,
    )

    for cfg in (
        okta(client_id="x", client_secret="y", issuer="https://d.okta.com/oauth2/default"),
        auth0(client_id="x", client_secret="y", domain="dev.eu.auth0.com"),
        microsoft_entra_id(client_id="x", client_secret="y", tenant_id="common"),
        slack_generic(client_id="x", client_secret="y"),
        keycloak(client_id="x", client_secret="y", issuer="https://d.com/realms/R"),
    ):
        adapter = memory_adapter()
        auth, _driver = _make_auth(adapter, cfg)
        assert auth is not None
