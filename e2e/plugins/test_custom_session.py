"""End-to-end: a custom-session provider replaces the default session storage.

Also covers the upstream ``customSession`` *response transformer* (ported from
reference/packages/better-auth/src/plugins/custom-session/custom-session.test.ts):
``custom_session(fn)`` rewrites the ``/get-session`` payload, and with
``should_mutate_list_device_sessions`` the same transform applies to the
multi-session list. The TS-only ``expectTypeOf``/``$Infer`` cases and the Node
``gc`` memory-leak case have no Python runtime equivalent and are not ported.
The upstream cookie-cache (``session_data``) Set-Cookie cases are now covered:
the core get-session handler re-issues the ``session_token`` and short-lived
``session_data`` cookies (each a separate Set-Cookie entry, distinct Max-Age)
when ``session.cookieCache`` is enabled and the session is due for refresh. The
``partitioned``-attribute case is now covered too: ``advanced.defaultCookieAttributes``
is merged over the base cookie attributes (before per-cookie ``maxAge`` overrides),
so refreshed cookies preserve ``Partitioned`` / ``SameSite=None`` etc.
"""

from __future__ import annotations

from typing import Any

import pytest

from kernia.auth import init
from kernia.plugins import email_and_password, with_custom_session
from kernia.types.init_options import KerniaOptions
from kernia_test_utils import ASGIDriver
from kernia_test_utils.adapter_fixtures import all_adapters_param


class DictSessionProvider:
    """Test-only in-memory session backend keyed by token."""

    def __init__(self) -> None:
        self.store: dict[str, dict[str, Any]] = {}
        self.create_calls = 0
        self.get_calls = 0
        self.delete_calls = 0

    async def create_session(
        self,
        *,
        user_id: str,
        token: str,
        expires_at: int,
        ip_address: str | None,
        user_agent: str | None,
    ) -> dict[str, Any]:
        self.create_calls += 1
        row = {
            "id": f"sess-{len(self.store) + 1}",
            "userId": user_id,
            "token": token,
            "expiresAt": expires_at,
            "ipAddress": ip_address,
            "userAgent": user_agent,
        }
        self.store[token] = row
        return row

    async def get_session(self, *, token: str) -> dict[str, Any] | None:
        self.get_calls += 1
        return self.store.get(token)

    async def delete_session(self, *, token: str) -> None:
        self.delete_calls += 1
        self.store.pop(token, None)


@pytest.mark.parametrize(*all_adapters_param())
async def test_custom_session_provider_is_used(adapter_factory) -> None:
    adapter = await adapter_factory()
    provider = DictSessionProvider()
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="s",
            plugins=[email_and_password(), with_custom_session(provider)],
        )
    )
    # Make sure init has run.
    for plugin in auth.context.plugins:
        if plugin.init is not None:
            await plugin.init(auth.context)

    driver = ASGIDriver(app=auth.router.mount())

    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "custom@example.com", "password": "passpass1"},
    )
    assert r.status == 200, r.json()
    # The provider was consulted — and the regular session table was bypassed.
    assert provider.create_calls == 1
    assert len(provider.store) == 1
    # The default adapter has no session row.
    from kernia.types.adapter import Where

    assert await adapter.count(model="session") == 0  # type: ignore[arg-type]

    r = await driver.request("GET", "/get-session")
    assert r.status == 200, r.json()
    assert r.json()["user"]["email"] == "custom@example.com"
    assert provider.get_calls >= 1

    r = await driver.request("POST", "/sign-out")
    assert r.status == 200
    assert provider.delete_calls == 1
    assert provider.store == {}


# ----- upstream customSession response-transform parity --------------------


async def _transform(data: dict[str, Any], _ctx: Any) -> dict[str, Any]:
    """Mirror the upstream test's transform callback."""
    user = data["user"]
    name = (user.get("name") or "").split(" ")
    return {
        "user": {
            "firstName": name[0] if name else None,
            "lastName": name[1] if len(name) > 1 else None,
        },
        "newData": {"message": "Hello, World!"},
        "session": data["session"],
    }


async def test_get_session_returns_custom_shape() -> None:
    """Upstream: 'should return the session' — newData merged into get-session."""
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="s",
            plugins=[email_and_password(), custom_session(_transform)],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())

    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={
            "email": "custom-shape@test.com",
            "password": "password1",
            "name": "Jane Doe",
        },
    )
    assert r.status == 200, r.json()

    r = await driver.request("GET", "/get-session")
    assert r.status == 200, r.json()
    body = r.json()
    assert body["newData"] == {"message": "Hello, World!"}
    assert body["user"]["firstName"] == "Jane"
    assert body["user"]["lastName"] == "Doe"
    # The transform replaced the payload — the raw user row is gone.
    assert "email" not in body["user"]


async def test_get_session_transform_returns_null_when_unauthenticated() -> None:
    """Upstream: transform is only applied to a real session; null stays null."""
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="s",
            plugins=[email_and_password(), custom_session(_transform)],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())

    r = await driver.request("GET", "/get-session")
    assert r.status == 200
    assert r.json() is None


async def test_get_session_accepts_disable_refresh_query() -> None:
    """Upstream: 'should accept disableRefresh as a query string without error'.

    @see https://github.com/better-auth/better-auth/issues/9195
    """
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="s",
            plugins=[email_and_password(), custom_session(_transform)],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())

    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={
            "email": "disable-refresh@test.com",
            "password": "password1",
            "name": "Ref Resh",
        },
    )
    assert r.status == 200, r.json()

    r = await driver.request(
        "GET", "/get-session", query="disableRefresh=true"
    )
    assert r.status == 200, r.json()
    assert r.json() is not None
    assert r.json()["newData"] == {"message": "Hello, World!"}


async def test_list_device_sessions_custom_shape() -> None:
    """Upstream: 'should return the custom session for multi-session'."""
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="s",
            plugins=[
                email_and_password(),
                multi_session(maximum=5),
                custom_session(
                    _transform, should_mutate_list_device_sessions=True
                ),
            ],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())

    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={
            "email": "device-list@test.com",
            "password": "password1",
            "name": "Device User",
        },
    )
    assert r.status == 200, r.json()

    r = await driver.request("GET", "/multi-session/list")
    assert r.status == 200, r.json()
    sessions = r.json()["sessions"]
    assert len(sessions) == 1
    assert sessions[0]["newData"] == {"message": "Hello, World!"}
    assert sessions[0]["user"]["firstName"] == "Device"
    assert sessions[0]["user"]["lastName"] == "User"


# ----- cookie-cache Set-Cookie behaviour on get-session refresh ------------
#
# Ported from the cookie-focused cases in custom-session.test.ts. These exercise
# the core get-session cookie-cache refresh: with `session.cookieCache` enabled
# and `updateAge=0`, get-session re-issues both the long-lived `session_token`
# and the short-lived `session_data` cookies as *separate* Set-Cookie entries,
# each with its own Max-Age.


def _set_cookie_headers(response) -> list[str]:
    return [v for k, v in response.headers if k.lower() == "set-cookie"]


def _max_age(cookie_str: str) -> int | None:
    import re

    m = re.search(r"Max-Age=(\d+)", cookie_str, re.IGNORECASE)
    return int(m.group(1)) if m else None


async def _cookie_cache_driver(
    *, expires_in: int = 86400, cache_max_age: int = 300
) -> ASGIDriver:
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="test-secret-key-cookie-cache!!",
            session=SessionOptions(
                expires_in=expires_in,
                update_age=0,
                cookie_cache_enabled=True,
                cookie_cache_max_age=cache_max_age,
            ),
            plugins=[email_and_password(), custom_session(_transform)],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={
            "email": "cookie-cache@test.com",
            "password": "password1",
            "name": "Cookie Cache",
        },
    )
    assert r.status == 200, r.json()
    return driver


async def test_get_session_emits_separate_set_cookie_entries() -> None:
    """Upstream: 'should return set cookie headers as separate entries'."""
    driver = await _cookie_cache_driver()
    r = await driver.request("GET", "/get-session")
    assert r.status == 200, r.json()
    set_cookies = _set_cookie_headers(r)
    assert len(set_cookies) >= 2
    joined = "; ".join(set_cookies)
    assert "better-auth.session_token" in joined
    assert "better-auth.session_data" in joined


async def test_get_session_does_not_double_encode_session_token() -> None:
    """Upstream: 'should not double-encode session cookie during refresh'."""
    driver = await _cookie_cache_driver()
    original = driver.cookies["better-auth.session_token"]

    r = await driver.request("GET", "/get-session")
    refreshed = None
    for cookie_str in _set_cookie_headers(r):
        name, _, rest = cookie_str.partition("=")
        if name.strip() == "better-auth.session_token":
            refreshed = rest.partition(";")[0]
            break
    assert refreshed is not None
    assert refreshed == original
    assert "%25" not in refreshed


async def test_get_session_preserves_individual_cookie_max_age() -> None:
    """Upstream: 'should preserve individual cookie Max-Age when cookieCache on'."""
    expires_in, cache_max_age = 86400, 300
    driver = await _cookie_cache_driver(
        expires_in=expires_in, cache_max_age=cache_max_age
    )
    r = await driver.request("GET", "/get-session")
    set_cookies = _set_cookie_headers(r)
    token_cookie = next(
        c for c in set_cookies if "better-auth.session_token" in c
    )
    data_cookie = next(c for c in set_cookies if "better-auth.session_data" in c)
    token_max_age = _max_age(token_cookie)
    data_max_age = _max_age(data_cookie)
    assert token_max_age is not None
    assert data_max_age is not None
    # The token keeps the long session lifetime, not the short cache one.
    assert expires_in - 10 < token_max_age <= expires_in
    assert data_max_age == cache_max_age
    assert token_max_age != data_max_age


async def test_get_session_does_not_comma_join_set_cookies() -> None:
    """Upstream: 'should not comma-join Set-Cookie headers'."""
    driver = await _cookie_cache_driver()
    r = await driver.request("GET", "/get-session")
    for cookie_str in _set_cookie_headers(r):
        names = [seg.strip().split("=")[0].lower() for seg in cookie_str.split(";")]
        better_auth_names = [n for n in names if n.startswith("better-auth.")]
        # Exactly one better-auth.* cookie per Set-Cookie header (no comma-join).
        assert len(better_auth_names) == 1


async def test_get_session_preserves_partitioned_cookie_attributes() -> None:
    """Upstream: 'should preserve partitioned cookie attributes during refresh'.

    @see https://github.com/better-auth/better-auth/issues/9231
    """
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="test-secret-key-partitioned!!!",
            session=SessionOptions(update_age=0),
            advanced={
                "default_cookie_attributes": {
                    "partitioned": True,
                    "same_site": "none",
                    "secure": True,
                    "http_only": True,
                },
            },
            plugins=[email_and_password(), custom_session(_transform)],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={
            "email": "partitioned@test.com",
            "password": "password1",
            "name": "Part It",
        },
    )
    assert r.status == 200, r.json()

    r = await driver.request("GET", "/get-session")
    set_cookies = _set_cookie_headers(r)
    better_auth_cookies = [c for c in set_cookies if "better-auth." in c]
    assert len(better_auth_cookies) > 0
    for cookie_str in better_auth_cookies:
        assert "Partitioned" in cookie_str
        assert "SameSite=None" in cookie_str
