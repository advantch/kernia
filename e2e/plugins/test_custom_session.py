"""End-to-end: a custom-session provider replaces the default session storage.

Also covers the upstream ``customSession`` *response transformer* (ported from
reference/packages/better-auth/src/plugins/custom-session/custom-session.test.ts):
``custom_session(fn)`` rewrites the ``/get-session`` payload, and with
``should_mutate_list_device_sessions`` the same transform applies to the
multi-session list. The TS-only ``expectTypeOf``/``$Infer`` cases and the Node
``gc`` memory-leak case have no Python runtime equivalent and are not ported.
The upstream cookie-cache (``session_data``) Set-Cookie cases depend on a core
get-session cookie-cache-refresh that the Python port does not yet emit on
``/get-session``; those remain a tracked core gap.
"""

from __future__ import annotations

from typing import Any

import pytest
from better_auth.auth import init
from better_auth.plugins import (
    custom_session,
    email_and_password,
    multi_session,
    with_custom_session,
)
from better_auth.types.init_options import BetterAuthOptions
from better_auth_memory_adapter import memory_adapter
from better_auth_test_utils import ASGIDriver
from better_auth_test_utils.adapter_fixtures import all_adapters_param


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
        BetterAuthOptions(
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
