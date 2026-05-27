"""End-to-end: a custom-session provider replaces the default session storage."""

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
