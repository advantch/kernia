"""Unit tests for the custom-session plugin's session-provider installation."""

from __future__ import annotations

import pytest
from better_auth.auth import init
from better_auth.plugins import with_custom_session
from better_auth.types.init_options import BetterAuthOptions
from better_auth_memory_adapter import memory_adapter


class _NoopProvider:
    async def create_session(self, **kwargs):  # type: ignore[no-untyped-def]
        return {
            "id": "fixed-id",
            "userId": kwargs["user_id"],
            "token": kwargs["token"],
            "expiresAt": kwargs["expires_at"],
        }

    async def get_session(self, *, token: str):  # type: ignore[no-untyped-def]
        return None

    async def delete_session(self, *, token: str) -> None:
        return None


@pytest.mark.asyncio
async def test_plugin_installs_provider_in_plugin_state() -> None:
    provider = _NoopProvider()
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="s",
            plugins=[with_custom_session(provider)],
        )
    )
    # init runs the async hook on first ASGI request OR via asyncio.run; either way
    # we directly drive it here.
    plugin = auth.context.plugins[0]
    await plugin.init(auth.context)
    assert auth.context.plugin_state["session_provider"] is provider
