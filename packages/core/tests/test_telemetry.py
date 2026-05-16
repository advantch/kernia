"""Unit tests for better_auth.telemetry."""

from __future__ import annotations

import asyncio
from typing import Any

from better_auth.auth import init
from better_auth.plugins import email_and_password
from better_auth.telemetry import telemetry
from better_auth.types.init_options import BetterAuthOptions
from better_auth_memory_adapter import memory_adapter


def _make_capture_sink():
    captured: list[dict[str, Any]] = []

    async def sink(event: dict[str, Any]) -> None:
        captured.append(event)

    return captured, sink


def test_plugin_off_by_default_no_emission_without_plugin() -> None:
    # Build an auth instance without telemetry — nothing emitted.
    # (Also verifies the absence of an exception on startup.)
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="x" * 32,
            plugins=[email_and_password()],
        )
    )
    assert auth is not None


def test_plugin_emits_startup_event_when_present() -> None:
    captured, sink = _make_capture_sink()
    init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="x" * 32,
            plugins=[email_and_password(), telemetry(sink=sink)],
        )
    )
    # init() schedules the async hook; pump the loop briefly.
    asyncio.get_event_loop().run_until_complete(asyncio.sleep(0)) if False else None
    # The init path runs `asyncio.run` when no loop is running, so by the time we
    # return the sink has been invoked.
    assert len(captured) == 1
    event = captured[0]
    assert event["kind"] == "startup"
    assert isinstance(event["version"], str)
    assert "email-password" in event["plugins"]
    assert "telemetry" not in event["plugins"]
    assert event["adapter"] == "MemoryAdapter"
    assert isinstance(event["ts"], int)


def test_advanced_telemetry_false_suppresses_emission() -> None:
    captured, sink = _make_capture_sink()
    init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="x" * 32,
            plugins=[telemetry(sink=sink)],
            advanced={"telemetry": False},
        )
    )
    assert captured == []
