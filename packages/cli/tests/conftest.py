"""Shared fixtures for CLI tests."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURE_CONFIG = '''"""Fixture better-auth config for CLI tests."""

from better_auth import BetterAuthOptions, BetterAuthPlugin, PluginSchema
from better_auth.auth import init
from better_auth_memory_adapter import memory_adapter
from better_auth.plugins.email_password.plugin import email_and_password
from better_auth.types.adapter import FieldDef, ModelDef


def _stub_plugin() -> BetterAuthPlugin:
    """A trivial plugin that adds a new `notes` table to exercise schema codegen."""
    from dataclasses import dataclass

    @dataclass(frozen=True, slots=True)
    class _Stub:
        id: str = "stub"
        version: str | None = "0.0.1"
        schema = PluginSchema(
            tables=(
                ModelDef(
                    name="notes",
                    fields=(
                        FieldDef("id", "string", unique=True),
                        FieldDef("userId", "string", references=("user", "id")),
                        FieldDef("body", "text"),
                        FieldDef("createdAt", "date"),
                    ),
                ),
            ),
        )
        endpoints = None
        middlewares = None
        hooks = None
        on_request = None
        on_response = None
        rate_limit = None
        error_codes = None
        init = None

    return _Stub()


auth = init(
    BetterAuthOptions(
        database=memory_adapter(),
        secret="test-secret-for-cli-fixture",
        base_url="http://localhost:3000",
        plugins=[email_and_password(), _stub_plugin()],
    )
)
'''


@pytest.fixture
def fixture_config_path(tmp_path: Path) -> Path:
    """Write the canonical fixture config to a temp dir and return its path."""
    path = tmp_path / "auth.py"
    path.write_text(FIXTURE_CONFIG)
    return path
