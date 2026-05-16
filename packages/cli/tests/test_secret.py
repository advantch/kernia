"""Tests for `better-auth secret`."""

from __future__ import annotations

from click.testing import CliRunner

from better_auth_cli.commands.secret import secret


def test_secret_prints_env_hint() -> None:
    runner = CliRunner()
    result = runner.invoke(secret, [])
    assert result.exit_code == 0
    assert "BETTER_AUTH_SECRET=" in result.output


def test_secret_raw_is_urlsafe_b64_length() -> None:
    runner = CliRunner()
    result = runner.invoke(secret, ["--raw"])
    assert result.exit_code == 0
    value = result.output.strip()
    # 32 bytes urlsafe-b64 → ~43 chars
    assert len(value) >= 32
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
    assert set(value).issubset(allowed)


def test_secret_two_calls_differ() -> None:
    runner = CliRunner()
    a = runner.invoke(secret, ["--raw"]).output.strip()
    b = runner.invoke(secret, ["--raw"]).output.strip()
    assert a != b
