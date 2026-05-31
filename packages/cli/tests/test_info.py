"""Tests for `kernia info`."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from kernia_cli.commands.info import info


def test_info_dry_run_works_without_config() -> None:
    runner = CliRunner()
    result = runner.invoke(info, ["--dry-run", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "kernia_python_version" in data
    assert "python_version" in data


def test_info_against_fixture_lists_plugins(
    tmp_path: Path, fixture_config_path: Path
) -> None:
    runner = CliRunner()
    result = runner.invoke(
        info,
        [
            "--cwd",
            str(tmp_path),
            "--config",
            str(fixture_config_path),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    plugin_ids = {p["id"] for p in data["plugins"]}
    assert "email-password" in plugin_ids or "email_password" in plugin_ids or "stub" in plugin_ids
    assert "stub" in plugin_ids
    assert data["route_count"] > 0
    assert data["adapter"] == "MemoryAdapter"


def test_info_text_output_mentions_plugins(
    tmp_path: Path, fixture_config_path: Path
) -> None:
    runner = CliRunner()
    result = runner.invoke(
        info,
        ["--cwd", str(tmp_path), "--config", str(fixture_config_path)],
    )
    assert result.exit_code == 0, result.output
    assert "kernia" in result.output
    assert "stub" in result.output
