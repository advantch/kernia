"""Tests for `kernia generate`."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner
from kernia_cli.commands.generate import generate


def test_generate_emits_migration(tmp_path: Path, fixture_config_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        generate,
        ["--cwd", str(tmp_path), "--config", str(fixture_config_path)],
    )
    assert result.exit_code == 0, result.output

    versions = tmp_path / "alembic" / "versions"
    files = list(versions.glob("*_kernia_schema.py"))
    assert len(files) == 1
    body = files[0].read_text()

    # Core tables.
    assert "op.create_table('user'" in body
    assert "op.create_table('session'" in body
    assert "op.create_table('account'" in body
    assert "op.create_table('verification'" in body
    # Plugin-contributed table.
    assert "op.create_table('notes'" in body

    # Drop in reverse for downgrade.
    assert "op.drop_table('notes')" in body
    assert "def upgrade()" in body
    assert "def downgrade()" in body


def test_generate_is_idempotent(tmp_path: Path, fixture_config_path: Path) -> None:
    runner = CliRunner()
    first = runner.invoke(
        generate,
        ["--cwd", str(tmp_path), "--config", str(fixture_config_path)],
    )
    assert first.exit_code == 0

    second = runner.invoke(
        generate,
        ["--cwd", str(tmp_path), "--config", str(fixture_config_path)],
    )
    assert second.exit_code == 0
    assert "already up to date" in second.output


def test_generate_custom_output(tmp_path: Path, fixture_config_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "migrations" / "schema.py"
    result = runner.invoke(
        generate,
        [
            "--cwd",
            str(tmp_path),
            "--config",
            str(fixture_config_path),
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
