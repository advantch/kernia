"""Tests for `better-auth init`."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from better_auth_cli.commands.init_cmd import init


def test_init_writes_files(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(init, ["--cwd", str(tmp_path), "--adapter", "memory"])
    assert result.exit_code == 0, result.output

    auth_py = tmp_path / "auth.py"
    env_example = tmp_path / ".env.example"

    assert auth_py.exists()
    assert env_example.exists()

    body = auth_py.read_text()
    assert "from better_auth_memory_adapter import memory_adapter" in body
    assert "init(" in body
    assert "email_and_password" in body

    env_body = env_example.read_text()
    assert "BETTER_AUTH_SECRET=" in env_body
    assert "DATABASE_URL=" in env_body


def test_init_refuses_overwrite_without_force(tmp_path: Path) -> None:
    runner = CliRunner()
    first = runner.invoke(init, ["--cwd", str(tmp_path)])
    assert first.exit_code == 0

    second = runner.invoke(init, ["--cwd", str(tmp_path)])
    assert second.exit_code != 0
    assert "already exists" in second.output


def test_init_force_overwrites(tmp_path: Path) -> None:
    runner = CliRunner()
    runner.invoke(init, ["--cwd", str(tmp_path)])
    (tmp_path / "auth.py").write_text("# tampered\n")
    result = runner.invoke(init, ["--cwd", str(tmp_path), "--force"])
    assert result.exit_code == 0
    assert "from better_auth" in (tmp_path / "auth.py").read_text()


def test_init_framework_snippet_fastapi(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        init,
        ["--cwd", str(tmp_path), "--adapter", "sqlite", "--framework", "fastapi"],
    )
    assert result.exit_code == 0, result.output
    body = (tmp_path / "auth.py").read_text()
    assert "FastAPI mount" in body
    assert "sqlalchemy_adapter" in body
