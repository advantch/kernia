"""End-to-end test of generate + migrate against a temp SQLite DB."""

from __future__ import annotations

from pathlib import Path

import sqlalchemy as sa
from click.testing import CliRunner

from kernia_cli.commands.generate import generate
from kernia_cli.commands.migrate import migrate


def test_generate_then_migrate_creates_tables(
    tmp_path: Path, fixture_config_path: Path
) -> None:
    runner = CliRunner()

    db_file = tmp_path / "app.db"
    db_url = f"sqlite:///{db_file}"

    gen = runner.invoke(
        generate,
        ["--cwd", str(tmp_path), "--config", str(fixture_config_path)],
    )
    assert gen.exit_code == 0, gen.output

    mig = runner.invoke(
        migrate,
        [
            "--cwd",
            str(tmp_path),
            "--config",
            str(fixture_config_path),
            "--db-url",
            db_url,
        ],
    )
    assert mig.exit_code == 0, mig.output

    engine = sa.create_engine(db_url)
    insp = sa.inspect(engine)
    tables = set(insp.get_table_names())
    # alembic_version is created by alembic itself.
    assert "user" in tables
    assert "session" in tables
    assert "account" in tables
    assert "verification" in tables
    assert "notes" in tables
