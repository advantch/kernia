"""`kernia migrate` — run `alembic upgrade head` against the user's DB.

Mirrors `reference/packages/cli/src/commands/migrate.ts`. We locate the user's
`alembic.ini` (or generate a minimal one on the fly) and call Alembic's
programmatic API. The DB URL is read from the user config's
`options.database` adapter or from the `KERNIA_DATABASE_URL` env var if
present.
"""

from __future__ import annotations

import os
from pathlib import Path

import click

from kernia_cli.utils import find_auth_handle, load_config_module


def _resolve_db_url(auth, override: str | None) -> str:
    if override:
        return _alembic_url(override)
    env_url = os.environ.get("KERNIA_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if env_url:
        return _alembic_url(env_url)
    # Best-effort: try to read a `.url` attribute off the adapter's engine.
    adapter = auth.context.adapter
    engine = getattr(adapter, "engine", None)
    if engine is not None and getattr(engine, "url", None) is not None:
        return _alembic_url(str(engine.url))
    raise click.ClickException(
        "No database URL could be resolved. Pass --db-url or set KERNIA_DATABASE_URL."
    )


def _alembic_url(url: str) -> str:
    """Return a sync SQLAlchemy URL suitable for Alembic's default env."""
    if url.startswith("sqlite+aiosqlite://"):
        return "sqlite://" + url.removeprefix("sqlite+aiosqlite://")
    return url


@click.command("migrate", help="Run Alembic upgrade to head.")
@click.option(
    "--config",
    "config_path",
    type=click.Path(dir_okay=False),
    default="auth.py",
    show_default=True,
)
@click.option(
    "--cwd",
    type=click.Path(file_okay=False, resolve_path=True),
    default=".",
    show_default=True,
)
@click.option(
    "--db-url",
    "db_url",
    default=None,
    help="Override the database URL (otherwise read from config or env).",
)
@click.option(
    "--revision",
    default="head",
    show_default=True,
    help="Target revision.",
)
def migrate(config_path: str, cwd: str, db_url: str | None, revision: str) -> None:
    from alembic import command
    from alembic.config import Config

    root = Path(cwd)
    full_config = root / config_path if not Path(config_path).is_absolute() else Path(config_path)

    mod = load_config_module(full_config)
    auth = find_auth_handle(mod)

    url = _resolve_db_url(auth, db_url)

    versions_dir = root / "alembic" / "versions"
    if not versions_dir.exists() or not any(versions_dir.glob("*.py")):
        raise click.ClickException(
            f"No Alembic migrations found in {versions_dir}. "
            f"Run `kernia generate` first."
        )

    cfg = Config()
    cfg.set_main_option("script_location", str(root / "alembic"))
    cfg.set_main_option("sqlalchemy.url", url)
    # Alembic needs an env.py — write a minimal one if missing.
    env_py = root / "alembic" / "env.py"
    if not env_py.exists():
        env_py.write_text(_MINIMAL_ENV_PY)
    script_mako = root / "alembic" / "script.py.mako"
    if not script_mako.exists():
        script_mako.write_text(_MINIMAL_SCRIPT_MAKO)

    click.echo(f"Running alembic upgrade {revision} against {url} ...")
    command.upgrade(cfg, revision)
    click.echo("Done.")


_MINIMAL_ENV_PY = '''"""Auto-generated minimal Alembic env for Kernia."""
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

config = context.config

if config.config_file_name is not None:
    try:
        fileConfig(config.config_file_name)
    except Exception:
        pass

target_metadata = None


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
'''


_MINIMAL_SCRIPT_MAKO = '''"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}
"""
from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = ${repr(branch_labels)}
depends_on = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
'''
