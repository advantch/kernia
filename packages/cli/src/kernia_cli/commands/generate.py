"""`kernia generate` — emit an Alembic migration for the resolved schema.

Mirrors `reference/packages/cli/src/commands/generate.ts`. Loads the user's config
module, resolves the merged schema (core + every plugin's tables/extensions), and
writes a single Alembic revision file with `op.create_table(...)` for each model.
"""

from __future__ import annotations

from pathlib import Path

import click

from kernia.db.migrations.codegen import emit_migration

from kernia_cli.utils import (
    collect_models,
    deterministic_revision,
    find_auth_handle,
    load_config_module,
)


@click.command("generate", help="Generate an Alembic migration from the resolved schema.")
@click.option(
    "--config",
    "config_path",
    type=click.Path(dir_okay=False, exists=False),
    default="auth.py",
    show_default=True,
    help="Path to the user config module (must define `auth = init(...)`).",
)
@click.option(
    "--output",
    type=click.Path(dir_okay=False),
    default=None,
    help="Output file. Defaults to alembic/versions/<rev>_kernia_schema.py.",
)
@click.option(
    "--cwd",
    type=click.Path(file_okay=False, resolve_path=True),
    default=".",
    show_default=True,
    help="Working directory.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite the output file if it exists.",
)
def generate(config_path: str, output: str | None, cwd: str, force: bool) -> None:
    mod = load_config_module(Path(cwd) / config_path if not Path(config_path).is_absolute() else config_path)
    auth = find_auth_handle(mod)

    models = collect_models(auth)
    revision = deterministic_revision(models)

    source = emit_migration(models, revision=revision, message="kernia schema")

    if output is None:
        out_dir = Path(cwd) / "alembic" / "versions"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{revision}_kernia_schema.py"
    else:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)

    if out_path.exists() and not force:
        existing = out_path.read_text()
        if existing == source:
            click.echo(f"Schema already up to date ({out_path}).")
            return
        raise click.ClickException(
            f"{out_path} already exists and differs. Pass --force to overwrite."
        )

    out_path.write_text(source)
    click.echo(f"Wrote migration: {out_path}")
    click.echo(f"Revision: {revision}")
