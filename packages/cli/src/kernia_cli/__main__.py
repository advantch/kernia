"""Entry point — `kernia` command tree."""

from __future__ import annotations

import click

from kernia_cli.commands.generate import generate
from kernia_cli.commands.info import info
from kernia_cli.commands.init_cmd import init
from kernia_cli.commands.migrate import migrate
from kernia_cli.commands.secret import secret


@click.group(help="kernia CLI.")
@click.version_option(message="%(prog)s, %(version)s")
def cli() -> None:
    """Top-level group."""


cli.add_command(init)
cli.add_command(generate)
cli.add_command(migrate)
cli.add_command(secret)
cli.add_command(info)


if __name__ == "__main__":
    cli()
