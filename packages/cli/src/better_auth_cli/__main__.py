"""Entry point — `better-auth` command tree."""

from __future__ import annotations

import click

from better_auth_cli.commands.generate import generate
from better_auth_cli.commands.info import info
from better_auth_cli.commands.init_cmd import init
from better_auth_cli.commands.migrate import migrate
from better_auth_cli.commands.secret import secret


@click.group(help="better-auth-python CLI.")
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
