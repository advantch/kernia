"""`kernia secret` — generate a fresh 32-byte secret.

Mirrors `reference/packages/cli/src/commands/secret.ts`.
"""

from __future__ import annotations

import secrets as _secrets

import click


def generate_secret() -> str:
    """Return a 32-byte urlsafe base64 secret (44 chars, no padding stripped)."""
    return _secrets.token_urlsafe(32)


@click.command("secret", help="Generate a cryptographically random secret.")
@click.option(
    "--raw",
    is_flag=True,
    default=False,
    help="Print only the secret (no .env hint).",
)
def secret(raw: bool) -> None:
    value = generate_secret()
    if raw:
        click.echo(value)
        return
    click.echo("")
    click.echo("Add the following to your .env file:")
    click.echo("# Auth Secret")
    click.echo(f"KERNIA_SECRET={value}")
