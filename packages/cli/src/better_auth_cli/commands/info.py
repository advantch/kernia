"""`better-auth info` — print runtime info for a loaded config.

Mirrors `reference/packages/cli/src/commands/info.ts` (slimmed: we only surface
things meaningful to the Python port).
"""

from __future__ import annotations

import json as _json
import platform
import sys
from pathlib import Path

import better_auth
import click

from better_auth_cli.utils import find_auth_handle, load_config_module

_REDACT_PATTERNS = ("password", "secret", "token", "key")


def _redact(url: str) -> str:
    """Strip credentials from a URL-ish string."""
    if "://" not in url:
        return url
    scheme, _, rest = url.partition("://")
    if "@" in rest:
        creds, _, host = rest.partition("@")
        return f"{scheme}://[REDACTED]@{host}"
    return url


def _collect(auth_handle) -> dict:
    ctx = auth_handle.context
    # `ctx.adapter` is the schema-driven transform wrapper; unwrap to the real
    # adapter so `info` reports e.g. "MemoryAdapter", not "TransformAdapter".
    adapter = getattr(ctx.adapter, "_raw", ctx.adapter)
    adapter_name = type(adapter).__name__
    target = ""
    engine = getattr(adapter, "engine", None)
    if engine is not None and getattr(engine, "url", None) is not None:
        target = _redact(str(engine.url))

    plugins = [
        {"id": p.id, "version": getattr(p, "version", None)}
        for p in ctx.plugins
    ]

    routes = list(auth_handle.router._endpoints.keys())
    sample = [f"{method} {path}" for (method, path) in routes[:10]]

    telemetry_opt_in = bool(
        ctx.options.advanced.get("telemetry") if isinstance(ctx.options.advanced, dict) else False
    )

    return {
        "better_auth_python_version": better_auth.__version__,
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "adapter": adapter_name,
        "database": target,
        "plugins": plugins,
        "route_count": len(routes),
        "routes_sample": sample,
        "telemetry_opt_in": telemetry_opt_in,
    }


@click.command("info", help="Print runtime info for the loaded config.")
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
    "--json",
    "as_json",
    is_flag=True,
    default=False,
    help="Print as JSON.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Don't load the user config — just print library info.",
)
def info(config_path: str, cwd: str, as_json: bool, dry_run: bool) -> None:
    if dry_run:
        data = {
            "better_auth_python_version": better_auth.__version__,
            "python_version": sys.version.split()[0],
            "platform": platform.platform(),
        }
    else:
        full_config = (
            Path(cwd) / config_path
            if not Path(config_path).is_absolute()
            else Path(config_path)
        )
        mod = load_config_module(full_config)
        auth_handle = find_auth_handle(mod)
        data = _collect(auth_handle)

    if as_json:
        click.echo(_json.dumps(data, indent=2, default=str))
        return

    click.echo("")
    click.echo("better-auth-python")
    click.echo("==================")
    for key, value in data.items():
        if isinstance(value, list):
            click.echo(f"{key}:")
            for item in value:
                click.echo(f"  - {item}")
        else:
            click.echo(f"{key}: {value}")
