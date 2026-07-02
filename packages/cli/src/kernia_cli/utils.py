"""Shared helpers for the CLI commands."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import click
from kernia.auth import Kernia
from kernia.db.migrations.codegen import resolve_full_schema
from kernia.db.schema import CORE_MODELS


def load_config_module(config_path: str | Path) -> ModuleType:
    """Import a user config file by path (e.g. `./auth.py`).

    The module is registered under a stable name so re-imports inside the same
    process reuse it.
    """
    path = Path(config_path).resolve()
    if not path.exists():
        raise click.ClickException(f"Config file not found: {path}")
    # Non-security: SHA1 only derives a stable module name from the path.
    digest = hashlib.sha1(str(path).encode(), usedforsecurity=False).hexdigest()[:8]
    mod_name = f"_kernia_user_config_{digest}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise click.ClickException(f"Could not load {path} as a Python module.")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    # Make sure the config's own dir is on sys.path so its relative imports work.
    parent = str(path.parent)
    if parent not in sys.path:
        sys.path.insert(0, parent)
    spec.loader.exec_module(mod)
    return mod


def find_auth_handle(mod: ModuleType) -> Kernia:
    """Return the `Kernia` instance from a user config module.

    Convention: the module exposes a top-level `auth` object. Falls back to the
    first `Kernia` instance found in the module namespace.
    """
    candidate = getattr(mod, "auth", None)
    if isinstance(candidate, Kernia):
        return candidate
    for value in vars(mod).values():
        if isinstance(value, Kernia):
            return value
    raise click.ClickException(
        "Config module did not expose a `Kernia` instance (e.g. `auth = init(...)`)."
    )


def deterministic_revision(models: Any) -> str:
    """Hash the resolved schema shape to a 12-char revision id.

    Re-running `generate` on an unchanged schema produces the same revision, so
    the user doesn't accumulate spurious migration files.
    """
    # Non-security: SHA1 fingerprints the schema shape into a stable revision id.
    h = hashlib.sha1(usedforsecurity=False)
    for m in models:
        h.update(m.name.encode())
        for f in m.fields:
            h.update(f.name.encode())
            h.update(f.type.encode())
            h.update(b"1" if f.required else b"0")
            h.update(b"1" if f.unique else b"0")
            if f.references:
                h.update((f.references[0] + "." + f.references[1]).encode())
            h.update(repr(f.default).encode())
    return h.hexdigest()[:12]


def collect_models(auth: Kernia) -> tuple[Any, ...]:
    """Merge core models with every plugin's schema for the given handle."""
    return resolve_full_schema(CORE_MODELS, auth.context.plugins)


__all__ = [
    "collect_models",
    "deterministic_revision",
    "find_auth_handle",
    "load_config_module",
]
