"""Architectural-rigor audit.

Fetches the Better Auth 1.6.11 source into a temporary directory and asserts
every relevant directory has a counterpart in this repo or an explicit waiver.
No upstream source is vendored or tracked in Git.

Run:  python scripts/audit_layout.py
"""

from __future__ import annotations

import os
import shutil
import sys
import tarfile
import tempfile
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE_PY = ROOT / "packages" / "core" / "src" / "kernia"
PACKAGES = ROOT / "packages"
BETTER_AUTH_REF = "f41514ef07cfafc5dbf463bd1500aee6575d88a7"
BETTER_AUTH_ARCHIVE = f"https://codeload.github.com/better-auth/better-auth/tar.gz/{BETTER_AUTH_REF}"

# Directories under reference/.../src that map elsewhere or are deliberately skipped.
# Every waiver is documented; no implicit stubs are allowed.
WAIVERS: dict[str, str] = {
    "test-utils": "lives at packages/test_utils/ (top-level workspace pkg)",
    "client": "frontends generate clients from the open-api plugin's OpenAPI 3.1 doc",
    "adapters": "covered by sibling workspace packages: memory_adapter, sqlalchemy_adapter, mongo_adapter",
}

# Standalone reference packages we deliberately do not port, with rationale.
PACKAGE_WAIVERS: dict[str, str] = {
    "electron": "frontend/runtime-specific TypeScript with no Python analogue",
    "expo": "React Native client; no Python analogue",
    "drizzle-adapter": "Drizzle is TS-specific; SQLAlchemy is the Python equivalent (we ship one good adapter)",
    "prisma-adapter": "Prisma is TS-specific; SQLAlchemy is the Python equivalent",
    "kysely-adapter": "Kysely is TS-specific; SQLAlchemy is the Python equivalent",
    "better-auth": "the main entry pkg in TS — its surface is split across packages/core + integration pkgs in Python",
    "core": "merged into packages/core in Python (TS splits core from facade; we don't)",
    "i18n": "merged into packages/core/src/kernia/i18n/ (data + helpers, not a separate workspace pkg)",
    "telemetry": "merged into packages/core/src/kernia/telemetry/",
}

# Plugin subdirectories that are not real plugins (e.g. test fixtures) — waive.
PLUGIN_WAIVERS: dict[str, str] = {
    "test-utils": "test fixtures shared across plugin tests; ours live under packages/test_utils/",
}


def kebab_to_snake(name: str) -> str:
    return name.replace("-", "_")


@contextmanager
def upstream_checkout() -> Iterator[Path]:
    existing = os.environ.get("KERNIA_BETTER_AUTH_SOURCE")
    if existing:
        yield Path(existing)
        return

    with tempfile.TemporaryDirectory(prefix="kernia-better-auth-") as tmp:
        tmp_path = Path(tmp)
        archive = tmp_path / "better-auth.tar.gz"
        with urllib.request.urlopen(BETTER_AUTH_ARCHIVE, timeout=30) as response:
            with archive.open("wb") as fh:
                shutil.copyfileobj(response, fh)
        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(tmp_path, filter="data")
        roots = [p for p in tmp_path.iterdir() if p.is_dir()]
        if not roots:
            raise RuntimeError("Better Auth archive did not contain a source directory")
        yield roots[0]


def main() -> int:
    try:
        with upstream_checkout() as upstream:
            return audit(upstream)
    except Exception as exc:
        print(f"ERROR: unable to load Better Auth {BETTER_AUTH_REF}: {exc}", file=sys.stderr)
        return 2


def audit(upstream: Path) -> int:
    reference_src = upstream / "packages" / "better-auth" / "src"
    reference_packages = upstream / "packages"
    if not reference_src.exists():
        print(f"ERROR: Better Auth source is missing {reference_src}", file=sys.stderr)
        return 2

    missing: list[str] = []
    waived: list[str] = []

    # Audit 1: every subdirectory of better-auth/src/ is implemented in packages/core/
    for child in sorted(reference_src.iterdir()):
        if not child.is_dir():
            continue
        kebab = child.name
        snake = kebab_to_snake(kebab)
        if kebab in WAIVERS:
            waived.append(f"  src/{kebab}  → waived ({WAIVERS[kebab]})")
            continue
        candidate = CORE_PY / snake
        if candidate.exists():
            continue
        missing.append(f"  better-auth/src/{kebab}  → expected {candidate.relative_to(ROOT)}")

    # Audit 2: every plugin under better-auth/src/plugins/ is implemented in packages/core/src/kernia/plugins/
    ref_plugins = reference_src / "plugins"
    py_plugins = CORE_PY / "plugins"
    if ref_plugins.exists():
        for child in sorted(ref_plugins.iterdir()):
            if not child.is_dir():
                continue
            kebab = child.name
            snake = kebab_to_snake(kebab)
            if kebab in PLUGIN_WAIVERS:
                waived.append(f"  plugins/{kebab}  → waived ({PLUGIN_WAIVERS[kebab]})")
                continue
            if (py_plugins / snake).exists():
                continue
            missing.append(f"  better-auth/src/plugins/{kebab}  → expected {(py_plugins / snake).relative_to(ROOT)}")

    # Audit 3: every top-level reference package is either ported as a workspace pkg or explicitly waived
    if reference_packages.exists():
        for child in sorted(reference_packages.iterdir()):
            if not child.is_dir():
                continue
            kebab = child.name
            snake = kebab_to_snake(kebab)
            if kebab in PACKAGE_WAIVERS:
                waived.append(f"  packages/{kebab}  → waived ({PACKAGE_WAIVERS[kebab]})")
                continue
            # accept either a top-level package or coverage under packages/core/src/kernia/plugins
            if (PACKAGES / snake).exists():
                continue
            if (py_plugins / snake).exists():
                continue
            missing.append(f"  better-auth/packages/{kebab}  → expected packages/{snake}/ or packages/core/.../plugins/{snake}/")

    if missing:
        print("LAYOUT AUDIT FAILED — uncovered directories:")
        for m in missing:
            print(m)
        print()
        print("Either implement the directory or add an explicit waiver to WAIVERS / PACKAGE_WAIVERS.")
        return 1

    src_count = sum(1 for c in reference_src.iterdir() if c.is_dir())
    plugin_count = sum(1 for c in ref_plugins.iterdir() if c.is_dir()) if ref_plugins.exists() else 0
    pkg_count = sum(1 for c in reference_packages.iterdir() if c.is_dir()) if reference_packages.exists() else 0
    print(f"OK: {src_count} core src dirs, {plugin_count} plugins, {pkg_count} upstream packages all accounted for.")
    if waived:
        print("Waivers:")
        for w in waived:
            print(w)
    return 0


if __name__ == "__main__":
    sys.exit(main())
