"""Architectural-rigor audit.

Walks `reference/packages/better-auth/src/` and asserts every directory has a
counterpart in this repo — either as an active package directory or as an explicit
stub. This is the no-shortcuts gate: if better-auth grows a new directory and we
don't reflect it, CI fails.

Run:  python scripts/audit_layout.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCE_SRC = ROOT / "reference" / "packages" / "better-auth" / "src"
CORE_PY = ROOT / "packages" / "core" / "src" / "better_auth"
PACKAGES = ROOT / "packages"

# Directories under reference/.../src that map elsewhere or are deliberately skipped.
# Every waiver is documented; no implicit stubs are allowed.
WAIVERS: dict[str, str] = {
    "test-utils": "lives at packages/test_utils/ (top-level workspace pkg)",
    "client": "frontends generate clients from the open-api plugin's OpenAPI 3.1 doc",
    "adapters": "covered by sibling workspace packages: memory_adapter, sqlalchemy_adapter, mongodb_adapter",
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
    "i18n": "merged into packages/core/src/better_auth/i18n/ (data + helpers, not a separate workspace pkg)",
    "telemetry": "merged into packages/core/src/better_auth/telemetry/",
}

# Plugin subdirectories that are not real plugins (e.g. test fixtures) — waive.
PLUGIN_WAIVERS: dict[str, str] = {
    "test-utils": "test fixtures shared across plugin tests; ours live under packages/test_utils/",
}


def kebab_to_snake(name: str) -> str:
    return name.replace("-", "_")


def main() -> int:
    if not REFERENCE_SRC.exists():
        print(f"ERROR: reference not initialized at {REFERENCE_SRC}", file=sys.stderr)
        print("  run: git submodule update --init", file=sys.stderr)
        return 2

    missing: list[str] = []
    waived: list[str] = []

    # Audit 1: every subdirectory of better-auth/src/ is implemented in packages/core/
    for child in sorted(REFERENCE_SRC.iterdir()):
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
        missing.append(f"  reference/.../src/{kebab}  → expected {candidate.relative_to(ROOT)}")

    # Audit 2: every plugin under better-auth/src/plugins/ is implemented in packages/core/src/better_auth/plugins/
    REF_PLUGINS = REFERENCE_SRC / "plugins"
    PY_PLUGINS = CORE_PY / "plugins"
    if REF_PLUGINS.exists():
        for child in sorted(REF_PLUGINS.iterdir()):
            if not child.is_dir():
                continue
            kebab = child.name
            snake = kebab_to_snake(kebab)
            if kebab in PLUGIN_WAIVERS:
                waived.append(f"  plugins/{kebab}  → waived ({PLUGIN_WAIVERS[kebab]})")
                continue
            if (PY_PLUGINS / snake).exists():
                continue
            missing.append(f"  reference/.../src/plugins/{kebab}  → expected {(PY_PLUGINS / snake).relative_to(ROOT)}")

    # Audit 3: every top-level reference package is either ported as a workspace pkg or explicitly waived
    REFERENCE_PACKAGES = ROOT / "reference" / "packages"
    if REFERENCE_PACKAGES.exists():
        for child in sorted(REFERENCE_PACKAGES.iterdir()):
            if not child.is_dir():
                continue
            kebab = child.name
            snake = kebab_to_snake(kebab)
            if kebab in PACKAGE_WAIVERS:
                waived.append(f"  packages/{kebab}  → waived ({PACKAGE_WAIVERS[kebab]})")
                continue
            # accept either a top-level package or coverage under packages/core/src/better_auth/plugins
            if (PACKAGES / snake).exists():
                continue
            if (PY_PLUGINS / snake).exists():
                continue
            missing.append(f"  reference/packages/{kebab}  → expected packages/{snake}/ or packages/core/.../plugins/{snake}/")

    if missing:
        print("LAYOUT AUDIT FAILED — uncovered directories:")
        for m in missing:
            print(m)
        print()
        print("Either implement the directory or add an explicit waiver to WAIVERS / PACKAGE_WAIVERS.")
        return 1

    src_count = sum(1 for c in REFERENCE_SRC.iterdir() if c.is_dir())
    plugin_count = sum(1 for c in REF_PLUGINS.iterdir() if c.is_dir()) if REF_PLUGINS.exists() else 0
    pkg_count = sum(1 for c in REFERENCE_PACKAGES.iterdir() if c.is_dir()) if REFERENCE_PACKAGES.exists() else 0
    print(f"OK: {src_count} core src dirs, {plugin_count} plugins, {pkg_count} reference packages all accounted for.")
    if waived:
        print("Waivers:")
        for w in waived:
            print(w)
    return 0


if __name__ == "__main__":
    sys.exit(main())
