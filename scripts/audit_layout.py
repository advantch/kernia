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
STUBS = ROOT / "packages" / "_stubs"

# Directories under reference/.../src that map elsewhere or are deliberately skipped.
# Keep this list short — every entry is a tradeoff that should be reviewed.
WAIVERS: dict[str, str] = {
    "test-utils": "lives at packages/test_utils/ (top-level workspace pkg)",
    "client": "covered by packages/core/src/better_auth/client/ (Phase 3)",
    "adapters": "covered by sibling workspace packages: memory_adapter, sqlalchemy_adapter, _stubs/*",
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

    for child in sorted(REFERENCE_SRC.iterdir()):
        if not child.is_dir():
            continue
        kebab = child.name
        snake = kebab_to_snake(kebab)
        if kebab in WAIVERS:
            waived.append(f"  {kebab}  → waived ({WAIVERS[kebab]})")
            continue
        candidate = CORE_PY / snake
        if candidate.exists():
            continue
        stub = STUBS / snake
        if stub.exists():
            continue
        missing.append(f"  reference/.../src/{kebab}  → expected {candidate.relative_to(ROOT)} or {stub.relative_to(ROOT)}")

    if missing:
        print("LAYOUT AUDIT FAILED — better-auth has directories not mirrored here:")
        for m in missing:
            print(m)
        print()
        print("Either add the directory under packages/core/src/better_auth/,")
        print("create a stub at packages/_stubs/, or add an explicit waiver to WAIVERS.")
        return 1

    print(f"OK: {sum(1 for c in REFERENCE_SRC.iterdir() if c.is_dir())} reference dirs accounted for.")
    if waived:
        print("Waivers:")
        for w in waived:
            print(w)
    return 0


if __name__ == "__main__":
    sys.exit(main())
