"""Bump every publishable Kernia package to a new lockstep version.

Updates each packages/*/pyproject.toml `version` and re-pins the sibling
`kernia` dependency to `>=<version>`. The suite ships in lockstep, so all
packages always share one version, matched by the git tag `v<version>`.

Run: uv run --with tomlkit python scripts/bump_version.py 0.2.0
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import tomlkit

if len(sys.argv) != 2 or not re.fullmatch(r"\d+\.\d+\.\d+([abc]\d+|rc\d+|\.dev\d+)?", sys.argv[1]):
    sys.exit("usage: bump_version.py <version>  (e.g. 0.2.0 or 0.2.0rc1)")

VERSION = sys.argv[1]
ROOT = Path(__file__).resolve().parent.parent

changed = []
for pp in sorted(ROOT.glob("packages/*/pyproject.toml")):
    doc = tomlkit.parse(pp.read_text())
    proj = doc["project"]
    proj["version"] = VERSION
    for i, dep in enumerate(list(proj.get("dependencies", []))):
        if re.fullmatch(r"kernia(>=.*)?", str(dep).strip()):
            proj["dependencies"][i] = f"kernia>={VERSION}"
    pp.write_text(tomlkit.dumps(doc))
    changed.append(proj["name"])

print(f"Bumped {len(changed)} packages to {VERSION}:")
for n in sorted(changed):
    print(f"  {n}")
print(
    f"\nNext: git commit -am 'release: v{VERSION}' && git tag v{VERSION} && git push --follow-tags"
)
