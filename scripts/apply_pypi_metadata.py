"""One-shot: inject PyPI-ready metadata into every publishable package.

Adds authors/license/urls/classifiers/keywords/readme, sets the release
version, and pins the sibling `kernia` dependency. Idempotent-ish: overwrites
the managed keys, leaves everything else (per-package deps) untouched.

Run: uv run --with tomlkit python scripts/apply_pypi_metadata.py 0.1.0
"""

from __future__ import annotations

import sys
from pathlib import Path

import tomlkit

VERSION = sys.argv[1] if len(sys.argv) > 1 else "0.1.0"
ROOT = Path(__file__).resolve().parent.parent
PIN = f"kernia>={VERSION}"

AUTHORS = [{"name": "Advantch"}]
KEYWORDS = [
    "authentication",
    "authorization",
    "sessions",
    "oauth",
    "passkeys",
    "sso",
    "asgi",
    "fastapi",
    "starlette",
    "django",
    "security",
]
CLASSIFIERS = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "Operating System :: OS Independent",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Software Development :: Libraries :: Python Modules",
    "Topic :: Internet :: WWW/HTTP :: Session",
    "Topic :: Security",
    "Typing :: Typed",
]
URLS = {
    "Homepage": "https://kernia.dev",
    "Documentation": "https://kernia.dev/docs",
    "Source": "https://github.com/advantch/kernia",
    "Issues": "https://github.com/advantch/kernia/issues",
    "Changelog": "https://github.com/advantch/kernia/releases",
}


def arr(values):
    a = tomlkit.array()
    a.multiline(True)
    a.extend(values)
    return a


def apply(path: Path) -> str:
    doc = tomlkit.parse(path.read_text())
    proj = doc["project"]
    proj["version"] = VERSION
    if "requires-python" not in proj:
        proj["requires-python"] = ">=3.11"
    proj["readme"] = "README.md"
    proj["license"] = "MIT"
    proj["license-files"] = arr(["LICENSE"])
    authors = tomlkit.array()
    authors.multiline(True)
    for a in AUTHORS:
        t = tomlkit.inline_table()
        t.update(a)
        authors.append(t)
    proj["authors"] = authors
    proj["keywords"] = arr(KEYWORDS)
    proj["classifiers"] = arr(CLASSIFIERS)
    urls = tomlkit.table()
    for k, v in URLS.items():
        urls[k] = v
    proj["urls"] = urls
    # pin the sibling core dependency
    if "dependencies" in proj:
        deps = proj["dependencies"]
        for i, d in enumerate(list(deps)):
            if str(d).strip() == "kernia":
                deps[i] = PIN
    path.write_text(tomlkit.dumps(doc))
    return proj["name"]


names = []
for pp in sorted(ROOT.glob("packages/*/pyproject.toml")):
    names.append(apply(pp))
print(f"Applied v{VERSION} + metadata to {len(names)} packages:")
for n in sorted(names):
    print(f"  {n}")
