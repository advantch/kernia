"""Generate one Markdown page per plugin under packages/core/src/better_auth/plugins/.

Reads each plugin's `__init__.py` docstring and, where the constructor can be
imported, walks its endpoint list and schema. Writes one file per plugin into
`docs/plugins/<name>.md` plus an index page.

Run from the repo root:

    python docs/scripts/build_plugin_pages.py
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PLUGINS_DIR = REPO_ROOT / "packages" / "core" / "src" / "better_auth" / "plugins"
DOCS_DIR = REPO_ROOT / "docs" / "plugins"
TEMPLATE = (REPO_ROOT / "docs" / "_includes" / "_plugin_template.md").read_text()


def _docstring_from_init(init_py: Path) -> str:
    try:
        mod = ast.parse(init_py.read_text())
    except SyntaxError:
        return "_(plugin docstring unavailable)_"
    doc = ast.get_docstring(mod)
    return doc or "_(no docstring)_"


def _constructor_name(plugin_dir: Path) -> str:
    """Heuristic: read `__all__` from the package init and pick the first export."""
    init_py = plugin_dir / "__init__.py"
    try:
        mod = ast.parse(init_py.read_text())
    except SyntaxError:
        return plugin_dir.name
    for node in ast.walk(mod):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == "__all__":
                    if isinstance(node.value, ast.List | ast.Tuple):
                        for elt in node.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                return elt.value
    return plugin_dir.name


def _safe_import(mod_path: str) -> object | None:
    try:
        return importlib.import_module(mod_path)
    except Exception:
        return None


def _endpoint_table(plugin_obj: object | None) -> str:
    endpoints = getattr(plugin_obj, "endpoints", None) if plugin_obj is not None else None
    if not endpoints:
        return "_(no HTTP endpoints — this plugin contributes hooks/schema only)_"
    rows = ["| Method | Path |", "| --- | --- |"]
    for ep in endpoints:
        opts = getattr(ep, "options", None)
        method = getattr(opts, "method", "POST") if opts else "POST"
        path = getattr(ep, "path", "?")
        rows.append(f"| `{method}` | `{path}` |")
    return "\n".join(rows)


def _schema_section(plugin_obj: object | None) -> str:
    schema = getattr(plugin_obj, "schema", None) if plugin_obj is not None else None
    if schema is None:
        return "_(no schema contributions)_"
    parts: list[str] = []
    tables = getattr(schema, "tables", ()) or ()
    if tables:
        parts.append("**New tables:**\n")
        for t in tables:
            field_names = ", ".join(f.name for f in t.fields)
            parts.append(f"- `{t.name}` — fields: {field_names}")
    extend = getattr(schema, "extend", {}) or {}
    if extend:
        parts.append("\n**Extends existing tables:**\n")
        for model_name, fields in extend.items():
            field_names = ", ".join(f.name for f in fields)
            parts.append(f"- `{model_name}` adds: {field_names}")
    if not parts:
        return "_(no schema contributions)_"
    return "\n".join(parts)


def render_plugin(plugin_dir: Path) -> tuple[str, str]:
    name = plugin_dir.name
    mod_path = f"better_auth.plugins.{name}"
    init_py = plugin_dir / "__init__.py"

    docstring = _docstring_from_init(init_py)
    constructor = _constructor_name(plugin_dir)
    plugin_mod = _safe_import(mod_path)
    plugin_obj = None
    if plugin_mod is not None:
        ctor = getattr(plugin_mod, constructor, None)
        if callable(ctor):
            try:
                plugin_obj = ctor()
            except Exception:
                plugin_obj = None

    body = (
        TEMPLATE
        .replace("{plugin_name}", name.replace("_", " ").title())
        .replace("{plugin_module}", mod_path)
        .replace("{plugin_constructor}", constructor)
        .replace("{plugin_docstring}", docstring)
        .replace("{endpoints_section}", _endpoint_table(plugin_obj))
        .replace("{schema_section}", _schema_section(plugin_obj))
    )
    return name, body


def main() -> None:
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    plugin_dirs = sorted(
        p for p in PLUGINS_DIR.iterdir() if p.is_dir() and not p.name.startswith("_")
    )

    rendered: list[str] = []
    for d in plugin_dirs:
        if not (d / "__init__.py").exists():
            continue
        name, body = render_plugin(d)
        out_path = DOCS_DIR / f"{name}.md"
        out_path.write_text(body)
        rendered.append(name)
        print(f"wrote {out_path.relative_to(REPO_ROOT)}")

    # Index page.
    lines = ["# Plugins", "", "Each page below documents a single built-in plugin.", ""]
    for name in rendered:
        title = name.replace("_", " ").title()
        lines.append(f"- [{title}]({name}.md)")
    (DOCS_DIR / "index.md").write_text("\n".join(lines) + "\n")
    print(f"wrote docs/plugins/index.md ({len(rendered)} plugins)")


if __name__ == "__main__":
    main()
