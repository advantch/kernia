#!/usr/bin/env bash
# Scaffolds pyproject.toml and __init__.py for every package.
# Idempotent: skips files that already exist.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Workspace packages: (path, dist-name, import-name, summary)
WORKSPACE_PKGS=(
    "packages/core|kernia|kernia|Python implementation compatible with Better Auth — framework-agnostic core"
    "packages/memory_adapter|kernia-memory-adapter|kernia_memory_adapter|In-memory adapter for Kernia (tests + dev)"
    "packages/sqlalchemy_adapter|kernia-sqlalchemy|kernia_sqlalchemy|SQLAlchemy 2.x async adapter for Kernia"
    "packages/fastapi_integration|kernia-fastapi|kernia_fastapi|FastAPI integration for Kernia"
    "packages/cli|kernia-cli|kernia_cli|CLI for Kernia (codegen, migrations)"
    "packages/test_utils|kernia-test-utils|kernia_test_utils|Shared test utilities for Kernia"
)

write_pyproject() {
    local path="$1" dist="$2" import_name="$3" summary="$4"
    local file="$path/pyproject.toml"
    if [[ -f "$file" ]]; then return; fi
    cat > "$file" <<EOF
[project]
name = "$dist"
version = "0.0.0"
description = "$summary"
requires-python = ">=3.11"
dependencies = []

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/$import_name"]
EOF
}

write_init() {
    local path="$1" import_name="$2"
    local dir="$path/src/$import_name"
    mkdir -p "$dir"
    [[ -f "$dir/__init__.py" ]] || echo '"""Package marker."""' > "$dir/__init__.py"
    [[ -f "$dir/py.typed" ]] || touch "$dir/py.typed"
}

for entry in "${WORKSPACE_PKGS[@]}"; do
    IFS='|' read -r path dist import_name summary <<< "$entry"
    write_pyproject "$path" "$dist" "$import_name" "$summary"
    write_init "$path" "$import_name"
done

# Stub packages (layout-locked, not implemented): each gets a marker file only.
STUBS=(
    passkey sso oauth_provider drizzle_adapter prisma_adapter kysely_adapter
    mongo_adapter redis_storage telemetry api_key scim stripe electron expo i18n
)
for stub in "${STUBS[@]}"; do
    dir="packages/_stubs/$stub"
    mkdir -p "$dir"
    cat > "$dir/README.md" <<EOF
# \`$stub\` (stub)

Layout-locked stub for a future kernia package.

The directory name is committed so that when the feature is implemented, it lands here
without architectural drift. See \`spec/file-mapping.md\` for the corresponding
Better Auth TypeScript path.

Status: **not implemented**.
EOF
done

echo "Scaffolded $(find packages -name pyproject.toml | wc -l | tr -d ' ') workspace packages."
echo "Stubs: $(find packages/_stubs -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')."
