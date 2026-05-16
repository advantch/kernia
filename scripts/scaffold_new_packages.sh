#!/usr/bin/env bash
# Scaffold every new workspace package created in the full-parity plan.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# (path, dist-name, import-name, summary, deps)
PKGS=(
    "packages/mongodb_adapter|better-auth-mongodb|better_auth_mongodb|MongoDB adapter for better-auth (motor)|better-auth,motor>=3"
    "packages/redis_storage|better-auth-redis-storage|better_auth_redis_storage|Redis-backed secondary storage for better-auth|better-auth,redis>=5"
    "packages/api_key|better-auth-api-key|better_auth_api_key|API key plugin for better-auth|better-auth"
    "packages/passkey|better-auth-passkey|better_auth_passkey|WebAuthn/FIDO2 passkey plugin for better-auth|better-auth,webauthn>=2"
    "packages/sso|better-auth-sso|better_auth_sso|SAML + OIDC SSO plugin for better-auth|better-auth,authlib>=1.3,python3-saml>=1.16"
    "packages/oauth_provider|better-auth-oauth-provider|better_auth_oauth_provider|OAuth2/OIDC provider (issuer side) plugin|better-auth,authlib>=1.3"
    "packages/scim|better-auth-scim|better_auth_scim|SCIM 2.0 provisioning plugin|better-auth"
    "packages/stripe|better-auth-stripe|better_auth_stripe|Stripe billing + webhooks plugin|better-auth,stripe>=10"
    "packages/starlette_integration|better-auth-starlette|better_auth_starlette|Starlette integration|better-auth,starlette>=0.37"
    "packages/django_integration|better-auth-django|better_auth_django|Django integration|better-auth,django>=4.2,anyio>=4"
)

for entry in "${PKGS[@]}"; do
    IFS='|' read -r path dist import_name summary deps_csv <<< "$entry"
    mkdir -p "$path/src/$import_name" "$path/tests"
    [[ -f "$path/src/$import_name/__init__.py" ]] || echo '"""Package marker."""' > "$path/src/$import_name/__init__.py"
    [[ -f "$path/src/$import_name/py.typed" ]] || touch "$path/src/$import_name/py.typed"
    [[ -f "$path/tests/__init__.py" ]] || touch "$path/tests/__init__.py"

    # Build the deps list as TOML array
    deps_lines=""
    IFS=',' read -ra deps <<< "$deps_csv"
    for d in "${deps[@]}"; do
        deps_lines+="    \"$d\","$'\n'
    done

    if [[ ! -f "$path/pyproject.toml" ]]; then
        cat > "$path/pyproject.toml" <<EOF
[project]
name = "$dist"
version = "0.0.0"
description = "$summary"
requires-python = ">=3.11"
dependencies = [
$deps_lines]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/$import_name"]
EOF
    fi
done

# Also ensure packages/core/tests exists
mkdir -p packages/core/tests
[[ -f packages/core/tests/__init__.py ]] || touch packages/core/tests/__init__.py

echo "Scaffolded $(find packages -maxdepth 2 -name pyproject.toml | wc -l | tr -d ' ') workspace packages."
