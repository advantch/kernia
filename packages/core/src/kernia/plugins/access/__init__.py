"""access — primitives used by `admin`, `organization`, `api_key`, `scim` for RBAC.

Mirrors `reference/packages/better-auth/src/plugins/access/`.
"""

from kernia.plugins.access.access import (
    AccessControl,
    AuthorizeResponse,
    Role,
    Statement,
    create_access_control,
    default_roles,
    default_statements,
    role,
)

__all__ = [
    "AccessControl",
    "AuthorizeResponse",
    "Role",
    "Statement",
    "create_access_control",
    "default_roles",
    "default_statements",
    "role",
]
