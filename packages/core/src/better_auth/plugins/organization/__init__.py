"""organization — multi-tenant orgs, members, invitations, teams, dynamic AC.

Mirrors `reference/packages/better-auth/src/plugins/organization/`.

Public surface::

    from better_auth.plugins.organization import organization

    organization(
        teams=True,
        dynamic_access_control=True,
        send_invitation=mock_smtp.send,
    )
"""

from better_auth.plugins.organization.access_control import (
    DEFAULT_ROLES,
    DEFAULT_STATEMENTS,
    AccessControl,
    Role,
    Statement,
    create_access_control,
    createAccessControl,
    define_role,
    defineRole,
    has_permission,
    merge_dynamic_roles,
)
from better_auth.plugins.organization.errors import ORGANIZATION_ERROR_CODES
from better_auth.plugins.organization.plugin import SendInvitation, organization

__all__ = [
    "AccessControl",
    "DEFAULT_ROLES",
    "DEFAULT_STATEMENTS",
    "ORGANIZATION_ERROR_CODES",
    "Role",
    "SendInvitation",
    "Statement",
    "createAccessControl",
    "create_access_control",
    "defineRole",
    "define_role",
    "has_permission",
    "merge_dynamic_roles",
    "organization",
]
