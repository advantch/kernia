"""organization — multi-tenant orgs, members, invitations, teams, dynamic AC.

Mirrors `reference/packages/better-auth/src/plugins/organization/`.

Public surface::

    from kernia.plugins.organization import organization

    organization(
        teams=True,
        dynamic_access_control=True,
        send_invitation=mock_smtp.send,
    )
"""

from kernia.plugins.organization.access_control import (
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
from kernia.plugins.organization.errors import ORGANIZATION_ERROR_CODES
from kernia.plugins.organization.plugin import SendInvitation, organization

__all__ = [
    "DEFAULT_ROLES",
    "DEFAULT_STATEMENTS",
    "ORGANIZATION_ERROR_CODES",
    "AccessControl",
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
