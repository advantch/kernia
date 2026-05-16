"""Organization plugin error codes.

Mirrors `reference/packages/better-auth/src/plugins/organization/error-codes.ts`.
We compress the verbose TS names into shorter, machine-readable codes — the messages
stay descriptive.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final


ORGANIZATION_ERROR_CODES: Final[Mapping[str, str]] = {
    "ORGANIZATION_NOT_FOUND": "Organization not found.",
    "NOT_MEMBER": "You are not a member of this organization.",
    "NOT_ALLOWED": "You are not allowed to perform this action.",
    "LAST_OWNER": "Cannot remove or demote the last owner of the organization.",
    "INVITATION_NOT_FOUND": "Invitation not found.",
    "INVITATION_EXPIRED": "Invitation has expired.",
    "INVITATION_NOT_FOR_YOU": "You are not the recipient of this invitation.",
    "EMAIL_ALREADY_INVITED": "An invitation for that email already exists.",
    "SLUG_TAKEN": "Organization slug is already taken.",
    "MEMBER_NOT_FOUND": "Member not found.",
    "TEAM_NOT_FOUND": "Team not found.",
    "TEAM_ALREADY_EXISTS": "A team with that name already exists.",
    "ROLE_NOT_FOUND": "Role not found.",
    "ROLE_ALREADY_EXISTS": "A role with that name already exists.",
    "INVALID_RESOURCE": "The permission references an unknown resource.",
    "ALREADY_MEMBER": "User is already a member of this organization.",
    "TEAMS_DISABLED": "Teams support is not enabled.",
    "DYNAMIC_AC_DISABLED": "Dynamic access control is not enabled.",
}


__all__ = ["ORGANIZATION_ERROR_CODES"]
