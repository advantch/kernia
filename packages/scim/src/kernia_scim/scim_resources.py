"""Build the SCIM User resource representation.

Mirrors ``reference/packages/scim/src/scim-resources.ts``.
"""

from __future__ import annotations

from typing import Any

from better_auth_scim.mappings import get_resource_url
from better_auth_scim.schemas import SCIM_USER_RESOURCE_SCHEMA


def create_user_resource(
    base_url: str,
    user: dict[str, Any],
    account: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the RFC 7643 User resource for ``user`` (+ optional ``account``)."""
    return {
        "id": user["id"],
        "externalId": account.get("accountId") if account else None,
        "meta": {
            "resourceType": "User",
            "created": user.get("createdAt"),
            "lastModified": user.get("updatedAt"),
            "location": get_resource_url(f"/scim/v2/Users/{user['id']}", base_url),
        },
        "userName": user.get("email"),
        "name": {"formatted": user.get("name")},
        "displayName": user.get("name"),
        "active": True,
        "emails": [{"primary": True, "value": user.get("email")}],
        "schemas": [SCIM_USER_RESOURCE_SCHEMA["id"]],
    }
