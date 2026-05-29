"""SCIM resource schema + resource-type constants.

Mirrors ``reference/packages/scim/src/user-schemas.ts``. These describe the User
resource for the discovery endpoints (``/Schemas``, ``/ResourceTypes``).
"""

from __future__ import annotations

from typing import Any

SCIM_USER_RESOURCE_SCHEMA: dict[str, Any] = {
    "id": "urn:ietf:params:scim:schemas:core:2.0:User",
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
    "name": "User",
    "description": "User Account",
    "attributes": [
        {
            "name": "id",
            "type": "string",
            "multiValued": False,
            "description": "Unique opaque identifier for the User",
            "required": False,
            "caseExact": True,
            "mutability": "readOnly",
            "returned": "default",
            "uniqueness": "server",
        },
        {
            "name": "userName",
            "type": "string",
            "multiValued": False,
            "description": (
                "Unique identifier for the User, typically used by the user to "
                "directly authenticate to the service provider"
            ),
            "required": True,
            "caseExact": False,
            "mutability": "readWrite",
            "returned": "default",
            "uniqueness": "server",
        },
        {
            "name": "displayName",
            "type": "string",
            "multiValued": False,
            "description": (
                "The name of the User, suitable for display to end-users.  The "
                "name SHOULD be the full name of the User being described, if "
                "known."
            ),
            "required": False,
            "caseExact": True,
            "mutability": "readOnly",
            "returned": "default",
            "uniqueness": "none",
        },
        {
            "name": "active",
            "type": "boolean",
            "multiValued": False,
            "description": (
                "A Boolean value indicating the User's administrative status."
            ),
            "required": False,
            "mutability": "readOnly",
            "returned": "default",
        },
        {
            "name": "name",
            "type": "complex",
            "multiValued": False,
            "description": "The components of the user's real name.",
            "required": False,
            "subAttributes": [
                {
                    "name": "formatted",
                    "type": "string",
                    "multiValued": False,
                    "description": (
                        "The full name, including all middlenames, titles, and "
                        "suffixes as appropriate, formatted for display(e.g., "
                        "'Ms. Barbara J Jensen, III')."
                    ),
                    "required": False,
                    "caseExact": False,
                    "mutability": "readWrite",
                    "returned": "default",
                    "uniqueness": "none",
                },
                {
                    "name": "familyName",
                    "type": "string",
                    "multiValued": False,
                    "description": (
                        "The family name of the User, or last name in most "
                        "Western languages (e.g., 'Jensen' given the fullname "
                        "'Ms. Barbara J Jensen, III')."
                    ),
                    "required": False,
                    "caseExact": False,
                    "mutability": "readWrite",
                    "returned": "default",
                    "uniqueness": "none",
                },
                {
                    "name": "givenName",
                    "type": "string",
                    "multiValued": False,
                    "description": (
                        "The given name of the User, or first name in most "
                        "Western languages (e.g., 'Barbara' given the full name "
                        "'Ms. Barbara J Jensen, III')."
                    ),
                    "required": False,
                    "caseExact": False,
                    "mutability": "readWrite",
                    "returned": "default",
                    "uniqueness": "none",
                },
            ],
        },
        {
            "name": "emails",
            "type": "complex",
            "multiValued": True,
            "description": (
                "Email addresses for the user.  The value SHOULD be canonicalized "
                "by the service provider, e.g., 'bjensen@example.com' instead of "
                "'bjensen@EXAMPLE.COM'. Canonical type values of 'work', 'home', "
                "and 'other'."
            ),
            "required": False,
            "subAttributes": [
                {
                    "name": "value",
                    "type": "string",
                    "multiValued": False,
                    "description": (
                        "Email addresses for the user.  The value SHOULD be "
                        "canonicalized by the service provider, e.g., "
                        "'bjensen@example.com' instead of 'bjensen@EXAMPLE.COM'. "
                        "Canonical type values of 'work', 'home', and 'other'."
                    ),
                    "required": False,
                    "caseExact": False,
                    "mutability": "readWrite",
                    "returned": "default",
                    "uniqueness": "server",
                },
                {
                    "name": "primary",
                    "type": "boolean",
                    "multiValued": False,
                    "description": (
                        "A Boolean value indicating the 'primary' or preferred "
                        "attribute value for this attribute, e.g., the preferred "
                        "mailing address or primary email address.  The primary "
                        "attribute value 'true' MUST appear no more than once."
                    ),
                    "required": False,
                    "mutability": "readWrite",
                    "returned": "default",
                },
            ],
            "mutability": "readWrite",
            "returned": "default",
            "uniqueness": "none",
        },
    ],
    "meta": {
        "resourceType": "Schema",
        "location": "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User",
    },
}

SCIM_USER_RESOURCE_TYPE: dict[str, Any] = {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
    "id": "User",
    "name": "User",
    "endpoint": "/Users",
    "description": "User Account",
    "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
    "meta": {
        "resourceType": "ResourceType",
        "location": "/scim/v2/ResourceTypes/User",
    },
}
