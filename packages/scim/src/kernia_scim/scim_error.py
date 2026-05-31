"""SCIM-compliant error envelope.

Mirrors ``reference/packages/scim/src/scim-error.ts``. SCIM errors carry a
body shaped per RFC 7644 section 3.12::

    {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "status": "404",
        "detail": "User not found",
    }
"""

from __future__ import annotations

from typing import Any

from better_auth.error import APIError

SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"

# Maps the upstream status keyword to the numeric HTTP status.
_STATUS_CODES: dict[str, int] = {
    "BAD_REQUEST": 400,
    "UNAUTHORIZED": 401,
    "FORBIDDEN": 403,
    "NOT_FOUND": 404,
    "CONFLICT": 409,
    "TOO_MANY_REQUESTS": 429,
    "INTERNAL_SERVER_ERROR": 500,
}


class SCIMAPIError(APIError):
    """An :class:`APIError` whose body follows the SCIM error schema."""

    def __init__(
        self,
        status: str | int = "INTERNAL_SERVER_ERROR",
        **overrides: Any,
    ) -> None:
        if isinstance(status, int):
            code = status
        else:
            code = _STATUS_CODES.get(status, 500)
        detail = overrides.get("detail")
        body: dict[str, Any] = {
            "schemas": [SCIM_ERROR_SCHEMA],
            "status": str(code),
            "detail": detail,
        }
        body.update(overrides)
        message = detail if detail is not None else overrides.get("message")
        super().__init__(code, "SCIM_ERROR", message=message or "SCIM error", data=body)
        # Preserve the rich SCIM body for the response envelope.
        self._scim_body = body

    def to_dict(self) -> dict[str, Any]:  # - documented on base
        return dict(self._scim_body)
