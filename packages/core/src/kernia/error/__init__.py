"""Error envelope.

Mirrors `reference/packages/better-auth/src/api/api-error.ts` and the `$ERROR_CODES`
convention. Every plugin contributes its own codes via `KerniaPlugin.error_codes`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final


class APIError(Exception):
    """Raised by handlers/hooks to return a typed error response.

    `status` is an HTTP status code. `code` is the machine-readable error identifier
    (e.g. `"INVALID_PASSWORD"`). `message` is human-readable. `data` is optional
    extra payload included in the JSON envelope.
    """

    def __init__(
        self,
        status: int,
        code: str,
        message: str | None = None,
        data: Mapping[str, object] | None = None,
    ) -> None:
        super().__init__(message or code)
        self.status = status
        self.code = code
        self.message = message or code
        self.data = dict(data) if data else None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {"code": self.code, "message": self.message}
        if self.data:
            out["data"] = self.data
        return out


# Core error codes — plugins extend this via `KerniaPlugin.error_codes`.
CORE_ERROR_CODES: Final[Mapping[str, str]] = {
    "INVALID_REQUEST": "Request is malformed.",
    "UNAUTHORIZED": "Authentication is required.",
    "FORBIDDEN": "Operation is not permitted.",
    "NOT_FOUND": "Resource does not exist.",
    "RATE_LIMITED": "Too many requests.",
    "INTERNAL": "Internal server error.",
    "INVALID_EMAIL": "Email address is invalid.",
    "INVALID_PASSWORD": "Password does not meet policy.",
    "USER_NOT_FOUND": "No user matches those credentials.",
    "USER_ALREADY_EXISTS": "An account with that email already exists.",
    "SESSION_EXPIRED": "Session has expired.",
}


@dataclass(frozen=True, slots=True)
class ErrorRegistry:
    """Aggregated error code map. Filled at startup from core + plugin contributions."""

    codes: dict[str, str] = field(default_factory=lambda: dict(CORE_ERROR_CODES))

    def extend(self, codes: Mapping[str, str], *, plugin_id: str) -> None:
        for code, msg in codes.items():
            if code in self.codes:
                raise ValueError(
                    f"Plugin {plugin_id!r} tried to redefine error code {code!r}"
                )
            self.codes[code] = msg
