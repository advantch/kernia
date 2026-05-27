"""Shared helpers used by framework integration packages."""

from kernia.integrations.session import (
    SESSION_COOKIE_NAME,
    resolve_session,
    resolve_session_from_request,
    strip_base_path,
)

__all__ = [
    "SESSION_COOKIE_NAME",
    "resolve_session",
    "resolve_session_from_request",
    "strip_base_path",
]
