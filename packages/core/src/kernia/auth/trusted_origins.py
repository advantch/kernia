"""Trusted-origins / CSRF middleware.

Mirrors `reference/packages/better-auth/src/auth/trusted-origins.ts`. For any
state-changing request (POST/PUT/PATCH/DELETE), the `Origin` (or fallback
`Referer`) must match the configured `base_url` or appear in `trusted_origins`.
Same-origin requests with no Origin header (e.g. server-side `fetch` from the
same app) are accepted.

We integrate this as a router-level pre-check in `Router.mount()` rather than as
a plugin, so it's always on by default (you can disable it by setting
`advanced.disable_csrf_check = True`).
"""

from __future__ import annotations

from collections.abc import Sequence
from urllib.parse import urlparse


def normalize_origin(value: str) -> str | None:
    """Reduce a URL or origin string to `scheme://host[:port]`. Returns None if
    the input is not a well-formed origin."""
    if not value:
        return None
    parsed = urlparse(value if "://" in value else f"https://{value}")
    if not parsed.scheme or not parsed.netloc:
        return None
    # netloc must not contain whitespace or be obviously malformed
    if any(ch.isspace() for ch in parsed.netloc):
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def is_trusted(
    *,
    origin: str | None,
    referer: str | None,
    base_url: str,
    trusted_origins: Sequence[str],
) -> bool:
    """Decide whether a request's Origin (or Referer fallback) is trusted.

    Same-origin requests with no Origin header (common for SSR or non-fetch
    callers) return True. Otherwise we require an explicit match against
    `base_url` or `trusted_origins`.
    """
    candidate = origin or referer
    if not candidate:
        return True
    candidate_origin = normalize_origin(candidate)
    if candidate_origin is None:
        return False
    base_origin = normalize_origin(base_url)
    allowed: set[str] = set()
    if base_origin:
        allowed.add(base_origin)
    for t in trusted_origins:
        n = normalize_origin(t)
        if n:
            allowed.add(n)
    return candidate_origin in allowed


def is_state_changing(method: str) -> bool:
    return method.upper() in {"POST", "PUT", "PATCH", "DELETE"}


__all__ = ["is_state_changing", "is_trusted", "normalize_origin"]
