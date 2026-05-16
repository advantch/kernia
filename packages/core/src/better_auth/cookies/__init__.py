"""Cookie signing + parsing.

Mirrors `reference/packages/better-auth/src/cookies/`. The signing scheme is HMAC-SHA256
over the cookie value, with the signature appended after a `.` separator (same wire
format better-auth uses, so JS clients interop).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Mapping

from better_auth.types.cookie import CookieAttributes, CookieDef


def sign(value: str, secret: str) -> str:
    """Return `value.<base64url-hmac>`. Constant-time on the verify side."""
    mac = hmac.new(secret.encode(), value.encode(), hashlib.sha256).digest()
    sig = _b64url(mac)
    return f"{value}.{sig}"


def verify(signed: str, secret: str) -> str | None:
    """Return the original value if the signature matches, else None."""
    if "." not in signed:
        return None
    value, _, sig = signed.rpartition(".")
    expected = hmac.new(secret.encode(), value.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(_b64url(expected), sig):
        return None
    return value


def new_token(n_bytes: int = 32) -> str:
    """Cryptographically random session token (URL-safe)."""
    return _b64url(secrets.token_bytes(n_bytes))


def render_set_cookie(name: str, value: str, attrs: CookieAttributes) -> str:
    """Render a Set-Cookie header value from a name, value, and attributes."""
    parts: list[str] = [f"{name}={value}"]
    if attrs.path:
        parts.append(f"Path={attrs.path}")
    if attrs.domain:
        parts.append(f"Domain={attrs.domain}")
    if attrs.max_age is not None:
        parts.append(f"Max-Age={attrs.max_age}")
    if attrs.expires is not None:
        # RFC 1123 date format
        import email.utils

        parts.append(f"Expires={email.utils.formatdate(attrs.expires, usegmt=True)}")
    if attrs.http_only:
        parts.append("HttpOnly")
    if attrs.secure:
        parts.append("Secure")
    if attrs.same_site:
        parts.append(f"SameSite={attrs.same_site.capitalize()}")
    if attrs.partitioned:
        parts.append("Partitioned")
    return "; ".join(parts)


def parse_cookie_header(header: str) -> Mapping[str, str]:
    """Parse a `Cookie:` request header into a name→value map."""
    out: dict[str, str] = {}
    for chunk in header.split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        name, _, value = chunk.partition("=")
        out[name.strip()] = value.strip()
    return out


def _b64url(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


__all__ = [
    "CookieAttributes",
    "CookieDef",
    "new_token",
    "parse_cookie_header",
    "render_set_cookie",
    "sign",
    "verify",
]
