"""Cookie-secret rotation.

Better-auth supports `secret` rotation: the active secret signs new cookies; older
secrets remain valid for verify so existing sessions don't break.

Mirrors how the JS reference accepts `secret: string | string[]`. In Python we
accept either a string (one secret) or a sequence (first is active).
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence


def sign_with(value: str, *, active_secret: str) -> str:
    """Sign a value with the active secret. Returns `value.<b64sig>`."""
    from kernia.cookies import sign

    return sign(value, active_secret)


def verify_with_any(signed: str, *, secrets: Sequence[str]) -> str | None:
    """Verify a signed value against ANY of the supplied secrets.

    Use the active secret first (it's the common case); fall back to older secrets
    so rotation doesn't invalidate live sessions. Constant-time per secret.

    Returns the original value if any secret accepts the signature; else None.
    """
    if "." not in signed:
        return None
    value, _, sig = signed.rpartition(".")
    for s in secrets:
        expected = hmac.new(s.encode(), value.encode(), hashlib.sha256).digest()
        import base64

        expected_b64 = base64.urlsafe_b64encode(expected).rstrip(b"=").decode("ascii")
        if hmac.compare_digest(expected_b64, sig):
            return value
    return None


def normalize_secrets(secret: str | Sequence[str]) -> tuple[str, ...]:
    """Coerce the user's `secret` option into a tuple of strings.

    First element is the active signing secret. Subsequent elements are verify-only.
    """
    if isinstance(secret, str):
        return (secret,)
    if not secret:
        raise ValueError("at least one secret is required")
    return tuple(secret)


__all__ = ["normalize_secrets", "sign_with", "verify_with_any"]
