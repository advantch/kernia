"""Password hashing.

Uses stdlib `hashlib.scrypt` so the core has zero non-stdlib deps. Wire format:
    `scrypt$<n>$<r>$<p>$<b64salt>$<b64hash>`
This format is parseable, upgrade-resilient (we can swap to argon2 later by adding a
new prefix), and matches better-auth's "scrypt by default" stance.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

_N = 2**14  # ~25ms on modern hardware
_R = 8
_P = 1
_DKLEN = 64


def hash_password(password: str) -> str:
    """Hash a password with a fresh random salt."""
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_N,
        r=_R,
        p=_P,
        dklen=_DKLEN,
        maxmem=2 ** 26,
    )
    return f"scrypt${_N}${_R}${_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time password check against a stored hash."""
    try:
        scheme, n, r, p, salt_b64, hash_b64 = stored.split("$")
    except ValueError:
        return False
    if scheme != "scrypt":
        return False
    try:
        salt = _unb64(salt_b64)
        expected = _unb64(hash_b64)
    except Exception:
        return False
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=int(n),
        r=int(r),
        p=int(p),
        dklen=len(expected),
        maxmem=2 ** 26,
    )
    return hmac.compare_digest(digest, expected)


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _unb64(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


__all__ = ["hash_password", "verify_password"]
