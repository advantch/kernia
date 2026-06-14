"""Password hashing.

Default: **Argon2id** (via `argon2-cffi`) — the OWASP-recommended modern KDF.
Legacy: **scrypt** (stdlib) — verifier-only, kept so existing hashes are still
acceptable. `needs_rehash()` returns True for stored hashes that should be
upgraded to argon2id on next successful verify.

Wire formats:
  argon2id: standard PHC string `$argon2id$v=19$m=...$t=...$p=...$<salt>$<hash>`
  scrypt:   `scrypt$<n>$<r>$<p>$<b64salt>$<b64hash>`
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import cast

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError

    _ARGON2 = PasswordHasher()
    _HAS_ARGON2 = True
except ImportError:  # pragma: no cover — argon2-cffi is a hard dep in pyproject
    # Typed as PasswordHasher for the checker; every use is gated on _HAS_ARGON2.
    _ARGON2 = cast("PasswordHasher", None)
    _HAS_ARGON2 = False

# Legacy scrypt parameters — used only for verification of pre-existing hashes.
_LEGACY_N = 2**14
_LEGACY_R = 8
_LEGACY_P = 1
_LEGACY_DKLEN = 64


def hash_password(password: str) -> str:
    """Hash a password with Argon2id (current default).

    Wire format: PHC standard string, e.g.
        $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
    """
    if not _HAS_ARGON2:
        return _legacy_scrypt_hash(password)
    return _ARGON2.hash(password)


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verify against any supported hash format.

    Returns True for both argon2id hashes and legacy scrypt hashes (with the
    documented `scrypt$...$...$...` prefix). Returns False on any parse error or
    mismatch.
    """
    if stored.startswith("$argon2"):
        if not _HAS_ARGON2:
            return False
        try:
            _ARGON2.verify(stored, password)
            return True
        except VerifyMismatchError:
            return False
        except Exception:
            return False
    if stored.startswith("scrypt$"):
        return _legacy_scrypt_verify(password, stored)
    return False


def needs_rehash(stored: str) -> bool:
    """True if the stored hash should be upgraded to the current default on next login.

    Use after a successful `verify_password` to migrate users transparently:
        if verify_password(pw, row.password):
            if needs_rehash(row.password):
                row.password = hash_password(pw)
                await adapter.update(...)
    """
    if stored.startswith("scrypt$"):
        return True  # always upgrade legacy hashes
    if stored.startswith("$argon2"):
        if not _HAS_ARGON2:
            return False
        return bool(_ARGON2.check_needs_rehash(stored))
    return True


# ----------------------------------------------------------------------- legacy


def _legacy_scrypt_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_LEGACY_N,
        r=_LEGACY_R,
        p=_LEGACY_P,
        dklen=_LEGACY_DKLEN,
        maxmem=2**26,
    )
    return f"scrypt${_LEGACY_N}${_LEGACY_R}${_LEGACY_P}${_b64(salt)}${_b64(digest)}"


def _legacy_scrypt_verify(password: str, stored: str) -> bool:
    try:
        _scheme, n, r, p, salt_b64, hash_b64 = stored.split("$")
        salt = _unb64(salt_b64)
        expected = _unb64(hash_b64)
    except (ValueError, Exception):
        return False
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=int(n),
        r=int(r),
        p=int(p),
        dklen=len(expected),
        maxmem=2**26,
    )
    return hmac.compare_digest(digest, expected)


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _unb64(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


__all__ = [
    "hash_password",
    "needs_rehash",
    "verify_password",
]
