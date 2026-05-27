"""AES-GCM encryption for OAuth tokens at rest.

Mirrors `reference/packages/better-auth/src/oauth2/utils.ts` (decryptOAuthToken/
setTokenUtil). When `KerniaOptions.account.encryptOAuthTokens` is enabled,
access_token and refresh_token columns are stored encrypted using a key derived
from the active cookie secret.

Wire format on disk:
    enc.v1.<nonce-b64>.<ciphertext+tag-b64>
"""

from __future__ import annotations

import base64
import hashlib
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_PREFIX = "enc.v1."


def _derive_key(secret: str) -> bytes:
    """Stable 32-byte key from the cookie secret. Stable across restarts."""
    return hashlib.sha256(b"better-auth:oauth-token:" + secret.encode()).digest()


def encrypt_token(plain: str, *, secret: str) -> str:
    """AES-GCM encrypt a token. Result is safe to store as a string column."""
    nonce = secrets.token_bytes(12)
    aes = AESGCM(_derive_key(secret))
    ct = aes.encrypt(nonce, plain.encode("utf-8"), associated_data=None)
    return _PREFIX + _b64(nonce) + "." + _b64(ct)


def decrypt_token(stored: str, *, secret: str) -> str:
    """Decrypt a token stored by `encrypt_token`. Raises ValueError on tamper."""
    if not stored.startswith(_PREFIX):
        raise ValueError("not an encrypted token")
    body = stored[len(_PREFIX):]
    try:
        nonce_b64, ct_b64 = body.split(".", 1)
        nonce = _unb64(nonce_b64)
        ct = _unb64(ct_b64)
    except (ValueError, Exception) as e:
        raise ValueError(f"malformed encrypted token: {e}") from None
    aes = AESGCM(_derive_key(secret))
    try:
        plain = aes.decrypt(nonce, ct, associated_data=None)
    except Exception as e:
        raise ValueError(f"AES-GCM tag verification failed: {e}") from None
    return plain.decode("utf-8")


def is_encrypted(stored: str) -> bool:
    return stored.startswith(_PREFIX)


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _unb64(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


__all__ = ["decrypt_token", "encrypt_token", "is_encrypted"]
