"""SCIM token storage + verification.

Mirrors ``reference/packages/scim/src/scim-tokens.ts``. The stored representation
depends on ``SCIMOptions.store_scim_token``:

  * ``"plain"`` (default) — stored verbatim.
  * ``"hashed"`` — SHA-256, base64url (no padding).
  * ``"encrypted"`` — symmetric-encrypted with the app secret.
  * ``{"hash": fn}`` — custom one-way hash.
  * ``{"encrypt": fn, "decrypt": fn}`` — custom reversible encryption.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Awaitable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from better_auth.types.context import EndpointContext

    from better_auth_scim.types import SCIMOptions


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _default_key_hasher(token: str) -> str:
    digest = hashlib.sha256(token.encode("utf-8")).digest()
    return _b64url_no_pad(digest)


def _symmetric_encrypt(secret: str, data: str) -> str:
    key = hashlib.sha256(secret.encode()).digest()
    raw = data.encode()
    out = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
    return _b64url_no_pad(out)


def _symmetric_decrypt(secret: str, data: str) -> str:
    key = hashlib.sha256(secret.encode()).digest()
    padded = data + "=" * (-len(data) % 4)
    raw = base64.urlsafe_b64decode(padded)
    out = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
    return out.decode()


async def _maybe_await(value: Any) -> Any:
    if isinstance(value, Awaitable):
        return await value
    return value


async def store_scim_token(
    ctx: EndpointContext, opts: SCIMOptions, scim_token: str
) -> str:
    """Return the at-rest representation of ``scim_token`` for this config."""
    store = opts.store_scim_token
    if store == "encrypted":
        return _symmetric_encrypt(ctx.auth.secret, scim_token)
    if store == "hashed":
        return _default_key_hasher(scim_token)
    if isinstance(store, dict) and "hash" in store:
        return await _maybe_await(store["hash"](scim_token))
    if isinstance(store, dict) and "encrypt" in store:
        return await _maybe_await(store["encrypt"](scim_token))
    return scim_token


async def verify_scim_token(
    ctx: EndpointContext,
    opts: SCIMOptions,
    stored_scim_token: str,
    scim_token: str,
) -> bool:
    """Return True if ``scim_token`` matches the ``stored_scim_token``."""
    store = opts.store_scim_token
    if store == "encrypted":
        return _symmetric_decrypt(ctx.auth.secret, stored_scim_token) == scim_token
    if store == "hashed":
        return _default_key_hasher(scim_token) == stored_scim_token
    if isinstance(store, dict) and "hash" in store:
        return await _maybe_await(store["hash"](scim_token)) == stored_scim_token
    if isinstance(store, dict) and "decrypt" in store:
        return await _maybe_await(store["decrypt"](stored_scim_token)) == scim_token
    return scim_token == stored_scim_token
