"""SecondaryStorage Protocol.

Mirrors `reference/packages/better-auth/src/types/secondary-storage.ts`. Used by the
session-data cookie-cache strategy and any plugin that needs ephemeral key-value
storage (rate-limit, device-code, etc.). Redis, in-memory, or custom backends
implement this.

All values are bytes-or-str. `ttl` is seconds; `None` means no expiry.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class SecondaryStorage(Protocol):
    """Ephemeral key-value backend.

    All methods are async. Keys are strings; values are strings (consumers serialize
    JSON themselves). Implementations MUST:
      - return None from `get` on missing/expired keys
      - honor `ttl` on `set` (best-effort eviction is acceptable for in-memory backends)
      - perform `get_and_delete` atomically (this is the contract that lets rate-limit
        and device-flow approval avoid races)
    """

    async def get(self, key: str) -> str | None: ...

    async def set(self, key: str, value: str, *, ttl: int | None = None) -> None: ...

    async def delete(self, key: str) -> None: ...

    async def get_and_delete(self, key: str) -> str | None: ...
