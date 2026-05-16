"""In-memory adapter — used as the test oracle and for local dev.

Mirrors `reference/packages/better-auth/src/adapters/memory-adapter/`.
"""

from better_auth_memory_adapter.adapter import MemoryAdapter, memory_adapter

__all__ = ["MemoryAdapter", "memory_adapter"]
