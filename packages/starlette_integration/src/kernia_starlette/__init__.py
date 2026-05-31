"""Starlette integration for Kernia.

Mirrors `kernia_fastapi`:
  * `mount_kernia(app, auth)` — mounts the auth ASGI app at base_path
  * `get_session` / `require_session` — request-aware coroutine helpers
"""

from kernia_starlette.integration import (
    get_session,
    mount_kernia,
    require_session,
)

__all__ = ["get_session", "mount_kernia", "require_session"]
