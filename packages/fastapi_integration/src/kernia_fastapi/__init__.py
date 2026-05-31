"""FastAPI integration for Kernia.

Mirrors the pattern of `reference/packages/better-auth/src/integrations/next.ts`
adapted for FastAPI. Exposes:
  * `mount_kernia(app, auth)` — mounts the auth ASGI app at base_path
  * `get_session` / `require_session` — FastAPI dependencies for downstream routes
"""

from kernia_fastapi.integration import (
    get_session,
    mount_kernia,
    require_session,
)

__all__ = ["get_session", "mount_kernia", "require_session"]
