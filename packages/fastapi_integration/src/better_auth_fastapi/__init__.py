"""FastAPI integration for better-auth.

Mirrors the pattern of `reference/packages/better-auth/src/integrations/next.ts`
adapted for FastAPI. Exposes:
  * `mount_better_auth(app, auth)` — mounts the auth ASGI app at base_path
  * `get_session` / `require_session` — FastAPI dependencies for downstream routes
"""

from better_auth_fastapi.integration import (
    get_session,
    mount_better_auth,
    require_session,
)

__all__ = ["get_session", "mount_better_auth", "require_session"]
