"""Starlette integration for better-auth.

Mirrors `better_auth_fastapi`:
  * `mount_better_auth(app, auth)` — mounts the auth ASGI app at base_path
  * `get_session` / `require_session` — request-aware coroutine helpers
"""

from better_auth_starlette.integration import (
    get_session,
    mount_better_auth,
    require_session,
)

__all__ = ["get_session", "mount_better_auth", "require_session"]
