"""magic_link — see reference/packages/better-auth/src/plugins/magic-link/.

Passwordless sign-in via emailed short-lived URLs. Tokens are persisted in the
core `verification` table with identifier `magic-link:<token>` and atomically
consumed on first GET to `/magic-link/verify`.
"""

from kernia.plugins.magic_link.plugin import (
    MAGIC_LINK_ERROR_CODES,
    magic_link,
)

__all__ = ["MAGIC_LINK_ERROR_CODES", "magic_link"]
