"""Core API routes.

Mirrors `reference/packages/better-auth/src/api/routes/`. These are the endpoints
the core always registers (not contributed by plugins): session management,
account management, email verification, ok/error.

Each route module exports a tuple `ROUTES` of `AuthEndpoint` values. `core_routes()`
returns the full set; `init()` registers it.
"""

from better_auth.api.routes.account import ACCOUNT_ROUTES
from better_auth.api.routes.email_verification import EMAIL_VERIFICATION_ROUTES
from better_auth.api.routes.error import ERROR_ROUTES
from better_auth.api.routes.ok import OK_ROUTES
from better_auth.api.routes.session import SESSION_ROUTES
from better_auth.api.routes.sign_in_social import SOCIAL_ROUTES
from better_auth.api.routes.update_user import UPDATE_USER_ROUTES
from better_auth.types.endpoint import AuthEndpoint


def core_routes() -> tuple[AuthEndpoint, ...]:
    return (
        *OK_ROUTES,
        *ERROR_ROUTES,
        *SESSION_ROUTES,
        *ACCOUNT_ROUTES,
        *UPDATE_USER_ROUTES,
        *EMAIL_VERIFICATION_ROUTES,
        *SOCIAL_ROUTES,
    )


__all__ = ["core_routes"]
