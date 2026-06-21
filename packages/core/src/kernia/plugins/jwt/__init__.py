"""JWT plugin.

Mirrors `reference/packages/better-auth/src/plugins/jwt/`. Issues JSON Web Tokens
signed with a key managed in our `jwk` table; exposes a JWKS doc; supports key
rotation.

Endpoints:
  * GET  /token         — issue a JWT (requires session)
  * GET  /jwks          — return the JSON Web Key Set
  * POST /jwks/rotate   — rotate the active signing key (admin)
"""

from kernia.plugins.jwt.plugin import (
    JwtOptions,
    issue_jwt,
    jwt,
    sign_jwt,
    to_exp_jwt,
    verify_local_jwt,
)

__all__ = [
    "JwtOptions",
    "issue_jwt",
    "jwt",
    "sign_jwt",
    "to_exp_jwt",
    "verify_local_jwt",
]
