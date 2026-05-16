"""Email/password plugin.

Built into `better-auth` itself (not a third-party plugin). Mirrors
`reference/packages/better-auth/src/api/routes/sign-up-email.ts`,
`sign-in-email.ts`, `forget-password.ts`, `reset-password.ts`.

Exposes the canonical routes:
  * POST /sign-up/email
  * POST /sign-in/email
  * POST /forget-password
  * POST /reset-password
"""

from better_auth.plugins.email_password.plugin import email_and_password

__all__ = ["email_and_password"]
