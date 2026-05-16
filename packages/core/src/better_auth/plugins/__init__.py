"""Built-in plugins.

Mirrors `reference/packages/better-auth/src/plugins/`. The MVP ships `email_password`;
the other directories (admin, two_factor, magic_link, etc.) are stubs locked in
`packages/_stubs/`.
"""

from better_auth.plugins.email_password import email_and_password

__all__ = ["email_and_password"]
