"""Built-in plugins.

Mirrors `reference/packages/better-auth/src/plugins/` one-to-one. Each plugin
subdirectory is a real implementation (no stubs). Plugins are wired through the
parity plan's Lane C/D/E/F.
"""

from better_auth.plugins.email_password import email_and_password

__all__ = ["email_and_password"]
