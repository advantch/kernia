"""Database-backed admin configuration.

Persists runtime-facing settings for auth method availability, email clients,
Stripe setup, and the public sign-in UI. The plugin also gates configured auth
routes so disabled login methods fail before their handlers run.
"""

from kernia.plugins.admin_config.plugin import (
    ADMIN_CONFIG_ERROR_CODES,
    AdminConfigOptions,
    admin_config,
)

__all__ = ["ADMIN_CONFIG_ERROR_CODES", "AdminConfigOptions", "admin_config"]
