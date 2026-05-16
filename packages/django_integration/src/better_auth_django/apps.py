"""Django app config for better-auth-django.

Importing this module triggers no Django machinery; the config is only loaded
once the user adds ``better_auth_django`` to ``INSTALLED_APPS``.
"""

from __future__ import annotations

from django.apps import AppConfig


class BetterAuthConfig(AppConfig):
    """Standard Django app config — no ready-hook side effects.

    The auth instance lives on whatever the user passes into ``setup()`` /
    ``BetterAuthView.as_view(auth=...)``. We deliberately don't read it from
    settings here so users can construct the ``BetterAuth`` object at module
    load time without forcing a Django settings dependency on the core.
    """

    name = "better_auth_django"
    label = "better_auth_django"
    verbose_name = "Better Auth"
    default_auto_field = "django.db.models.BigAutoField"
