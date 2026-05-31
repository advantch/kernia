"""Built-in plugins.

Mirrors `reference/packages/better-auth/src/plugins/` one-to-one. Each plugin
subdirectory is implemented locally or re-exported from a standalone Kernia
package.

Plugin imports are best-effort so optional standalone packages do not become
mandatory core dependencies. Users should prefer the explicit submodule import
path (e.g. `from kernia.plugins.jwt import jwt`) inside production code.
"""

from __future__ import annotations

from typing import Any

__all__: list[str] = []


def _try_import(name: str, attr: str) -> Any:
    try:
        mod = __import__(f"kernia.plugins.{name}", fromlist=[attr])
        value = getattr(mod, attr, None)
        if value is not None:
            globals()[attr] = value
            __all__.append(attr)
        return value
    except Exception:
        return None


# Lane B / core plugin
_try_import("email_password", "email_and_password")

# Lane D2 — JWT + OAuth proxy + One Tap
_try_import("jwt", "jwt")
_try_import("oauth_proxy", "oauth_proxy")
_try_import("one_tap", "one_tap")
# Upstream-parity custom-session response transformer (distinct from the
# Python-only storage-provider `with_custom_session`).
_try_import("custom_session", "custom_session")

# Optional and built-in plugins; pulled in when their constructors are importable.
for _name, _attr in (
    ("admin", "admin"),
    ("admin_config", "admin_config"),
    ("anonymous", "anonymous"),
    ("bearer", "bearer"),
    ("custom_session", "with_custom_session"),
    ("device_authorization", "device_authorization"),
    ("last_login_method", "last_login_method"),
    ("multi_session", "multi_session"),
    ("siwe", "siwe"),
    ("two_factor", "two_factor"),
    ("username", "username"),
    ("magic_link", "magic_link"),
    ("email_otp", "email_otp"),
    ("captcha", "captcha"),
    ("haveibeenpwned", "have_i_been_pwned"),
    ("generic_oauth", "generic_oauth"),
    ("organization", "organization"),
    ("phone_number", "phone_number"),
    ("open_api", "open_api"),
    ("one_time_token", "one_time_token"),
    ("additional_fields", "additional_fields"),
    ("access", "access"),
    ("mcp", "mcp"),
    ("oidc_provider", "oidc_provider"),
):
    _try_import(_name, _attr)
