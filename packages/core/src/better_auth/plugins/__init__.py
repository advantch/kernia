"""Built-in plugins.

Mirrors `reference/packages/better-auth/src/plugins/` one-to-one. Each plugin
subdirectory is a real implementation (no stubs). Plugins are wired through the
parity plan's Lane C/D/E/F.

Plugin imports are best-effort because lanes ship in parallel; only the ones
that have landed are re-exported. Users should prefer the explicit submodule
import path (e.g. `from better_auth.plugins.jwt import jwt`) inside production
code.
"""

from __future__ import annotations

from typing import Any

__all__: list[str] = []


def _try_import(name: str, attr: str) -> Any:
    try:
        mod = __import__(f"better_auth.plugins.{name}", fromlist=[attr])
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

# In-flight parallel lanes — pulled in if their constructors have landed.
for _name, _attr in (
    ("admin", "admin"),
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
