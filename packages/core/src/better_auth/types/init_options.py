"""Top-level `BetterAuthOptions` — mirrors `reference/packages/better-auth/src/types/auth.ts`.

This is the user-facing configuration object passed to `better_auth.init()`.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from better_auth.types.adapter import CustomAdapter
    from better_auth.types.plugin import BetterAuthPlugin


@dataclass
class EmailPasswordOptions:
    """Email/password feature flags. Mirrors `emailAndPassword` in better-auth."""

    enabled: bool = False
    require_email_verification: bool = False
    min_password_length: int = 8
    max_password_length: int = 128
    auto_sign_in: bool = True


@dataclass
class SessionOptions:
    """Session lifetime + cookie tuning. Mirrors `session` in better-auth."""

    expires_in: int = 60 * 60 * 24 * 7  # 7 days, seconds
    update_age: int = 60 * 60 * 24  # 1 day — refresh cookie if older than this
    cookie_cache_enabled: bool = True
    cookie_cache_max_age: int = 60 * 5  # 5 min — short-lived `session_data` cookie


@dataclass
class RateLimitOptions:
    """Global rate-limit policy."""

    enabled: bool = True
    window: int = 60
    max: int = 100
    storage: str = "memory"  # or "redis", etc. — adapter-resolved


@dataclass
class BetterAuthOptions:
    """The single options object the user provides.

    `database` is required and must be a `CustomAdapter`. `secret` is required for
    cookie signing.
    """

    database: CustomAdapter
    secret: str
    base_url: str = "http://localhost:3000"
    base_path: str = "/api/auth"
    trusted_origins: Sequence[str] = ()
    email_and_password: EmailPasswordOptions = field(default_factory=EmailPasswordOptions)
    session: SessionOptions = field(default_factory=SessionOptions)
    rate_limit: RateLimitOptions = field(default_factory=RateLimitOptions)
    plugins: Sequence[BetterAuthPlugin] = ()
    # Adapter-specific or plugin-specific extras live here, keyed by plugin id.
    advanced: dict[str, Any] = field(default_factory=dict)
