"""Top-level `BetterAuthOptions` — mirrors `reference/packages/better-auth/src/types/auth.ts`.

This is the user-facing configuration object passed to `better_auth.init()`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from better_auth.social_providers._base import OAuthProvider
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
class AccountLinkingOptions:
    """Account-linking policy. Mirrors `account.accountLinking` in better-auth.

    `trusted_providers` lists provider ids whose `email_verified=True` is enough
    to merge a new OAuth account with an existing user (matched on email). When
    `allow_different_emails=True`, /oauth2/link will accept an OAuth account
    whose email differs from the active user's.
    """

    enabled: bool = False
    trusted_providers: tuple[str, ...] = ()
    allow_different_emails: bool = False


@dataclass
class AccountOptions:
    """`account` config block. Mirrors `account` in better-auth.

    `encrypt_oauth_tokens` is mirrored into `BetterAuthOptions.advanced` for
    backward compatibility with existing call sites in `link_account.py`.
    """

    account_linking: AccountLinkingOptions = field(default_factory=AccountLinkingOptions)
    encrypt_oauth_tokens: bool = False


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
    # Optional ephemeral key/value backend (Redis, in-memory, …) shared by
    # plugins that want caching or distributed coordination — see
    # `better_auth.types.secondary_storage.SecondaryStorage`.
    secondary_storage: Any | None = None
    # Optional rate-limit store override. When `None` and rate-limit is enabled,
    # `init()` synthesizes an `InMemoryRateLimitStore`.
    rate_limit_store: Any | None = None
    # Social OAuth providers keyed by provider id (e.g. "google" -> google(...)).
    # Plugged into the core /sign-in/social + /callback/<provider> endpoints.
    social_providers: Mapping[str, OAuthProvider] = field(default_factory=dict)
    # Account-linking + token-encryption config. Mirrors `account` in better-auth.
    account: AccountOptions = field(default_factory=AccountOptions)
    # Adapter-specific or plugin-specific extras live here, keyed by plugin id.
    advanced: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Mirror account.encrypt_oauth_tokens onto advanced["encrypt_oauth_tokens"]
        # so existing call sites (link_account.py, account.py) keep working.
        if self.account.encrypt_oauth_tokens and not self.advanced.get(
            "encrypt_oauth_tokens"
        ):
            self.advanced["encrypt_oauth_tokens"] = True
