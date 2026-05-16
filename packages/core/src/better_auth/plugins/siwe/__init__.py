"""siwe plugin — Sign-In With Ethereum.

Port of `reference/packages/better-auth/src/plugins/siwe/`. Verifies an
EIP-4361 message + signature, consumes a server-issued nonce, then signs the
user in (auto-creating the user with `walletAddress` if needed).

Requires the optional `eth-account` dependency (declared via the
`[project.optional-dependencies] siwe` extra on `better-auth`).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from better_auth.plugins.siwe import routes
from better_auth.types.adapter import FieldDef
from better_auth.types.endpoint import AuthEndpoint
from better_auth.types.hooks import PluginHooks
from better_auth.types.plugin import BetterAuthPlugin, PluginSchema, RateLimitRule


SIWE_ERROR_CODES: Mapping[str, str] = {
    "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE": "SIWE nonce is invalid or expired.",
    "INVALID_SIWE_SIGNATURE": "SIWE signature is invalid.",
}


_SIWE_USER_FIELDS: tuple[FieldDef, ...] = (
    FieldDef("walletAddress", "string", required=False, unique=True),
)


@dataclass(frozen=True, slots=True)
class _SIWEPlugin:
    id: str = "siwe"
    version: str | None = None
    schema: PluginSchema | None = field(
        default_factory=lambda: PluginSchema(extend={"user": _SIWE_USER_FIELDS})
    )
    endpoints: tuple[AuthEndpoint, ...] = field(default_factory=lambda: routes.ALL)
    middlewares: None = None
    hooks: PluginHooks | None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = (
        RateLimitRule(path="/siwe/nonce", window=60, max=30),
        RateLimitRule(path="/siwe/verify", window=60, max=10),
    )
    error_codes: Mapping[str, str] = field(
        default_factory=lambda: dict(SIWE_ERROR_CODES)
    )
    init: None = None


def siwe(*, enable_ens: bool = False) -> BetterAuthPlugin:
    """Construct the SIWE plugin.

    `enable_ens` is reserved for future ENS reverse-lookup support; callers can
    wire ENS via a custom after-hook for now.
    """
    del enable_ens
    return _SIWEPlugin()  # type: ignore[return-value]


__all__ = ["SIWE_ERROR_CODES", "siwe"]
