"""siwe plugin — Sign-In With Ethereum.

Port of `reference/packages/better-auth/src/plugins/siwe/`. Verifies an
EIP-4361 message + signature, consumes a server-issued nonce, then signs the
user in (auto-creating the user with `walletAddress` if needed).

Requires the optional `eth-account` dependency. For ENS reverse-lookup, pass an
`ENSResolver` (e.g. `web3_ens_resolver(rpc_url=...)`) — without one, ENS lookup
is disabled even if `enable_ens=True`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from kernia.plugins.siwe import routes
from kernia.plugins.siwe.ens import ENSResolver, web3_ens_resolver
from kernia.types.adapter import FieldDef
from kernia.types.endpoint import AuthEndpoint
from kernia.types.hooks import PluginHooks
from kernia.types.plugin import KerniaPlugin, PluginSchema, RateLimitRule


SIWE_ERROR_CODES: Mapping[str, str] = {
    "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE": "SIWE nonce is invalid or expired.",
    "INVALID_SIWE_SIGNATURE": "SIWE signature is invalid.",
}


_SIWE_USER_FIELDS: tuple[FieldDef, ...] = (
    FieldDef("walletAddress", "string", required=False, unique=True),
    FieldDef("ensName", "string", required=False),
)


# Module-level resolver registry, keyed by plugin instance id. The plugin
# dataclass is frozen so we can't store the resolver on it directly without
# breaking equality contracts for downstream tests; instead the routes look up
# the resolver here.
_RESOLVERS: dict[int, ENSResolver] = {}


def _resolver_for(plugin_id: str) -> ENSResolver | None:
    """Look up the resolver registered for the plugin instance id."""
    return _RESOLVERS.get(hash(plugin_id))


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


def siwe(
    *,
    enable_ens: bool = False,
    ens_resolver: ENSResolver | None = None,
    ens_rpc_url: str | None = None,
) -> KerniaPlugin:
    """Construct the SIWE plugin.

    To enable ENS reverse-lookup, supply *either* a custom `ens_resolver`
    (an async callable `(address) -> ens_name | None`) OR `ens_rpc_url`
    (the default web3.py-based resolver is built for you). Either way, set
    `enable_ens=True`. If both are supplied, `ens_resolver` wins.

    On successful sign-in, when ENS is enabled, the resolved name is written
    to `user.ensName` (a new field added via PluginSchema.extend).
    """
    plugin = _SIWEPlugin()
    if enable_ens:
        if ens_resolver is None and ens_rpc_url is not None:
            ens_resolver = web3_ens_resolver(ens_rpc_url)
        if ens_resolver is not None:
            _RESOLVERS[hash(plugin.id)] = ens_resolver
    return plugin  # type: ignore[return-value]


__all__ = ["ENSResolver", "SIWE_ERROR_CODES", "siwe", "web3_ens_resolver"]
