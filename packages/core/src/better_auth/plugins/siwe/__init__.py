"""siwe plugin — Sign-In With Ethereum.

Port of `reference/packages/better-auth/src/plugins/siwe/`. Issues a chain-scoped
nonce, verifies an EIP-4361 message + signature (via the pluggable
``verify_message`` option), consumes the nonce, then signs the user in
(auto-creating the user + a ``walletAddress`` record if needed).

Message verification is pluggable like upstream (``get_nonce`` / ``verify_message``).
The defaults use the optional ``eth-account`` dependency for real signature
recovery and a 17-char alphanumeric nonce. For ENS reverse-lookup, pass either an
``ens_lookup`` callback (upstream shape: ``{walletAddress} -> {name, avatar}``) or
the legacy ``ens_resolver`` / ``ens_rpc_url`` with ``enable_ens=True``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from better_auth.plugins.siwe import routes
from better_auth.plugins.siwe.ens import ENSResolver, web3_ens_resolver
from better_auth.plugins.siwe.routes import ENSLookup, GetNonce, SIWEOptions, VerifyMessage
from better_auth.types.adapter import FieldDef, ModelDef
from better_auth.types.endpoint import AuthEndpoint
from better_auth.types.hooks import PluginHooks
from better_auth.types.plugin import BetterAuthPlugin, PluginSchema, RateLimitRule

SIWE_ERROR_CODES: Mapping[str, str] = {
    "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE": "SIWE nonce is invalid or expired.",
    "INVALID_SIWE_SIGNATURE": "SIWE signature is invalid.",
}


# `user.walletAddress` + `user.ensName` are convenience columns the Python port
# keeps for direct lookups (and for the ENS feature). The canonical store is the
# `walletAddress` model below, matching upstream.
_SIWE_USER_FIELDS: tuple[FieldDef, ...] = (
    FieldDef("walletAddress", "string", required=False, unique=True),
    FieldDef("ensName", "string", required=False),
)


WALLET_ADDRESS_MODEL = ModelDef(
    name="walletAddress",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("userId", "string", references=("user", "id")),
        FieldDef("address", "string"),
        FieldDef("chainId", "number"),
        FieldDef("isPrimary", "boolean", required=False, default=False),
        FieldDef("createdAt", "date"),
    ),
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
        default_factory=lambda: PluginSchema(
            tables=(WALLET_ADDRESS_MODEL,),
            extend={"user": _SIWE_USER_FIELDS},
        )
    )
    endpoints: tuple[AuthEndpoint, ...] = field(default_factory=lambda: routes.ALL)
    middlewares: None = None
    hooks: PluginHooks | None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = (
        RateLimitRule(path="/siwe/nonce", window=60, max=30),
        RateLimitRule(path="/siwe/get-nonce", window=60, max=30),
        RateLimitRule(path="/siwe/verify", window=60, max=10),
    )
    error_codes: Mapping[str, str] = field(
        default_factory=lambda: dict(SIWE_ERROR_CODES)
    )
    init: None = None


def siwe(
    *,
    domain: str = "localhost",
    email_domain_name: str | None = None,
    anonymous: bool = True,
    get_nonce: GetNonce | None = None,
    verify_message: VerifyMessage | None = None,
    ens_lookup: ENSLookup | None = None,
    enable_ens: bool = False,
    ens_resolver: ENSResolver | None = None,
    ens_rpc_url: str | None = None,
) -> BetterAuthPlugin:
    """Construct the SIWE plugin.

    Upstream-parity options:
      * ``domain`` — the SIWE domain embedded in the CACAO envelope.
      * ``email_domain_name`` — domain used to synthesize a placeholder email.
      * ``anonymous`` — when ``False``, a valid ``email`` is required on verify.
      * ``get_nonce`` — async ``() -> str`` (defaults to a 17-char alphanumeric).
      * ``verify_message`` — async ``(args) -> bool`` (defaults to ``eth_account``
        signature recovery).
      * ``ens_lookup`` — async ``({walletAddress}) -> {name, avatar} | None``.

    ENS convenience (legacy): supply either ``ens_resolver`` (async
    ``(address) -> name | None``) OR ``ens_rpc_url`` (builds a web3.py resolver)
    with ``enable_ens=True``. When ENS is enabled the resolved name is written to
    ``user.ensName`` and used as the default ``user.name``.
    """
    routes.configure(
        SIWEOptions(
            domain=domain,
            email_domain_name=email_domain_name,
            anonymous=anonymous,
            get_nonce=get_nonce,
            verify_message=verify_message,
            ens_lookup=ens_lookup,
        )
    )
    plugin = _SIWEPlugin()
    if enable_ens:
        if ens_resolver is None and ens_rpc_url is not None:
            ens_resolver = web3_ens_resolver(ens_rpc_url)
        if ens_resolver is not None:
            _RESOLVERS[hash(plugin.id)] = ens_resolver
    return plugin  # type: ignore[return-value]


__all__ = [
    "ENSLookup",
    "ENSResolver",
    "GetNonce",
    "SIWE_ERROR_CODES",
    "SIWEOptions",
    "VerifyMessage",
    "siwe",
    "web3_ens_resolver",
]
