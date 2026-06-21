"""WebAuthn passkey plugin.

Port of ``reference/packages/passkey/src/index.ts``. Contributes the ``passkey``
table and the upstream endpoint surface:

  * ``GET  /passkey/generate-register-options``
  * ``GET  /passkey/generate-authenticate-options``
  * ``POST /passkey/verify-registration``
  * ``POST /passkey/verify-authentication``
  * ``GET  /passkey/list-user-passkeys``
  * ``POST /passkey/delete-passkey``
  * ``POST /passkey/update-passkey``

WebAuthn option-generation and attestation/assertion verification are delegated to
the ``webauthn`` PyPI library (via :mod:`kernia_passkey.webauthn_server`,
which mirrors ``@simplewebauthn/server`` so the two verify functions can be
monkeypatched in tests).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from kernia.types.endpoint import AuthEndpoint
from kernia.types.hooks import PluginHooks
from kernia.types.plugin import KerniaPlugin, PluginSchema, RateLimitRule

from . import routes
from .error_codes import PASSKEY_ERROR_CODES
from .schema import PASSKEY_MODEL
from .types import (
    PasskeyAdvancedOptions,
    PasskeyAuthenticationOptions,
    PasskeyOptions,
    PasskeyRegistrationOptions,
)


@dataclass(frozen=True, slots=True)
class _PasskeyPlugin:
    id: str = "passkey"
    version: str | None = None
    schema: PluginSchema | None = field(
        default_factory=lambda: PluginSchema(tables=(PASSKEY_MODEL,))
    )
    endpoints: tuple[AuthEndpoint, ...] = ()
    middlewares: None = None
    hooks: PluginHooks | None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = (
        RateLimitRule(path="/passkey/verify-registration", window=60, max=10),
        RateLimitRule(path="/passkey/verify-authentication", window=60, max=20),
    )
    error_codes: Mapping[str, str] = field(default_factory=lambda: dict(PASSKEY_ERROR_CODES))
    init: Any = None


def passkey(
    options: PasskeyOptions | None = None,
    *,
    rp_id: str | None = None,
    rp_name: str | None = None,
    origin: str | list[str] | None = None,
    authenticator_selection: dict | None = None,
    registration: PasskeyRegistrationOptions | None = None,
    authentication: PasskeyAuthenticationOptions | None = None,
    advanced: PasskeyAdvancedOptions | None = None,
) -> KerniaPlugin:
    """Construct the passkey plugin.

    Accepts either a :class:`PasskeyOptions` instance positionally (mirroring the
    upstream ``passkey(options)`` signature) or the individual keyword arguments.
    """
    if options is None:
        options = PasskeyOptions(
            rp_id=rp_id,
            rp_name=rp_name,
            origin=origin,
            authenticator_selection=authenticator_selection,
            advanced=advanced or PasskeyAdvancedOptions(),
            registration=registration,
            authentication=authentication,
        )

    routes._OPTIONS_REGISTRY["passkey"] = options
    endpoints = routes.build_endpoints(options)

    async def _init(ctx: Any) -> None:
        ctx.plugin_state["passkey"] = options

    plugin = _PasskeyPlugin(endpoints=endpoints, init=_init)  # type: ignore[call-arg]
    return plugin  # type: ignore[return-value]


__all__ = ["PASSKEY_ERROR_CODES", "passkey"]
