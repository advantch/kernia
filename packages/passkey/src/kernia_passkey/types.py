"""Passkey option types.

Port of ``reference/packages/passkey/src/types.ts``. Callbacks are async-or-sync
callables (the runtime awaits them when needed), mirroring the upstream
``Awaitable<T>`` shape.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

# A resolved user used during registration. Mirrors ``PasskeyRegistrationUser``.
PasskeyRegistrationUser = dict  # {"id": str, "name": str, "displayName"?: str}

# Extensions resolver: either a literal dict or a callable returning one.
PasskeyExtensionsResolver = dict | Callable[..., Awaitable[dict | None] | dict | None]


@dataclass(frozen=True, slots=True)
class PasskeyRegistrationOptions:
    """Registration behaviour overrides (``PasskeyRegistrationOptions``)."""

    require_session: bool = True
    resolve_user: Callable[..., Any] | None = None
    after_verification: Callable[..., Any] | None = None
    extensions: PasskeyExtensionsResolver | None = None


@dataclass(frozen=True, slots=True)
class PasskeyAuthenticationOptions:
    """Authentication behaviour overrides (``PasskeyAuthenticationOptions``)."""

    extensions: PasskeyExtensionsResolver | None = None
    after_verification: Callable[..., Any] | None = None


@dataclass(frozen=True, slots=True)
class PasskeyAdvancedOptions:
    """Advanced options (``PasskeyOptions.advanced``)."""

    web_authn_challenge_cookie: str = "better-auth-passkey"


@dataclass(frozen=True, slots=True)
class PasskeyOptions:
    """Top-level passkey plugin options (``PasskeyOptions``).

    All fields are optional and mirror the upstream defaults:

    * ``rp_id`` defaults to the base URL hostname (or ``localhost``).
    * ``rp_name`` defaults to the app name.
    * ``origin`` defaults to ``None`` (taken from the request ``Origin`` header).
    """

    rp_id: str | None = None
    rp_name: str | None = None
    origin: str | list[str] | None = None
    authenticator_selection: dict | None = None
    advanced: PasskeyAdvancedOptions = field(default_factory=PasskeyAdvancedOptions)
    registration: PasskeyRegistrationOptions | None = None
    authentication: PasskeyAuthenticationOptions | None = None


__all__ = [
    "PasskeyAdvancedOptions",
    "PasskeyAuthenticationOptions",
    "PasskeyOptions",
    "PasskeyRegistrationOptions",
    "PasskeyRegistrationUser",
]
