"""Deprecated shim for the standalone OAuth2.1 / OIDC provider.

Mirrors better-auth upstream, where the in-tree ``oidc-provider`` plugin is
**deprecated** in favour of the dedicated ``@better-auth/oauth-provider`` package
(the full OAuth 2.1 + OpenID Connect issuer: PKCE, refresh rotation with reuse
detection, RFC 7662 introspection, RFC 7009 revocation, RFC 8414 metadata,
dynamic client registration, …).

The Python port follows the same split: the real implementation lives in the
``better_auth_oauth_provider`` package. This module remains importable so legacy
call sites keep working, but every entry point emits a :class:`DeprecationWarning`
and delegates to ``better_auth_oauth_provider``.

Migration::

    # before (deprecated)
    from better_auth.plugins.oidc_provider import oidc_provider

    # after
    from better_auth_oauth_provider import oauth_provider, OAuthProviderOptions

Importing this shim does *not* pull in the provider package; the delegation is
lazy so core has no hard dependency on the standalone package.
"""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from better_auth.types.plugin import BetterAuthPlugin

_DEPRECATION = (
    "better_auth.plugins.oidc_provider is deprecated; install and use the "
    "`better_auth_oauth_provider` package instead "
    "(from better_auth_oauth_provider import oauth_provider, OAuthProviderOptions)."
)


def _require_oauth_provider() -> Any:
    try:
        import better_auth_oauth_provider as mod
    except ImportError as exc:  # pragma: no cover - depends on install layout
        raise ImportError(
            "The oidc_provider shim delegates to the `better_auth_oauth_provider` "
            "package, which is not installed. Add it to your dependencies: "
            "`pip install better-auth-oauth-provider`."
        ) from exc
    return mod


def oidc_provider(options: Any) -> BetterAuthPlugin:
    """Deprecated. Delegates to ``better_auth_oauth_provider.oauth_provider``.

    ``options`` may be an ``OAuthProviderOptions`` (passed through) or any object
    accepted by the standalone factory.
    """
    warnings.warn(_DEPRECATION, DeprecationWarning, stacklevel=2)
    mod = _require_oauth_provider()
    return mod.oauth_provider(options)  # type: ignore[no-any-return]


def __getattr__(name: str) -> Any:
    """Re-export the standalone package's public names (e.g. ``OAuthProviderOptions``).

    Lets ``from better_auth.plugins.oidc_provider import OAuthProviderOptions``
    keep working without a hard import at module load.
    """
    if name in {"OAuthProviderOptions", "OAuthClient", "create_client"}:
        warnings.warn(_DEPRECATION, DeprecationWarning, stacklevel=2)
        return getattr(_require_oauth_provider(), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["oidc_provider"]
