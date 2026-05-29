"""Multi-session plugin construction.

Maintains a `better-auth.session_list` signed cookie containing a JSON list of
`{id, token}` records — one entry per signed-in user on this browser. The active
session is whichever token is currently set in `better-auth.session_token`.

Mirrors `reference/packages/better-auth/src/plugins/multi-session/index.ts` but
uses a single list cookie rather than one `_multi-<token>` cookie per session
(simpler, matches Lane C3 spec).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from better_auth.plugins.multi_session import routes
from better_auth.types.endpoint import AuthEndpoint
from better_auth.types.hooks import AfterHook, PluginHooks
from better_auth.types.plugin import BetterAuthPlugin, PluginSchema, RateLimitRule

MULTI_SESSION_ERROR_CODES: Mapping[str, str] = {
    "INVALID_SESSION_TOKEN": "The session token is invalid or expired.",
    "MULTI_SESSION_LIMIT_REACHED": "Reached the maximum number of concurrent sessions.",
}


@dataclass(frozen=True, slots=True)
class _MultiSessionPlugin:
    id: str = "multi-session"
    version: str | None = None
    schema: PluginSchema | None = None
    endpoints: tuple[AuthEndpoint, ...] = field(default_factory=lambda: routes.ALL)
    middlewares: None = None
    hooks: PluginHooks | None = None
    on_request: None = None
    on_response: Any = None
    rate_limit: tuple[RateLimitRule, ...] = ()
    error_codes: Mapping[str, str] = field(
        default_factory=lambda: dict(MULTI_SESSION_ERROR_CODES)
    )
    init: None = None
    options: routes.MultiSessionOptions = field(
        default_factory=lambda: routes.MultiSessionOptions()
    )


def multi_session(*, maximum: int = 5) -> BetterAuthPlugin:
    """Construct the multi-session plugin.

    Args:
        maximum: maximum number of concurrent device sessions kept in the
            session_list cookie. Older entries are evicted when this is exceeded.
    """
    opts = routes.MultiSessionOptions(maximum=maximum)
    return _MultiSessionPlugin(
        hooks=PluginHooks(
            after=(
                AfterHook(match=routes.match_sign_in, handler=routes.after_sign_in_hook(opts)),
                AfterHook(match=routes.match_sign_out, handler=routes.after_sign_out_hook(opts)),
            ),
        ),
        on_response=routes.on_response_factory(opts),
        options=opts,
    )  # type: ignore[return-value]
