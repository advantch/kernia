"""anonymous plugin — port of `reference/packages/better-auth/src/plugins/anonymous/`.

Provides ephemeral, account-less sign-in for first-time visitors. Hooks into the
email-password and magic-link sign-in/sign-up flows so that when an anonymous user
later "graduates" to a real account, the anonymous user row is collapsed into the
new user (via an optional `on_link` callback) and then deleted.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from better_auth.plugins.anonymous import routes
from better_auth.types.adapter import FieldDef, Where
from better_auth.types.context import EndpointContext
from better_auth.types.endpoint import AuthEndpoint
from better_auth.types.hooks import AfterHook, BeforeHook, PluginHooks
from better_auth.types.plugin import BetterAuthPlugin, PluginSchema, RateLimitRule

ANONYMOUS_ERROR_CODES: Mapping[str, str] = {
    "INVALID_EMAIL_FORMAT": "Email was not generated in a valid format",
    "FAILED_TO_CREATE_USER": "Failed to create user",
    "COULD_NOT_CREATE_SESSION": "Could not create session",
    "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY": (
        "Anonymous users cannot sign in again anonymously"
    ),
    "FAILED_TO_DELETE_ANONYMOUS_USER": "Failed to delete anonymous user",
    "FAILED_TO_DELETE_ANONYMOUS_USER_SESSIONS": (
        "Failed to delete anonymous user sessions"
    ),
    "USER_IS_NOT_ANONYMOUS": "User is not anonymous",
    "DELETE_ANONYMOUS_USER_DISABLED": "Deleting anonymous users is disabled",
}


_ANONYMOUS_USER_FIELDS: tuple[FieldDef, ...] = (
    FieldDef("isAnonymous", "boolean", required=False, default=False),
)


OnLinkCallback = Callable[[dict[str, Any], dict[str, Any], EndpointContext], Awaitable[None]]


_LINK_TARGET_PATHS = {
    "/sign-in/email",
    "/sign-up/email",
    "/sign-in/username",
    "/sign-up/username",
    "/magic-link/verify",
    "/sign-in/magic-link",
    "/sign-in/passkey",
    "/passkey/authenticate/finish",
}


def _link_target_matcher(ctx: EndpointContext) -> bool:
    return ctx.request.path in _LINK_TARGET_PATHS


def _request_key(ctx: EndpointContext) -> int:
    return id(ctx.request)


def _make_before_hook(on_link: OnLinkCallback | None) -> BeforeHook:
    async def before(ctx: EndpointContext) -> None:
        if ctx.session is None:
            return
        user = await ctx.auth.adapter.find_one(
            model="user",
            where=(Where(field="id", value=ctx.session.user_id),),
        )
        if user and user.get("isAnonymous"):
            ctx.auth.plugin_state.setdefault("_anonymous_pending", {})[
                _request_key(ctx)
            ] = {"user": user, "on_link": on_link}

    return BeforeHook(match=_link_target_matcher, handler=before)


def _make_after_hook() -> AfterHook:
    async def after(ctx: EndpointContext, result: object) -> object | None:
        state = ctx.auth.plugin_state.get("_anonymous_pending", {})
        entry = state.pop(_request_key(ctx), None)
        if not entry:
            return None
        anon_user = entry["user"]
        on_link: OnLinkCallback | None = entry["on_link"]
        new_user: dict[str, Any] | None = None
        if isinstance(result, dict):
            maybe_user = result.get("user")
            if isinstance(maybe_user, dict) and maybe_user.get("id") != anon_user["id"]:
                new_user = maybe_user
        if not new_user:
            return None
        if on_link is not None:
            await on_link(anon_user, new_user, ctx)

        opts = ctx.auth.plugin_state.get("anonymous", {}) or {}
        # Mirror upstream guard: skip cleanup when deletion is disabled, the new
        # session is the same user, or the new user is itself anonymous.
        if (
            bool(opts.get("disable_delete_anonymous_user", False))
            or new_user.get("id") == anon_user["id"]
            or bool(new_user.get("isAnonymous"))
        ):
            return None
        await ctx.auth.adapter.delete_many(
            model="session",
            where=(Where(field="userId", value=anon_user["id"]),),
        )
        await ctx.auth.adapter.delete(
            model="user",
            where=(Where(field="id", value=anon_user["id"]),),
        )
        return None

    return AfterHook(match=_link_target_matcher, handler=after)


@dataclass(frozen=True, slots=True)
class _AnonymousPlugin:
    options: Mapping[str, Any] = field(default_factory=dict)
    id: str = "anonymous"
    version: str | None = None
    schema: PluginSchema | None = field(
        default_factory=lambda: PluginSchema(extend={"user": _ANONYMOUS_USER_FIELDS})
    )
    endpoints: tuple[AuthEndpoint, ...] = field(default_factory=lambda: routes.ALL)
    middlewares: None = None
    hooks: PluginHooks | None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = (
        RateLimitRule(path="/sign-in/anonymous", window=60, max=10),
    )
    error_codes: Mapping[str, str] = field(
        default_factory=lambda: dict(ANONYMOUS_ERROR_CODES)
    )

    async def init(self, ctx: Any) -> None:
        ctx.plugin_state["anonymous"] = dict(self.options)


def anonymous(
    on_link: OnLinkCallback | None = None,
    *,
    email_domain_name: str | None = None,
    generate_random_email: Callable[[], Any] | None = None,
    generate_name: Callable[[EndpointContext], Any] | None = None,
    disable_delete_anonymous_user: bool = False,
) -> BetterAuthPlugin:
    """Construct the anonymous plugin.

    Pass `on_link` to migrate domain data from the anonymous user into the new
    real user when an anonymous session converts via a credential sign-in.
    """
    hooks = PluginHooks(
        before=(_make_before_hook(on_link),),
        after=(_make_after_hook(),),
    )
    options: dict[str, Any] = {
        "disable_delete_anonymous_user": disable_delete_anonymous_user,
    }
    if email_domain_name is not None:
        options["email_domain_name"] = email_domain_name
    if generate_random_email is not None:
        options["generate_random_email"] = generate_random_email
    if generate_name is not None:
        options["generate_name"] = generate_name
    return _AnonymousPlugin(options=options, hooks=hooks)  # type: ignore[return-value, call-arg]


__all__ = ["ANONYMOUS_ERROR_CODES", "anonymous"]
