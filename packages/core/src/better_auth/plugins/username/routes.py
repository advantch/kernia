"""Username plugin endpoint handlers.

Mirrors `reference/packages/better-auth/src/plugins/username/index.ts`.

Two architectural notes vs. the JS reference:

  * Upstream has no `/sign-up/username` endpoint; usernames are attached to the
    shared `/sign-up/email` body and persisted via `databaseHooks`. The Python
    `/sign-up/email` body is a fixed dataclass that drops unknown fields, so this
    port keeps a dedicated `/sign-up/username` endpoint instead. The validation
    rules, normalization, and error codes match upstream.
  * Per-instance options (min/max length, validators, normalizers) are stashed in
    `ctx.auth.plugin_state["username"]` by the plugin `init` so multiple `init()`
    instances can carry different config.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from better_auth.api.endpoint import create_auth_endpoint
from better_auth.context import create_session
from better_auth.crypto import hash_password, verify_password
from better_auth.error import APIError
from better_auth.types.adapter import Where
from better_auth.types.context import EndpointContext
from better_auth.types.endpoint import AuthEndpoint, EndpointOptions

_DEFAULT_RE = re.compile(r"^[a-zA-Z0-9_.]+$")


@dataclass(frozen=True, slots=True)
class UsernameOptions:
    """Resolved username options. Mirrors upstream `UsernameOptions`."""

    min_username_length: int = 3
    max_username_length: int = 30
    username_validator: Callable[[str], bool] | None = None
    display_username_validator: Callable[[str], bool] | None = None
    username_normalization: Callable[[str], str] | bool | None = None
    display_username_normalization: Callable[[str], str] | bool | None = None
    username_validation_order: str = "pre-normalization"
    display_username_validation_order: str = "pre-normalization"

    def normalize(self, username: str) -> str:
        if self.username_normalization is False:
            return username
        if callable(self.username_normalization):
            return self.username_normalization(username)
        return username.lower()

    def normalize_display(self, display_username: str) -> str:
        if callable(self.display_username_normalization):
            return self.display_username_normalization(display_username)
        return display_username


_DEFAULT = UsernameOptions()


def _opts(ctx: EndpointContext) -> UsernameOptions:
    opts = ctx.auth.plugin_state.get("username")
    return opts if isinstance(opts, UsernameOptions) else _DEFAULT


def _default_validator(username: str) -> bool:
    return bool(_DEFAULT_RE.match(username))


def _validate(opts: UsernameOptions, username: str, *, status: int) -> None:
    if len(username) < opts.min_username_length:
        raise APIError(status, "USERNAME_TOO_SHORT")
    if len(username) > opts.max_username_length:
        raise APIError(status, "USERNAME_TOO_LONG")
    validator = opts.username_validator or _default_validator
    if not validator(username):
        raise APIError(status, "INVALID_USERNAME")


# ----- request body shapes -----


@dataclass(frozen=True, slots=True)
class SignUpUsernameBody:
    username: str
    password: str
    email: str | None = None
    name: str | None = None
    display_username: str | None = None


@dataclass(frozen=True, slots=True)
class SignInUsernameBody:
    username: str
    password: str
    remember_me: bool = True
    callback_url: str | None = None


@dataclass(frozen=True, slots=True)
class IsUsernameAvailableBody:
    username: str


# ----- handlers -----


async def _sign_up_username(ctx: EndpointContext) -> dict[str, object]:
    body: SignUpUsernameBody = ctx.body
    opts = _opts(ctx)

    normalized = opts.normalize(body.username)
    to_validate = (
        normalized
        if opts.username_validation_order == "post-normalization"
        else body.username
    )
    _validate(opts, to_validate, status=422)

    if len(body.password) < ctx.auth.options.email_and_password.min_password_length:
        raise APIError(400, "PASSWORD_TOO_SHORT")

    display = opts.normalize_display(body.display_username or body.username)

    if opts.display_username_validator is not None:
        if not opts.display_username_validator(body.display_username or body.username):
            raise APIError(400, "INVALID_DISPLAY_USERNAME")

    existing = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="username", value=normalized),),
    )
    if existing is not None:
        raise APIError(409, "USERNAME_IS_ALREADY_TAKEN")

    if body.email:
        existing_email = await ctx.auth.adapter.find_one(
            model="user",
            where=(Where(field="email", value=body.email),),
        )
        if existing_email is not None:
            raise APIError(409, "EMAIL_ALREADY_IN_USE")

    import time

    now = int(time.time())
    email = body.email or f"{normalized}@username.local"
    user = await ctx.auth.adapter.create(
        model="user",
        data={
            "email": email,
            "name": body.name,
            "username": normalized,
            "displayUsername": display,
            "emailVerified": False,
            "createdAt": now,
            "updatedAt": now,
        },
    )
    await ctx.auth.adapter.create(
        model="account",
        data={
            "userId": user["id"],
            "accountId": user["id"],
            "providerId": "credential",
            "password": hash_password(body.password),
            "createdAt": now,
            "updatedAt": now,
        },
    )

    session, cookies = await create_session(
        ctx.auth,
        user_id=user["id"],
        ip_address=ctx.request.headers.get("x-forwarded-for"),
        user_agent=ctx.request.headers.get("user-agent"),
    )
    ctx.set_cookies.extend(cookies)
    return {
        "user": user,
        "session": {"id": session.id, "expiresAt": session.expires_at},
    }


async def _sign_in_username(ctx: EndpointContext) -> dict[str, object]:
    body: SignInUsernameBody = ctx.body
    if not body.username or not body.password:
        raise APIError(401, "INVALID_USERNAME_OR_PASSWORD")
    opts = _opts(ctx)

    username = (
        opts.normalize(body.username)
        if opts.username_validation_order == "pre-normalization"
        else body.username
    )
    _validate(opts, username, status=422)

    user = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="username", value=opts.normalize(username)),),
    )
    if not user:
        # Hash to mitigate timing side channel.
        hash_password(body.password)
        raise APIError(401, "INVALID_USERNAME_OR_PASSWORD")

    account = await ctx.auth.adapter.find_one(
        model="account",
        where=(
            Where(field="userId", value=user["id"]),
            Where(field="providerId", value="credential"),
        ),
    )
    if not account or not account.get("password"):
        raise APIError(401, "INVALID_USERNAME_OR_PASSWORD")
    if not verify_password(body.password, account["password"]):
        raise APIError(401, "INVALID_USERNAME_OR_PASSWORD")

    if (
        ctx.auth.options.email_and_password.require_email_verification
        and not user.get("emailVerified")
    ):
        raise APIError(403, "EMAIL_NOT_VERIFIED")

    session, cookies = await create_session(
        ctx.auth,
        user_id=user["id"],
        ip_address=ctx.request.headers.get("x-forwarded-for"),
        user_agent=ctx.request.headers.get("user-agent"),
        remember_me=body.remember_me,
    )
    ctx.set_cookies.extend(cookies)
    if body.callback_url:
        ctx.response_headers["Location"] = body.callback_url
    return {
        "redirect": bool(body.callback_url),
        "token": session.token,
        "url": body.callback_url,
        "user": {
            "id": user["id"],
            "username": user.get("username"),
            "displayUsername": user.get("displayUsername"),
            "email": user.get("email"),
        },
        "session": {"id": session.id, "expiresAt": session.expires_at},
    }


async def _is_username_available(ctx: EndpointContext) -> dict[str, object]:
    body: IsUsernameAvailableBody = ctx.body
    opts = _opts(ctx)
    username = body.username
    if not username:
        raise APIError(422, "INVALID_USERNAME")
    _validate(opts, username, status=422)

    user = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="username", value=opts.normalize(username)),),
    )
    return {"available": user is None}


SIGN_UP_USERNAME = create_auth_endpoint(
    "/sign-up/username",
    EndpointOptions(method="POST", body=SignUpUsernameBody),
    _sign_up_username,
)

SIGN_IN_USERNAME = create_auth_endpoint(
    "/sign-in/username",
    EndpointOptions(method="POST", body=SignInUsernameBody),
    _sign_in_username,
)

IS_USERNAME_AVAILABLE = create_auth_endpoint(
    "/is-username-available",
    EndpointOptions(method="POST", body=IsUsernameAvailableBody),
    _is_username_available,
)


ALL: tuple[AuthEndpoint, ...] = (
    SIGN_UP_USERNAME,
    SIGN_IN_USERNAME,
    IS_USERNAME_AVAILABLE,
)
