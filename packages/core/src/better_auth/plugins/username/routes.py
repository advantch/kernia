"""Username plugin endpoint handlers.

Mirrors `reference/packages/better-auth/src/plugins/username/index.ts`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from better_auth.api.endpoint import create_auth_endpoint
from better_auth.context import create_session
from better_auth.crypto import hash_password, verify_password
from better_auth.error import APIError
from better_auth.types.adapter import Where
from better_auth.types.context import EndpointContext
from better_auth.types.endpoint import AuthEndpoint, EndpointOptions


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


def _normalize(username: str) -> str:
    return username.lower()


def _validate(username: str) -> None:
    if len(username) < 3:
        raise APIError(422, "USERNAME_TOO_SHORT")
    if len(username) > 30:
        raise APIError(422, "USERNAME_TOO_LONG")
    # default validator: alphanumeric + underscore + dot
    for c in username:
        if not (c.isalnum() or c in "_."):
            raise APIError(422, "INVALID_USERNAME")


async def _sign_up_username(ctx: EndpointContext) -> dict[str, object]:
    body: SignUpUsernameBody = ctx.body
    _validate(body.username)

    if len(body.password) < ctx.auth.options.email_and_password.min_password_length:
        raise APIError(400, "PASSWORD_TOO_SHORT")

    normalized = _normalize(body.username)
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

    now = int(time.time())
    email = body.email or f"{normalized}@username.local"
    user = await ctx.auth.adapter.create(
        model="user",
        data={
            "email": email,
            "name": body.name,
            "username": normalized,
            "displayUsername": body.display_username or body.username,
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
    _validate(body.username)
    normalized = _normalize(body.username)

    user = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="username", value=normalized),),
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

    session, cookies = await create_session(
        ctx.auth,
        user_id=user["id"],
        ip_address=ctx.request.headers.get("x-forwarded-for"),
        user_agent=ctx.request.headers.get("user-agent"),
        remember_me=body.remember_me,
    )
    ctx.set_cookies.extend(cookies)
    return {
        "user": {
            "id": user["id"],
            "username": user.get("username"),
            "displayUsername": user.get("displayUsername"),
            "email": user.get("email"),
        },
        "session": {"id": session.id, "expiresAt": session.expires_at},
    }


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


ALL: tuple[AuthEndpoint, ...] = (SIGN_UP_USERNAME, SIGN_IN_USERNAME)
