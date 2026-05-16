"""Anonymous plugin endpoint handler.

Mirrors `reference/packages/better-auth/src/plugins/anonymous/index.ts`.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass

from better_auth.api.endpoint import create_auth_endpoint
from better_auth.context import create_session
from better_auth.error import APIError
from better_auth.types.context import EndpointContext
from better_auth.types.endpoint import AuthEndpoint, EndpointOptions


@dataclass(frozen=True, slots=True)
class SignInAnonymousBody:
    name: str | None = None


async def _sign_in_anonymous(ctx: EndpointContext) -> dict[str, object]:
    # Reject if the caller already has an anonymous session.
    if ctx.session is not None:
        existing_user = await ctx.auth.adapter.find_one(
            model="user",
            where=(),
        )
        # We cannot easily query by id without `Where`; use a direct lookup.
        from better_auth.types.adapter import Where

        existing_user = await ctx.auth.adapter.find_one(
            model="user",
            where=(Where(field="id", value=ctx.session.user_id),),
        )
        if existing_user and existing_user.get("isAnonymous"):
            raise APIError(
                400,
                "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY",
            )

    body: SignInAnonymousBody | None = ctx.body if ctx.body else None
    name = (body.name if body else None) or "Anonymous"
    anon_id = secrets.token_urlsafe(12)
    email = f"temp-{anon_id}@anonymous.local"
    now = int(time.time())

    user = await ctx.auth.adapter.create(
        model="user",
        data={
            "email": email,
            "name": name,
            "emailVerified": False,
            "isAnonymous": True,
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


SIGN_IN_ANONYMOUS = create_auth_endpoint(
    "/sign-in/anonymous",
    EndpointOptions(method="POST", body=SignInAnonymousBody),
    _sign_in_anonymous,
)


ALL: tuple[AuthEndpoint, ...] = (SIGN_IN_ANONYMOUS,)
