"""One-time-token endpoint handlers.

Mirrors `reference/packages/better-auth/src/plugins/one-time-token/index.ts`.

The plugin issues a short-lived disposable token bound to a *session token*,
persisted in the `verification` table with identifier `one-time-token:<storedToken>`.
A subsequent `POST /one-time-token/verify` call consumes the row, looks up the
bound session, (optionally) sets the session cookie, and returns the full
`{session, user}` object.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import string
import time
from collections.abc import Awaitable, Callable
from typing import Any, cast

from pydantic import BaseModel

from kernia.api.endpoint import create_auth_endpoint
from kernia.cookies import sign
from kernia.error import APIError
from kernia.types.adapter import Where
from kernia.types.context import EndpointContext
from kernia.types.cookie import SESSION_TOKEN_COOKIE, CookieAttributes
from kernia.types.endpoint import AuthEndpoint, EndpointOptions

_DEFAULT_EXPIRES_IN_MIN = 3  # minutes — matches the reference default
_ALPHABET = string.ascii_letters + string.digits


def _now() -> int:
    return int(time.time())


def generate_random_string(length: int = 32) -> str:
    """A-Za-z0-9 token of the requested length (mirrors generateRandomString)."""
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def default_key_hasher(token: str) -> str:
    """SHA-256 → base64url (no padding). Mirrors `defaultKeyHasher`."""
    digest = hashlib.sha256(token.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


class GenerateOneTimeTokenBody(BaseModel):
    # Kept for backwards compatibility; upstream generate takes no body.
    pass


class VerifyOneTimeTokenBody(BaseModel):
    token: str


class OneTimeTokenOptions:
    """Runtime options for the one-time-token plugin."""

    def __init__(
        self,
        *,
        expires_in: int = _DEFAULT_EXPIRES_IN_MIN,
        disable_client_request: bool = False,
        generate_token: Callable[..., Awaitable[str]] | None = None,
        disable_set_session_cookie: bool = False,
        store_token: Any = "plain",
        set_ott_header_on_new_session: bool = False,
    ) -> None:
        self.expires_in = expires_in
        self.disable_client_request = disable_client_request
        self.generate_token = generate_token
        self.disable_set_session_cookie = disable_set_session_cookie
        self.store_token = store_token
        self.set_ott_header_on_new_session = set_ott_header_on_new_session


async def _store_token(opts: OneTimeTokenOptions, token: str) -> str:
    store = opts.store_token
    if store == "hashed":
        return default_key_hasher(token)
    if isinstance(store, dict) and store.get("type") == "custom-hasher":
        return cast("str", await store["hash"](token))
    return token


async def generate_token_for_session(
    opts: OneTimeTokenOptions,
    ctx: EndpointContext,
    session: dict[str, Any],
) -> str:
    """Create a verification row binding a fresh token to a session token."""
    if opts.generate_token is not None:
        token = await opts.generate_token(session, ctx)
    else:
        token = generate_random_string(32)
    expires_at = _now() + opts.expires_in * 60
    stored_token = await _store_token(opts, token)
    await ctx.auth.adapter.create(
        model="verification",
        data={
            "identifier": f"one-time-token:{stored_token}",
            "value": session["session"]["token"],
            "expiresAt": expires_at,
            "createdAt": _now(),
            "updatedAt": _now(),
        },
    )
    return token


def _make_generate(
    opts: OneTimeTokenOptions,
) -> Callable[[EndpointContext], Awaitable[dict[str, object]]]:
    async def _generate(ctx: EndpointContext) -> dict[str, object]:
        # A present request object means this is a client (HTTP) request.
        if opts.disable_client_request and ctx.request is not None:
            raise APIError(400, "BAD_REQUEST", message="Client requests are disabled")
        if ctx.session is None:
            raise APIError(401, "UNAUTHORIZED")
        user_row = await ctx.auth.adapter.find_one(
            model="user", where=(Where(field="id", value=ctx.session.user_id),)
        )
        session_payload = {
            "session": {
                "id": ctx.session.id,
                "token": ctx.session.token,
                "userId": ctx.session.user_id,
                "expiresAt": ctx.session.expires_at,
            },
            "user": user_row or {"id": ctx.session.user_id},
        }
        token = await generate_token_for_session(opts, ctx, session_payload)
        return {"token": token}

    return _generate


def _make_verify(
    opts: OneTimeTokenOptions,
) -> Callable[[EndpointContext], Awaitable[dict[str, object]]]:
    async def _verify(ctx: EndpointContext) -> dict[str, object]:
        body: VerifyOneTimeTokenBody = ctx.body
        stored_token = await _store_token(opts, body.token)
        identifier = f"one-time-token:{stored_token}"
        where = (Where(field="identifier", value=identifier),)

        record = await ctx.auth.adapter.find_one(model="verification", where=where)
        if not record:
            raise APIError(400, "BAD_REQUEST", message="Invalid token")
        # Consume the token (single use), regardless of expiry.
        await ctx.auth.adapter.delete_many(model="verification", where=where)

        if int(record.get("expiresAt", 0)) < _now():
            raise APIError(400, "BAD_REQUEST", message="Token expired")

        session_token = str(record["value"])
        session_row = await ctx.auth.adapter.find_one(
            model="session", where=(Where(field="token", value=session_token),)
        )
        if not session_row:
            raise APIError(400, "BAD_REQUEST", message="Session not found")

        user_row = await ctx.auth.adapter.find_one(
            model="user", where=(Where(field="id", value=session_row["userId"]),)
        )

        # Check expiry BEFORE setting the session cookie (upstream order) — an
        # expired session must never be (re)issued as a credential, not even on
        # an error response.
        if int(session_row.get("expiresAt", 0)) < _now():
            raise APIError(400, "BAD_REQUEST", message="Session expired")

        if not opts.disable_set_session_cookie:
            signed = sign(session_token, secret=ctx.auth.secret)
            attrs = CookieAttributes(
                path="/",
                max_age=ctx.auth.options.session.expires_in,
                http_only=True,
                secure=ctx.auth.base_url.startswith("https"),
                same_site="lax",
            )
            ctx.set_cookies.append((SESSION_TOKEN_COOKIE, signed, attrs))

        return {"session": session_row, "user": user_row}

    return _verify


def build_endpoints(opts: OneTimeTokenOptions) -> tuple[AuthEndpoint, ...]:
    generate = create_auth_endpoint(
        "/one-time-token/generate",
        EndpointOptions(method="GET", requires_session=True),
        _make_generate(opts),
    )
    verify = create_auth_endpoint(
        "/one-time-token/verify",
        EndpointOptions(method="POST", body=VerifyOneTimeTokenBody),
        _make_verify(opts),
    )
    return (generate, verify)
