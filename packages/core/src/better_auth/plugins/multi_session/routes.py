"""Multi-session endpoints + hooks.

The plugin stores the list of active device sessions in a signed cookie named
`better-auth.session_list`. The cookie value is a JSON array of
`{id, token}` records, signed with the HMAC scheme in `better_auth.cookies`.

Active session = whichever token currently lives in `better-auth.session_token`.
The list cookie tracks *all* sessions on this browser, including the active one.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any

from better_auth.api.endpoint import create_auth_endpoint
from better_auth.cookies import sign, verify
from better_auth.error import APIError
from better_auth.types.adapter import Where
from better_auth.types.context import EndpointContext
from better_auth.types.cookie import (
    SESSION_TOKEN_COOKIE,
    CookieAttributes,
)
from better_auth.types.endpoint import AuthEndpoint, EndpointOptions

SESSION_LIST_COOKIE = "better-auth.session_list"


@dataclass(frozen=True, slots=True)
class MultiSessionOptions:
    maximum: int = 5


# ----- helpers --------------------------------------------------------------


def _encode_list(records: list[dict[str, str]]) -> str:
    raw = json.dumps(records, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode_list(encoded: str) -> list[dict[str, str]]:
    pad = "=" * (-len(encoded) % 4)
    try:
        raw = base64.urlsafe_b64decode(encoded + pad)
        data = json.loads(raw)
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    cleaned: list[dict[str, str]] = []
    for item in data:
        if (
            isinstance(item, dict)
            and isinstance(item.get("id"), str)
            and isinstance(item.get("token"), str)
        ):
            cleaned.append({"id": item["id"], "token": item["token"]})
    return cleaned


def _read_list_cookie(ctx: EndpointContext) -> list[dict[str, str]]:
    raw = ctx.request.cookies.get(SESSION_LIST_COOKIE)
    if not raw:
        return []
    value = verify(raw, secret=ctx.auth.secret)
    if value is None:
        return []
    return _decode_list(value)


def _list_cookie_attrs(ctx: EndpointContext) -> CookieAttributes:
    return CookieAttributes(
        path="/",
        max_age=ctx.auth.options.session.expires_in,
        http_only=True,
        secure=ctx.auth.base_url.startswith("https"),
        same_site="lax",
    )


def _set_list(
    ctx: EndpointContext, records: list[dict[str, str]], opts: MultiSessionOptions
) -> None:
    # Enforce maximum (keep most-recent at head).
    if len(records) > opts.maximum:
        records = records[: opts.maximum]
    encoded = sign(_encode_list(records), secret=ctx.auth.secret)
    ctx.set_cookies.append((SESSION_LIST_COOKIE, encoded, _list_cookie_attrs(ctx)))


def _clear_list(ctx: EndpointContext) -> None:
    ctx.set_cookies.append((
        SESSION_LIST_COOKIE,
        "",
        CookieAttributes(path="/", max_age=0, http_only=True, secure=False, same_site="lax"),
    ))


def _active_token(ctx: EndpointContext) -> str | None:
    cookie = ctx.request.cookies.get(SESSION_TOKEN_COOKIE)
    if not cookie:
        return None
    return verify(cookie, secret=ctx.auth.secret)


def _session_cookie_attrs(ctx: EndpointContext) -> CookieAttributes:
    return CookieAttributes(
        path="/",
        max_age=ctx.auth.options.session.expires_in,
        http_only=True,
        secure=ctx.auth.base_url.startswith("https"),
        same_site="lax",
    )


# ----- body shapes ---------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SwitchBody:
    session_id: str


@dataclass(frozen=True, slots=True)
class RevokeBody:
    session_id: str


# ----- endpoint handlers ---------------------------------------------------


async def _list_handler(ctx: EndpointContext) -> dict[str, Any]:
    records = _read_list_cookie(ctx)
    if not records:
        # Fallback: if there is an active session, expose it as a single-entry list.
        if ctx.session is not None:
            user = await ctx.auth.adapter.find_one(
                model="user",
                where=(Where(field="id", value=ctx.session.user_id),),
            )
            return {
                "sessions": [
                    {
                        "id": ctx.session.id,
                        "userId": ctx.session.user_id,
                        "expiresAt": ctx.session.expires_at,
                        "isActive": True,
                        "user": user,
                    }
                ]
            }
        return {"sessions": []}

    active = _active_token(ctx)
    out: list[dict[str, Any]] = []
    now = int(time.time())
    for rec in records:
        row = await ctx.auth.adapter.find_one(
            model="session",
            where=(Where(field="token", value=rec["token"]),),
        )
        if not row:
            continue
        if int(row.get("expiresAt", 0)) < now:
            continue
        user = await ctx.auth.adapter.find_one(
            model="user",
            where=(Where(field="id", value=row["userId"]),),
        )
        out.append({
            "id": row["id"],
            "userId": row["userId"],
            "expiresAt": row["expiresAt"],
            "isActive": active == rec["token"],
            "user": user,
        })
    return {"sessions": out}


async def _switch_handler(ctx: EndpointContext) -> dict[str, Any]:
    body: SwitchBody = ctx.body
    records = _read_list_cookie(ctx)
    target = next((r for r in records if r["id"] == body.session_id), None)
    if target is None:
        raise APIError(401, "INVALID_SESSION_TOKEN")

    row = await ctx.auth.adapter.find_one(
        model="session",
        where=(Where(field="token", value=target["token"]),),
    )
    if not row or int(row.get("expiresAt", 0)) < int(time.time()):
        # purge stale entry
        new_records = [r for r in records if r["id"] != target["id"]]
        _set_list(ctx, new_records, ctx.auth.plugin_state.get("multi_session_options", MultiSessionOptions()))
        raise APIError(401, "INVALID_SESSION_TOKEN")

    # Move target to head of list (becomes active).
    new_records = [target] + [r for r in records if r["id"] != target["id"]]
    opts = ctx.auth.plugin_state.get("multi_session_options", MultiSessionOptions())
    _set_list(ctx, new_records, opts)
    signed = sign(target["token"], secret=ctx.auth.secret)
    ctx.set_cookies.append((SESSION_TOKEN_COOKIE, signed, _session_cookie_attrs(ctx)))
    return {"session": {"id": row["id"], "userId": row["userId"], "expiresAt": row["expiresAt"]}}


async def _revoke_handler(ctx: EndpointContext) -> dict[str, Any]:
    body: RevokeBody = ctx.body
    records = _read_list_cookie(ctx)
    target = next((r for r in records if r["id"] == body.session_id), None)
    if target is None:
        raise APIError(404, "INVALID_SESSION_TOKEN")

    active = _active_token(ctx)
    is_active = target["token"] == active

    # Always delete the session row.
    await ctx.auth.adapter.delete_many(
        model="session",
        where=(Where(field="token", value=target["token"]),),
    )

    new_records = [r for r in records if r["id"] != target["id"]]
    opts = ctx.auth.plugin_state.get("multi_session_options", MultiSessionOptions())

    if is_active:
        # Promote next session if any, else clear cookies.
        if new_records:
            promoted = new_records[0]
            signed = sign(promoted["token"], secret=ctx.auth.secret)
            ctx.set_cookies.append((SESSION_TOKEN_COOKIE, signed, _session_cookie_attrs(ctx)))
            _set_list(ctx, new_records, opts)
        else:
            ctx.set_cookies.append((
                SESSION_TOKEN_COOKIE,
                "",
                CookieAttributes(path="/", max_age=0, http_only=True, secure=False, same_site="lax"),
            ))
            _clear_list(ctx)
    else:
        if new_records:
            _set_list(ctx, new_records, opts)
        else:
            _clear_list(ctx)

    return {"success": True}


# ----- after-hooks: track sign-in / sign-out -------------------------------


def match_sign_in(ctx: EndpointContext) -> bool:
    return ctx.request.path in ("/sign-in/email", "/sign-up/email")


def match_sign_out(ctx: EndpointContext) -> bool:
    return ctx.request.path == "/sign-out"


def after_sign_in_hook(opts: MultiSessionOptions):
    async def handler(ctx: EndpointContext, result: object) -> object | None:
        # The handler emits a `session_token` Set-Cookie via ctx.set_cookies.
        new_token: str | None = None
        new_id: str | None = None
        # Find the signed session_token cookie just emitted by the handler.
        for name, value, _attrs in ctx.set_cookies:
            if name == SESSION_TOKEN_COOKIE and value:
                token = verify(value, secret=ctx.auth.secret)
                if token:
                    new_token = token
                    break
        if not new_token and isinstance(result, dict):
            session = result.get("session")
            if isinstance(session, dict) and isinstance(session.get("id"), str):
                new_id = session["id"]
                row = await ctx.auth.adapter.find_one(
                    model="session",
                    where=(Where(field="id", value=new_id),),
                )
                if row:
                    new_token = row.get("token")
        if not new_token:
            return None
        if new_id is None:
            row = await ctx.auth.adapter.find_one(
                model="session",
                where=(Where(field="token", value=new_token),),
            )
            if not row:
                return None
            new_id = row["id"]

        records = _read_list_cookie(ctx)
        # Remove any duplicate token & put this one at the head.
        records = [r for r in records if r["token"] != new_token and r["id"] != new_id]
        records.insert(0, {"id": new_id, "token": new_token})
        _set_list(ctx, records, opts)
        return None

    return handler


def after_sign_out_hook(opts: MultiSessionOptions):
    async def handler(ctx: EndpointContext, result: object) -> object | None:
        # Sign-out already revoked the active session and emitted clearing cookies.
        # We need to either promote the next session in the list, or clear the list.
        active_token = ctx.session.token if ctx.session is not None else None
        records = _read_list_cookie(ctx)
        if active_token:
            records = [r for r in records if r["token"] != active_token]

        if records:
            promoted = records[0]
            # Overwrite the clearing cookie with the promoted token.
            ctx.set_cookies = [c for c in ctx.set_cookies if c[0] != SESSION_TOKEN_COOKIE]
            signed = sign(promoted["token"], secret=ctx.auth.secret)
            ctx.set_cookies.append((SESSION_TOKEN_COOKIE, signed, _session_cookie_attrs(ctx)))
            _set_list(ctx, records, opts)
        else:
            _clear_list(ctx)
        return None

    return handler


def on_response_factory(opts: MultiSessionOptions):
    async def on_response(ctx: EndpointContext, result: object) -> None:
        # Stash options so handlers can read them without import gymnastics.
        ctx.auth.plugin_state.setdefault("multi_session_options", opts)

    return on_response


# ----- endpoint table -----------------------------------------------------


LIST = create_auth_endpoint(
    "/multi-session/list",
    EndpointOptions(method="GET"),
    _list_handler,
)

SWITCH = create_auth_endpoint(
    "/multi-session/switch",
    EndpointOptions(method="POST", body=SwitchBody),
    _switch_handler,
)

REVOKE = create_auth_endpoint(
    "/multi-session/revoke",
    EndpointOptions(method="POST", body=RevokeBody),
    _revoke_handler,
)


ALL: tuple[AuthEndpoint, ...] = (LIST, SWITCH, REVOKE)
