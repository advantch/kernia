"""Device-authorization endpoints — RFC 8628.

Endpoints:
  * POST `/device/code`   — initiate; client receives device_code + user_code.
  * POST `/device/token`  — client polls; gets `access_token` once approved.
  * GET  `/device`        — user-facing landing page (returns user_code + status).
  * POST `/device/approve` — authenticated user approves a user_code.
  * POST `/device/deny`    — authenticated user denies a user_code.

User-code charset is restricted to characters that survive whiteboard transcription:
`BCDFGHJKLMNPQRSTVWXZ` (consonants, no vowels, no ambiguous shapes).
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from kernia.api.endpoint import create_auth_endpoint
from kernia.context import create_session
from kernia.error import APIError
from kernia.types.adapter import Where
from kernia.types.context import EndpointContext
from kernia.types.endpoint import AuthEndpoint, EndpointOptions


# Human-friendly charset: no vowels (filters most accidental words), no 0/O/1/I.
USER_CODE_CHARSET = "BCDFGHJKLMNPQRSTVWXZ"
DEVICE_CODE_CHARSET = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)


@dataclass(frozen=True, slots=True)
class DeviceAuthorizationOptions:
    expires_in: int = 600  # seconds
    interval: int = 5  # seconds
    user_code_length: int = 8
    device_code_length: int = 40
    verification_uri: str | None = None


# Module-level options register so the endpoint table doesn't need closure state.
_options: DeviceAuthorizationOptions = DeviceAuthorizationOptions()


def configure(opts: DeviceAuthorizationOptions) -> None:
    global _options
    _options = opts


def _generate_user_code(length: int) -> str:
    return "".join(secrets.choice(USER_CODE_CHARSET) for _ in range(length))


def _generate_device_code(length: int) -> str:
    return "".join(secrets.choice(DEVICE_CODE_CHARSET) for _ in range(length))


# ----- request bodies -----


@dataclass(frozen=True, slots=True)
class DeviceCodeBody:
    client_id: str
    scope: str | None = None


@dataclass(frozen=True, slots=True)
class DeviceTokenBody:
    device_code: str
    client_id: str
    grant_type: str = "urn:ietf:params:oauth:grant-type:device_code"


@dataclass(frozen=True, slots=True)
class DeviceActionBody:
    user_code: str


# ----- handlers -----


async def _device_code(ctx: EndpointContext) -> dict[str, Any]:
    body: DeviceCodeBody = ctx.body
    opts = _options
    device_code = _generate_device_code(opts.device_code_length)
    user_code = _generate_user_code(opts.user_code_length)
    now = int(time.time())
    expires_at = now + opts.expires_in
    await ctx.auth.adapter.create(
        model="deviceCode",
        data={
            "deviceCode": device_code,
            "userCode": user_code,
            "userId": None,
            "expiresAt": expires_at,
            "status": "pending",
            "pollingInterval": opts.interval,
            "clientId": body.client_id,
            "scope": body.scope,
            "lastPolledAt": None,
        },
    )
    verification_uri = opts.verification_uri or f"{ctx.auth.base_url}/device"
    return {
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": f"{verification_uri}?user_code={user_code}",
        "expires_in": opts.expires_in,
        "interval": opts.interval,
    }


async def _device_token(ctx: EndpointContext) -> dict[str, Any]:
    body: DeviceTokenBody = ctx.body
    if body.grant_type != "urn:ietf:params:oauth:grant-type:device_code":
        raise APIError(400, "INVALID_REQUEST", message="Unsupported grant_type")

    row = await ctx.auth.adapter.find_one(
        model="deviceCode",
        where=(Where(field="deviceCode", value=body.device_code),),
    )
    if not row:
        raise APIError(
            400,
            "INVALID_DEVICE_CODE",
            data={"error": "invalid_grant"},
        )

    if row.get("clientId") and row["clientId"] != body.client_id:
        raise APIError(
            400,
            "INVALID_DEVICE_CODE",
            data={"error": "invalid_grant", "error_description": "Client ID mismatch"},
        )

    now = int(time.time())

    # Rate-limit (slow_down).
    last_polled = row.get("lastPolledAt")
    interval = int(row.get("pollingInterval") or _options.interval)
    if last_polled and (now - int(last_polled)) < interval:
        raise APIError(
            400,
            "POLLING_TOO_FREQUENTLY",
            data={"error": "slow_down"},
        )

    await ctx.auth.adapter.update(
        model="deviceCode",
        where=(Where(field="id", value=row["id"]),),
        update={"lastPolledAt": now},
    )

    if int(row["expiresAt"]) < now:
        await ctx.auth.adapter.delete(
            model="deviceCode",
            where=(Where(field="id", value=row["id"]),),
        )
        raise APIError(400, "EXPIRED_DEVICE_CODE", data={"error": "expired_token"})

    status = row["status"]
    if status == "pending":
        raise APIError(
            400,
            "AUTHORIZATION_PENDING",
            data={"error": "authorization_pending"},
        )
    if status == "denied":
        await ctx.auth.adapter.delete(
            model="deviceCode",
            where=(Where(field="id", value=row["id"]),),
        )
        raise APIError(400, "ACCESS_DENIED", data={"error": "access_denied"})

    if status == "approved" and row.get("userId"):
        session, _cookies = await create_session(
            ctx.auth,
            user_id=row["userId"],
            ip_address=ctx.request.headers.get("x-forwarded-for"),
            user_agent=ctx.request.headers.get("user-agent"),
        )
        await ctx.auth.adapter.delete(
            model="deviceCode",
            where=(Where(field="id", value=row["id"]),),
        )
        return {
            "access_token": session.token,
            "token_type": "Bearer",
            "expires_in": session.expires_at - now,
            "scope": row.get("scope") or "",
        }

    raise APIError(500, "INVALID_DEVICE_CODE", data={"error": "server_error"})


async def _device_landing(ctx: EndpointContext) -> dict[str, Any]:
    user_code = ctx.request.query.get("user_code")
    if isinstance(user_code, list):
        user_code = user_code[0] if user_code else None
    if not user_code:
        return {"user_code": None, "status": None}
    cleaned = user_code.replace("-", "")
    row = await ctx.auth.adapter.find_one(
        model="deviceCode",
        where=(Where(field="userCode", value=cleaned),),
    )
    if not row:
        raise APIError(400, "INVALID_USER_CODE", data={"error": "invalid_request"})
    if int(row["expiresAt"]) < int(time.time()):
        raise APIError(400, "EXPIRED_USER_CODE", data={"error": "expired_token"})

    # Auto-claim the device code for the current user (so /approve doesn't 400).
    if ctx.session is not None and not row.get("userId") and row["status"] == "pending":
        await ctx.auth.adapter.update(
            model="deviceCode",
            where=(Where(field="id", value=row["id"]),),
            update={"userId": ctx.session.user_id},
        )

    return {"user_code": user_code, "status": row["status"]}


async def _device_approve(ctx: EndpointContext) -> dict[str, Any]:
    body: DeviceActionBody = ctx.body
    return await _set_status(ctx, body.user_code, "approved")


async def _device_deny(ctx: EndpointContext) -> dict[str, Any]:
    body: DeviceActionBody = ctx.body
    return await _set_status(ctx, body.user_code, "denied")


async def _set_status(ctx: EndpointContext, user_code: str, status: str) -> dict[str, Any]:
    cleaned = user_code.replace("-", "")
    row = await ctx.auth.adapter.find_one(
        model="deviceCode",
        where=(Where(field="userCode", value=cleaned),),
    )
    if not row:
        raise APIError(400, "INVALID_USER_CODE", data={"error": "invalid_request"})
    if int(row["expiresAt"]) < int(time.time()):
        raise APIError(400, "EXPIRED_USER_CODE", data={"error": "expired_token"})
    if row["status"] != "pending":
        raise APIError(
            400,
            "DEVICE_CODE_ALREADY_PROCESSED",
            data={"error": "invalid_request"},
        )

    # If the device code isn't yet claimed, claim it for the active user.
    user_id = row.get("userId") or ctx.session.user_id  # type: ignore[union-attr]
    if row.get("userId") and row["userId"] != ctx.session.user_id:  # type: ignore[union-attr]
        raise APIError(403, "ACCESS_DENIED", data={"error": "access_denied"})

    await ctx.auth.adapter.update(
        model="deviceCode",
        where=(Where(field="id", value=row["id"]),),
        update={"status": status, "userId": user_id},
    )
    return {"success": True}


# ----- endpoint table -----


DEVICE_CODE = create_auth_endpoint(
    "/device/code",
    EndpointOptions(method="POST", body=DeviceCodeBody),
    _device_code,
)

DEVICE_TOKEN = create_auth_endpoint(
    "/device/token",
    EndpointOptions(method="POST", body=DeviceTokenBody),
    _device_token,
)

DEVICE_LANDING = create_auth_endpoint(
    "/device",
    EndpointOptions(method="GET"),
    _device_landing,
)

DEVICE_APPROVE = create_auth_endpoint(
    "/device/approve",
    EndpointOptions(method="POST", body=DeviceActionBody, requires_session=True),
    _device_approve,
)

DEVICE_DENY = create_auth_endpoint(
    "/device/deny",
    EndpointOptions(method="POST", body=DeviceActionBody, requires_session=True),
    _device_deny,
)


ALL: tuple[AuthEndpoint, ...] = (
    DEVICE_CODE,
    DEVICE_TOKEN,
    DEVICE_LANDING,
    DEVICE_APPROVE,
    DEVICE_DENY,
)
