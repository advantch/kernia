"""Device-authorization endpoints — RFC 8628.

Port of `reference/packages/better-auth/src/plugins/device-authorization/routes.ts`.

Endpoints:
  * POST `/device/code`    — initiate; client receives device_code + user_code.
  * POST `/device/token`   — client polls; gets `access_token` once approved.
  * GET  `/device`         — verify a user_code + (when signed in) *claim* it.
  * POST `/device/approve` — the claiming user approves a user_code.
  * POST `/device/deny`    — the claiming user denies a user_code.

OAuth 2.0 error semantics (RFC 8628 §3.5): every error response carries an
``error`` + ``error_description`` pair. Upstream returns these at the top level of
the JSON body; the Python error envelope nests plugin payloads under ``data``, so
they surface as ``r.json()["data"]["error"]`` / ``["error_description"]`` here. The
``error`` value (``authorization_pending``, ``slow_down``, ``access_denied``,
``expired_token``, ``invalid_grant``, ``invalid_client``, ``invalid_request``,
``unauthorized``) and its description match upstream exactly.

Security: GHSA-cq3f-vc6p-68fh. ``GET /device`` *claims* a pending code for the
signed-in user via an update guarded by ``userId IS NULL`` so a concurrent claim
can never be overwritten. ``approve``/``deny`` reject any session that is not the
claiming user (``invalid_request`` when unclaimed, ``access_denied`` / FORBIDDEN
when a *different* user tries).
"""

from __future__ import annotations

import math
import re
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

from kernia.api.endpoint import create_auth_endpoint
from kernia.context import create_session
from kernia.error import APIError
from kernia.types.adapter import Where
from kernia.types.context import EndpointContext
from kernia.types.endpoint import AuthEndpoint, EndpointOptions

# Upstream default charset (no vowels-ish ambiguity); matches /^[A-Z0-9]{8}$/.
# cspell:disable-next-line
DEFAULT_USER_CODE_CHARSET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
DEVICE_CODE_CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


# Mirrors the upstream error-codes.ts messages used in `error_description`.
_MSG = {
    "INVALID_DEVICE_CODE": "Invalid device code",
    "EXPIRED_DEVICE_CODE": "Device code has expired",
    "EXPIRED_USER_CODE": "User code has expired",
    "AUTHORIZATION_PENDING": "Authorization pending",
    "ACCESS_DENIED": "Access denied",
    "INVALID_USER_CODE": "Invalid user code",
    "DEVICE_CODE_ALREADY_PROCESSED": "Device code already processed",
    "DEVICE_CODE_NOT_CLAIMED": (
        "Device code has not been claimed by a verifying session; call "
        "`GET /device` with the `user_code` while signed in before approving "
        "or denying"
    ),
    "POLLING_TOO_FREQUENTLY": "Polling too frequently",
    "USER_NOT_FOUND": "User not found",
    "FAILED_TO_CREATE_SESSION": "Failed to create session",
    "INVALID_DEVICE_CODE_STATUS": "Invalid device code status",
    "AUTHENTICATION_REQUIRED": "Authentication required",
}


# --------------------------------------------------------------------------- time

_MS_UNITS = {
    "ms": 1,
    "s": 1000,
    "sec": 1000,
    "m": 60_000,
    "min": 60_000,
    "h": 3_600_000,
    "hr": 3_600_000,
    "d": 86_400_000,
}
_MS_RE = re.compile(r"^\s*([0-9.]+)\s*([a-z]+)\s*$", re.IGNORECASE)


def parse_ms(value: str | int) -> int:
    """Parse a time string ('30m', '5s', '1h', '5min') into milliseconds.

    Mirrors `reference/packages/better-auth/src/utils/time.ts` for the subset of
    units the plugin uses. Integers are treated as already-millisecond values.
    """
    if isinstance(value, int | float):
        return int(value)
    m = _MS_RE.match(value)
    if not m:
        raise ValueError(f"Invalid time string: {value!r}")
    num = float(m.group(1))
    unit = m.group(2).lower()
    if unit not in _MS_UNITS:
        raise ValueError(f"Invalid time unit in {value!r}")
    return int(num * _MS_UNITS[unit])


# --------------------------------------------------------------------------- options


@dataclass(frozen=True, slots=True)
class DeviceAuthorizationOptions:
    expires_in: str | int = "30m"
    interval: str | int = "5s"
    user_code_length: int = 8
    device_code_length: int = 40
    verification_uri: str | None = None
    generate_device_code: Callable[[], str | Awaitable[str]] | None = None
    generate_user_code: Callable[[], str | Awaitable[str]] | None = None
    validate_client: Callable[[str], bool | Awaitable[bool]] | None = None
    on_device_auth_request: Callable[[str, str | None], None | Awaitable[None]] | None = None


# Module-level options register so the endpoint table doesn't need closure state.
_options: DeviceAuthorizationOptions = DeviceAuthorizationOptions()


def configure(opts: DeviceAuthorizationOptions) -> None:
    global _options
    _options = opts


def _default_generate_user_code(length: int) -> str:
    return "".join(secrets.choice(DEFAULT_USER_CODE_CHARSET) for _ in range(length))


def _default_generate_device_code(length: int) -> str:
    return "".join(secrets.choice(DEVICE_CODE_CHARSET) for _ in range(length))


async def _maybe_await(value: Any) -> Any:
    if hasattr(value, "__await__"):
        return await value
    return value


async def _gen_device_code(opts: DeviceAuthorizationOptions) -> str:
    if opts.generate_device_code is not None:
        return str(await _maybe_await(opts.generate_device_code()))
    return _default_generate_device_code(opts.device_code_length)


async def _gen_user_code(opts: DeviceAuthorizationOptions) -> str:
    if opts.generate_user_code is not None:
        return str(await _maybe_await(opts.generate_user_code()))
    return _default_generate_user_code(opts.user_code_length)


def _build_verification_uris(
    verification_uri: str | None, base_url: str, user_code: str
) -> tuple[str, str]:
    """Mirror upstream `buildVerificationUris` (absolute / relative / with-query)."""
    uri = verification_uri or "/device"
    parsed = urlparse(uri)
    if parsed.scheme and parsed.netloc:
        # Absolute URL.
        base_uri = uri
        complete = parsed
    else:
        # Relative path — resolve against base_url.
        base = urlparse(base_url)
        merged = parsed._replace(scheme=base.scheme, netloc=base.netloc)
        base_uri = urlunparse(merged)
        complete = merged

    existing = complete.query
    new_query = (existing + "&" if existing else "") + urlencode({"user_code": user_code})
    complete_uri = urlunparse(complete._replace(query=new_query))
    return base_uri, complete_uri


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


# ----- error helper -----


def _oauth_error(status: int, code: str, error: str, error_description: str) -> APIError:
    return APIError(
        status,
        code,
        message=error_description,
        data={"error": error, "error_description": error_description},
    )


# ----- handlers -----


async def _device_code(ctx: EndpointContext) -> dict[str, Any]:
    body: DeviceCodeBody = ctx.body
    opts = _options

    if opts.validate_client is not None:
        is_valid = await _maybe_await(opts.validate_client(body.client_id))
        if not is_valid:
            raise _oauth_error(400, "INVALID_REQUEST", "invalid_client", "Invalid client ID")

    if opts.on_device_auth_request is not None:
        await _maybe_await(opts.on_device_auth_request(body.client_id, body.scope))

    device_code = await _gen_device_code(opts)
    user_code = await _gen_user_code(opts)
    expires_ms = parse_ms(opts.expires_in)
    interval_ms = parse_ms(opts.interval)
    now = int(time.time())
    expires_at = now + math.floor(expires_ms / 1000)

    await ctx.auth.adapter.create(
        model="deviceCode",
        data={
            "deviceCode": device_code,
            "userCode": user_code,
            "userId": None,
            "expiresAt": expires_at,
            "status": "pending",
            # Stored as milliseconds (upstream parity), returned in seconds.
            "pollingInterval": interval_ms,
            "clientId": body.client_id,
            "scope": body.scope,
            "lastPolledAt": None,
        },
    )

    verification_uri, verification_uri_complete = _build_verification_uris(
        opts.verification_uri, ctx.auth.base_url, user_code
    )
    return {
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": verification_uri_complete,
        "expires_in": math.floor(expires_ms / 1000),
        "interval": math.floor(interval_ms / 1000),
    }


async def _device_token(ctx: EndpointContext) -> dict[str, Any]:
    body: DeviceTokenBody = ctx.body
    opts = _options

    if opts.validate_client is not None:
        is_valid = await _maybe_await(opts.validate_client(body.client_id))
        if not is_valid:
            raise _oauth_error(400, "INVALID_DEVICE_CODE", "invalid_grant", "Invalid client ID")

    row = await ctx.auth.adapter.find_one(
        model="deviceCode",
        where=(Where(field="deviceCode", value=body.device_code),),
    )
    if not row:
        raise _oauth_error(400, "INVALID_DEVICE_CODE", "invalid_grant", _MSG["INVALID_DEVICE_CODE"])

    if row.get("clientId") and row["clientId"] != body.client_id:
        raise _oauth_error(400, "INVALID_DEVICE_CODE", "invalid_grant", "Client ID mismatch")

    now = int(time.time())

    # Rate-limit (slow_down). pollingInterval is stored in milliseconds.
    last_polled = row.get("lastPolledAt")
    polling_interval_ms = row.get("pollingInterval")
    if last_polled and polling_interval_ms:
        elapsed_ms = (now - int(last_polled)) * 1000
        if elapsed_ms < int(polling_interval_ms):
            raise _oauth_error(
                400,
                "POLLING_TOO_FREQUENTLY",
                "slow_down",
                _MSG["POLLING_TOO_FREQUENTLY"],
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
        raise _oauth_error(400, "EXPIRED_DEVICE_CODE", "expired_token", _MSG["EXPIRED_DEVICE_CODE"])

    status = row["status"]
    if status == "pending":
        raise _oauth_error(
            400,
            "AUTHORIZATION_PENDING",
            "authorization_pending",
            _MSG["AUTHORIZATION_PENDING"],
        )
    if status == "denied":
        await ctx.auth.adapter.delete(
            model="deviceCode",
            where=(Where(field="id", value=row["id"]),),
        )
        raise _oauth_error(400, "ACCESS_DENIED", "access_denied", _MSG["ACCESS_DENIED"])

    if status == "approved" and row.get("userId"):
        user = await ctx.auth.adapter.find_one(
            model="user",
            where=(Where(field="id", value=row["userId"]),),
        )
        if not user:
            raise _oauth_error(500, "INTERNAL", "server_error", _MSG["USER_NOT_FOUND"])

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

    raise _oauth_error(
        500, "INVALID_DEVICE_CODE", "server_error", _MSG["INVALID_DEVICE_CODE_STATUS"]
    )


async def _device_verify(ctx: EndpointContext) -> dict[str, Any]:
    user_code = ctx.request.query.get("user_code")
    if isinstance(user_code, list):
        user_code = user_code[0] if user_code else None
    if not user_code:
        raise _oauth_error(400, "INVALID_USER_CODE", "invalid_request", _MSG["INVALID_USER_CODE"])
    cleaned = user_code.replace("-", "")
    row = await ctx.auth.adapter.find_one(
        model="deviceCode",
        where=(Where(field="userCode", value=cleaned),),
    )
    if not row:
        raise _oauth_error(400, "INVALID_USER_CODE", "invalid_request", _MSG["INVALID_USER_CODE"])
    if int(row["expiresAt"]) < int(time.time()):
        raise _oauth_error(400, "EXPIRED_USER_CODE", "expired_token", _MSG["EXPIRED_USER_CODE"])

    # Claim the code for the signed-in user. The update is guarded by
    # `userId IS NULL` so a concurrent claim is never overwritten
    # (GHSA-cq3f-vc6p-68fh).
    if ctx.session is not None and not row.get("userId") and row["status"] == "pending":
        claimed = await ctx.auth.adapter.update(
            model="deviceCode",
            where=(
                Where(field="id", value=row["id"]),
                Where(field="status", value="pending", connector="AND"),
                Where(field="userId", value=None, operator="eq", connector="AND"),
            ),
            update={"userId": ctx.session.user_id},
        )
        if claimed:
            row["userId"] = ctx.session.user_id

    return {"user_code": user_code, "status": row["status"]}


async def _device_approve(ctx: EndpointContext) -> dict[str, Any]:
    body: DeviceActionBody = ctx.body
    return await _set_status(ctx, body.user_code, "approved")


async def _device_deny(ctx: EndpointContext) -> dict[str, Any]:
    body: DeviceActionBody = ctx.body
    return await _set_status(ctx, body.user_code, "denied")


async def _set_status(ctx: EndpointContext, user_code: str, status: str) -> dict[str, Any]:
    if ctx.session is None:
        raise _oauth_error(401, "UNAUTHORIZED", "unauthorized", _MSG["AUTHENTICATION_REQUIRED"])

    cleaned = user_code.replace("-", "")
    row = await ctx.auth.adapter.find_one(
        model="deviceCode",
        where=(Where(field="userCode", value=cleaned),),
    )
    if not row:
        raise _oauth_error(400, "INVALID_USER_CODE", "invalid_request", _MSG["INVALID_USER_CODE"])
    if int(row["expiresAt"]) < int(time.time()):
        raise _oauth_error(400, "EXPIRED_USER_CODE", "expired_token", _MSG["EXPIRED_USER_CODE"])
    if row["status"] != "pending":
        raise _oauth_error(
            400,
            "DEVICE_CODE_ALREADY_PROCESSED",
            "invalid_request",
            _MSG["DEVICE_CODE_ALREADY_PROCESSED"],
        )

    # Ownership gate (GHSA-cq3f-vc6p-68fh): the code must have been claimed by a
    # verifying session, and only that same user may approve/deny it.
    if not row.get("userId"):
        raise _oauth_error(
            400,
            "INVALID_USER_CODE",
            "invalid_request",
            _MSG["DEVICE_CODE_NOT_CLAIMED"],
        )
    if row["userId"] != ctx.session.user_id:
        raise _oauth_error(403, "FORBIDDEN", "access_denied", f"You are not authorized to {status}")

    await ctx.auth.adapter.update(
        model="deviceCode",
        where=(Where(field="id", value=row["id"]),),
        update={"status": status, "userId": ctx.session.user_id},
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

DEVICE_VERIFY = create_auth_endpoint(
    "/device",
    EndpointOptions(method="GET"),
    _device_verify,
)

DEVICE_APPROVE = create_auth_endpoint(
    "/device/approve",
    EndpointOptions(method="POST", body=DeviceActionBody),
    _device_approve,
)

DEVICE_DENY = create_auth_endpoint(
    "/device/deny",
    EndpointOptions(method="POST", body=DeviceActionBody),
    _device_deny,
)


ALL: tuple[AuthEndpoint, ...] = (
    DEVICE_CODE,
    DEVICE_TOKEN,
    DEVICE_VERIFY,
    DEVICE_APPROVE,
    DEVICE_DENY,
)
