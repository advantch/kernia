"""WebAuthn passkey plugin.

Reference: `reference/packages/passkey/src/`.

The plugin contributes a `passkey` table and six endpoints:

  * `POST /passkey/register/start`      — issue PublicKeyCredentialCreationOptions
  * `POST /passkey/register/finish`     — verify attestation, persist credential
  * `POST /passkey/authenticate/start`  — issue PublicKeyCredentialRequestOptions
  * `POST /passkey/authenticate/finish` — verify assertion, sign user in
  * `GET  /passkey/list`                — list this user's passkeys
  * `POST /passkey/delete`              — delete by credentialId

Implementation notes:
  - We rely on the `webauthn` PyPI library for option generation and verification.
  - The pending challenge is stashed in the `verification` table keyed by
    `passkey-reg:<userId>` / `passkey-auth:<challenge>`. TTL: 5 min.
  - Public keys + credential ids are stored base64url-encoded so the schema
    remains string-only across adapters.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from kernia.api.endpoint import create_auth_endpoint
from kernia.context import create_session
from kernia.error import APIError
from kernia.types.adapter import FieldDef, ModelDef, Where
from kernia.types.context import EndpointContext
from kernia.types.endpoint import AuthEndpoint, EndpointOptions
from kernia.types.hooks import PluginHooks
from kernia.types.plugin import KerniaPlugin, PluginSchema, RateLimitRule


PASSKEY_ERROR_CODES: Mapping[str, str] = {
    "PASSKEY_NOT_FOUND": "Passkey was not found.",
    "INVALID_PASSKEY_CHALLENGE": "Passkey challenge is invalid or expired.",
    "INVALID_PASSKEY_ATTESTATION": "Passkey attestation could not be verified.",
    "INVALID_PASSKEY_ASSERTION": "Passkey assertion could not be verified.",
}


CHALLENGE_TTL_SECONDS = 5 * 60


_PASSKEY_MODEL = ModelDef(
    name="passkey",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("userId", "string", references=("user", "id")),
        FieldDef("credentialId", "string", unique=True),
        FieldDef("publicKey", "text"),
        FieldDef("counter", "number", default=0),
        FieldDef("transports", "string", required=False),
        FieldDef("deviceType", "string", required=False),
        FieldDef("backedUp", "boolean", default=False),
        FieldDef("createdAt", "date"),
    ),
)


# ----- bodies -----


@dataclass(frozen=True, slots=True)
class RegisterStartBody:
    name: str | None = None  # passkey nickname


@dataclass(frozen=True, slots=True)
class RegisterFinishBody:
    response: dict[str, Any]
    name: str | None = None


@dataclass(frozen=True, slots=True)
class AuthenticateStartBody:
    email: str | None = None


@dataclass(frozen=True, slots=True)
class AuthenticateFinishBody:
    response: dict[str, Any]


@dataclass(frozen=True, slots=True)
class DeleteBody:
    credential_id: str


# ----- helpers -----


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _options_dict(options: Any) -> dict[str, Any]:
    """Convert a webauthn options object to a plain JSON-able dict."""
    from webauthn import options_to_json

    return json.loads(options_to_json(options))


# Process-global options registry keyed by `id(auth_context)`. We populate this
# at `passkey()` construction time (via a closure passed to the handlers
# through plugin_state) so we don't depend on the async `init` hook firing
# before the first request.
_OPTIONS_REGISTRY: dict[str, dict[str, Any]] = {}


def _passkey_options(ctx: EndpointContext) -> Mapping[str, Any]:
    # First check the per-context plugin_state (preferred), then the module-level
    # registry as a fallback for cases where the init hook hasn't run yet.
    state = ctx.auth.plugin_state.get("passkey")
    if state:
        return state
    if _OPTIONS_REGISTRY:
        # Single-plugin case: just return the first registered option set.
        # The registry is keyed by plugin id and there's only one passkey plugin.
        return next(iter(_OPTIONS_REGISTRY.values()))
    raise APIError(500, "INTERNAL", message="passkey plugin not initialized")


# ----- handlers -----


async def _register_start(ctx: EndpointContext) -> dict[str, object]:
    from webauthn import generate_registration_options

    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    opts = _passkey_options(ctx)
    user = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="id", value=ctx.session.user_id),),
    )
    if not user:
        raise APIError(401, "UNAUTHORIZED")
    options = generate_registration_options(
        rp_id=opts["rp_id"],
        rp_name=opts["rp_name"],
        user_id=user["id"].encode("utf-8"),
        user_name=user.get("email") or user["id"],
        user_display_name=user.get("name") or user.get("email") or user["id"],
    )
    challenge_b64 = _b64url(options.challenge)
    await ctx.auth.adapter.create(
        model="verification",
        data={
            "identifier": f"passkey-reg:{user['id']}",
            "value": challenge_b64,
            "expiresAt": int(time.time()) + CHALLENGE_TTL_SECONDS,
        },
    )
    return {"options": _options_dict(options)}


async def _register_finish(ctx: EndpointContext) -> dict[str, object]:
    from webauthn import verify_registration_response

    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: RegisterFinishBody = ctx.body
    opts = _passkey_options(ctx)

    pending = await ctx.auth.adapter.find_one(
        model="verification",
        where=(Where(field="identifier", value=f"passkey-reg:{ctx.session.user_id}"),),
    )
    if not pending or int(pending.get("expiresAt", 0)) < int(time.time()):
        raise APIError(400, "INVALID_PASSKEY_CHALLENGE")
    expected_challenge = _b64url_decode(pending["value"])

    try:
        verification = verify_registration_response(
            credential=body.response,
            expected_challenge=expected_challenge,
            expected_origin=opts["origin"],
            expected_rp_id=opts["rp_id"],
        )
    except Exception as exc:
        raise APIError(400, "INVALID_PASSKEY_ATTESTATION", message=str(exc)) from exc

    # Consume the challenge.
    await ctx.auth.adapter.delete(
        model="verification",
        where=(Where(field="identifier", value=f"passkey-reg:{ctx.session.user_id}"),),
    )

    credential_id_b64 = _b64url(verification.credential_id)
    public_key_b64 = _b64url(verification.credential_public_key)
    await ctx.auth.adapter.create(
        model="passkey",
        data={
            "userId": ctx.session.user_id,
            "credentialId": credential_id_b64,
            "publicKey": public_key_b64,
            "counter": int(verification.sign_count),
            "deviceType": getattr(verification.credential_device_type, "value", None)
            if verification.credential_device_type
            else None,
            "backedUp": bool(verification.credential_backed_up),
            "createdAt": int(time.time()),
        },
    )
    return {"success": True, "credentialId": credential_id_b64}


async def _authenticate_start(ctx: EndpointContext) -> dict[str, object]:
    from webauthn import generate_authentication_options

    body: AuthenticateStartBody | None = ctx.body
    opts = _passkey_options(ctx)
    allow: list[Any] = []
    if body and body.email:
        user = await ctx.auth.adapter.find_one(
            model="user",
            where=(Where(field="email", value=body.email),),
        )
        if user:
            from webauthn.helpers.structs import (
                PublicKeyCredentialDescriptor,
            )

            for row in await ctx.auth.adapter.find_many(
                model="passkey",
                where=(Where(field="userId", value=user["id"]),),
            ):
                allow.append(
                    PublicKeyCredentialDescriptor(
                        id=_b64url_decode(row["credentialId"])
                    )
                )

    options = generate_authentication_options(
        rp_id=opts["rp_id"],
        allow_credentials=allow if allow else None,
    )
    challenge_b64 = _b64url(options.challenge)
    await ctx.auth.adapter.create(
        model="verification",
        data={
            "identifier": f"passkey-auth:{challenge_b64}",
            "value": challenge_b64,
            "expiresAt": int(time.time()) + CHALLENGE_TTL_SECONDS,
        },
    )
    return {"options": _options_dict(options), "challenge": challenge_b64}


async def _authenticate_finish(ctx: EndpointContext) -> dict[str, object]:
    from webauthn import verify_authentication_response

    body: AuthenticateFinishBody = ctx.body
    opts = _passkey_options(ctx)
    response = body.response
    raw_id = response.get("rawId") or response.get("id")
    if not raw_id:
        raise APIError(400, "INVALID_PASSKEY_ASSERTION", message="missing rawId")

    passkey_row = await ctx.auth.adapter.find_one(
        model="passkey",
        where=(Where(field="credentialId", value=raw_id),),
    )
    if not passkey_row:
        raise APIError(401, "PASSKEY_NOT_FOUND")

    # Recover the expected challenge from the clientDataJSON.
    try:
        client_data_b64 = response["response"]["clientDataJSON"]
        client_data_bytes = _b64url_decode(client_data_b64)
        client_data = json.loads(client_data_bytes)
        challenge_b64 = client_data["challenge"]
    except Exception as exc:
        raise APIError(400, "INVALID_PASSKEY_ASSERTION", message=str(exc)) from exc

    pending = await ctx.auth.adapter.find_one(
        model="verification",
        where=(Where(field="identifier", value=f"passkey-auth:{challenge_b64}"),),
    )
    if not pending or int(pending.get("expiresAt", 0)) < int(time.time()):
        raise APIError(400, "INVALID_PASSKEY_CHALLENGE")
    expected_challenge = _b64url_decode(pending["value"])

    try:
        verification = verify_authentication_response(
            credential=response,
            expected_challenge=expected_challenge,
            expected_origin=opts["origin"],
            expected_rp_id=opts["rp_id"],
            credential_public_key=_b64url_decode(passkey_row["publicKey"]),
            credential_current_sign_count=int(passkey_row.get("counter") or 0),
        )
    except Exception as exc:
        raise APIError(401, "INVALID_PASSKEY_ASSERTION", message=str(exc)) from exc

    # Bump the counter + consume challenge.
    await ctx.auth.adapter.update(
        model="passkey",
        where=(Where(field="id", value=passkey_row["id"]),),
        update={"counter": int(verification.new_sign_count)},
    )
    await ctx.auth.adapter.delete(
        model="verification",
        where=(Where(field="identifier", value=f"passkey-auth:{challenge_b64}"),),
    )

    session, cookies = await create_session(
        ctx.auth,
        user_id=passkey_row["userId"],
        ip_address=ctx.request.headers.get("x-forwarded-for"),
        user_agent=ctx.request.headers.get("user-agent"),
    )
    ctx.set_cookies.extend(cookies)
    return {
        "success": True,
        "session": {"id": session.id, "expiresAt": session.expires_at},
        "userId": passkey_row["userId"],
    }


async def _list(ctx: EndpointContext) -> dict[str, object]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    rows = await ctx.auth.adapter.find_many(
        model="passkey",
        where=(Where(field="userId", value=ctx.session.user_id),),
    )
    return {
        "passkeys": [
            {
                "id": r["id"],
                "credentialId": r["credentialId"],
                "deviceType": r.get("deviceType"),
                "backedUp": r.get("backedUp", False),
                "createdAt": r.get("createdAt"),
            }
            for r in rows
        ]
    }


async def _delete(ctx: EndpointContext) -> dict[str, object]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: DeleteBody = ctx.body
    existing = await ctx.auth.adapter.find_one(
        model="passkey",
        where=(
            Where(field="userId", value=ctx.session.user_id),
            Where(field="credentialId", value=body.credential_id),
        ),
    )
    if not existing:
        raise APIError(404, "PASSKEY_NOT_FOUND")
    await ctx.auth.adapter.delete(
        model="passkey",
        where=(Where(field="id", value=existing["id"]),),
    )
    return {"success": True}


REGISTER_START = create_auth_endpoint(
    "/passkey/register/start",
    EndpointOptions(method="POST", body=RegisterStartBody, requires_session=True),
    _register_start,
)
REGISTER_FINISH = create_auth_endpoint(
    "/passkey/register/finish",
    EndpointOptions(method="POST", body=RegisterFinishBody, requires_session=True),
    _register_finish,
)
AUTHENTICATE_START = create_auth_endpoint(
    "/passkey/authenticate/start",
    EndpointOptions(method="POST", body=AuthenticateStartBody),
    _authenticate_start,
)
AUTHENTICATE_FINISH = create_auth_endpoint(
    "/passkey/authenticate/finish",
    EndpointOptions(method="POST", body=AuthenticateFinishBody),
    _authenticate_finish,
)
LIST = create_auth_endpoint(
    "/passkey/list",
    EndpointOptions(method="GET", requires_session=True),
    _list,
)
DELETE = create_auth_endpoint(
    "/passkey/delete",
    EndpointOptions(method="POST", body=DeleteBody, requires_session=True),
    _delete,
)


ALL: tuple[AuthEndpoint, ...] = (
    REGISTER_START,
    REGISTER_FINISH,
    AUTHENTICATE_START,
    AUTHENTICATE_FINISH,
    LIST,
    DELETE,
)


@dataclass(frozen=True, slots=True)
class _PasskeyPlugin:
    id: str = "passkey"
    version: str | None = None
    schema: PluginSchema | None = field(
        default_factory=lambda: PluginSchema(tables=(_PASSKEY_MODEL,))
    )
    endpoints: tuple[AuthEndpoint, ...] = field(default_factory=lambda: ALL)
    middlewares: None = None
    hooks: PluginHooks | None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = (
        RateLimitRule(path="/passkey/register/start", window=60, max=10),
        RateLimitRule(path="/passkey/register/finish", window=60, max=10),
        RateLimitRule(path="/passkey/authenticate/start", window=60, max=20),
        RateLimitRule(path="/passkey/authenticate/finish", window=60, max=20),
    )
    error_codes: Mapping[str, str] = field(
        default_factory=lambda: dict(PASSKEY_ERROR_CODES)
    )
    init: Any = None  # populated by `passkey()` factory


def passkey(*, rp_id: str, rp_name: str, origin: str | list[str]) -> KerniaPlugin:
    """Construct the passkey plugin.

    Options are stashed in the module-level `_OPTIONS_REGISTRY` so endpoint
    handlers can read them without depending on the async `init` hook (which
    is fire-and-forget when `init()` is invoked from inside a running event
    loop, e.g. by pytest-asyncio).
    """
    options = {"rp_id": rp_id, "rp_name": rp_name, "origin": origin}
    _OPTIONS_REGISTRY["passkey"] = options

    async def _init(ctx: Any) -> None:
        ctx.plugin_state["passkey"] = options

    plugin = _PasskeyPlugin(init=_init)  # type: ignore[call-arg]
    return plugin  # type: ignore[return-value]


__all__ = ["PASSKEY_ERROR_CODES", "passkey"]
