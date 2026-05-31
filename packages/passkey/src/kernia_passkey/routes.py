"""Passkey endpoint handlers.

Port of ``reference/packages/passkey/src/routes.ts``. Endpoint paths, request
shapes, response shapes, and error codes mirror upstream 1:1:

  * ``GET  /passkey/generate-register-options``     issue creation options
  * ``GET  /passkey/generate-authenticate-options`` issue request options
  * ``POST /passkey/verify-registration``           verify attestation, persist
  * ``POST /passkey/verify-authentication``         verify assertion, sign in
  * ``GET  /passkey/list-user-passkeys``            list the user's passkeys
  * ``POST /passkey/delete-passkey``                delete by id (owner-only)
  * ``POST /passkey/update-passkey``                rename by id (owner-only)

The pending WebAuthn challenge travels in a signed cookie (default name
``better-auth-passkey``) whose value is a random verification token; the token
keys a row on the core ``verification`` table holding the expected challenge and
user data. This matches the upstream ``setSignedCookie`` + ``createVerificationValue``
design exactly (rather than keying the row by challenge).
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from better_auth import cookies as cookie_utils
from better_auth.api.endpoint import create_auth_endpoint
from better_auth.context import create_session
from better_auth.error import APIError
from better_auth.types.adapter import Where
from better_auth.types.context import EndpointContext
from better_auth.types.cookie import CookieAttributes
from better_auth.types.endpoint import AuthEndpoint, EndpointOptions

from . import webauthn_server as _wa
from .error_codes import PASSKEY_ERROR_CODES
from .types import PasskeyOptions

CHALLENGE_TTL_SECONDS = 5 * 60


# ----- encoding helpers ------------------------------------------------------


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _credential_id_bytes(value: str) -> bytes:
    """Decode a stored credential id to bytes, tolerating non-base64url ids.

    Stored credential ids are base64url strings in normal operation; tests may
    seed arbitrary opaque ids, so fall back to the raw UTF-8 bytes.
    """
    try:
        return _b64url_decode(value)
    except Exception:
        return value.encode("utf-8")


def _now() -> int:
    return int(time.time())


def _generate_random_string(length: int = 32) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _options_dict(options: Any) -> dict[str, Any]:
    """Convert a webauthn options object to a plain JSON-able dict."""
    if isinstance(options, dict):
        return options
    from webauthn import options_to_json

    return json.loads(options_to_json(options))


# ----- option helpers --------------------------------------------------------


def _opts(ctx: EndpointContext) -> PasskeyOptions:
    state = ctx.auth.plugin_state.get("passkey")
    if isinstance(state, PasskeyOptions):
        return state
    if _OPTIONS_REGISTRY:
        return next(iter(_OPTIONS_REGISTRY.values()))
    return PasskeyOptions()


def _get_rp_id(opts: PasskeyOptions, base_url: str | None) -> str:
    if opts.rp_id:
        return opts.rp_id
    if base_url:
        host = urlparse(base_url).hostname
        if host:
            return host
    return "localhost"


def _app_name(ctx: EndpointContext) -> str:
    return str(ctx.auth.options.advanced.get("app_name") or "Better Auth")


def _challenge_cookie_name(opts: PasskeyOptions) -> str:
    return opts.advanced.web_authn_challenge_cookie


def _secure(ctx: EndpointContext) -> bool:
    return ctx.auth.base_url.startswith("https")


def _query(ctx: EndpointContext) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in (ctx.request.query or {}).items():
        out[k] = v[0] if isinstance(v, list) else v
    return out


def _parse_transports(value: Any) -> list[Any] | None:
    """Parse a comma-separated transports string into enum members.

    Mirrors the upstream cast to ``AuthenticatorTransportFuture[]`` but tolerates
    values that are not recognized by the ``webauthn`` enum (upstream does no
    validation here); unknown values are dropped.
    """
    if not value:
        return None
    from webauthn.helpers.structs import AuthenticatorTransport

    out: list[Any] = []
    for token in str(value).split(","):
        token = token.strip()
        if not token:
            continue
        try:
            out.append(AuthenticatorTransport(token))
        except ValueError:
            continue
    return out or None


async def _resolve_extensions(extensions: Any, ctx: EndpointContext) -> Any:
    if not extensions:
        return None
    if callable(extensions):
        result = extensions(ctx=ctx)
        if hasattr(result, "__await__"):
            result = await result
        return result
    return extensions


async def _maybe_await(value: Any) -> Any:
    if hasattr(value, "__await__"):
        return await value
    return value


# ----- signed cookie helpers -------------------------------------------------


def _get_signed_cookie(ctx: EndpointContext, name: str) -> str | None:
    raw = ctx.request.cookies.get(name)
    if not raw:
        return None
    return cookie_utils.verify(raw, secret=ctx.auth.secret)


def _set_signed_cookie(
    ctx: EndpointContext, name: str, value: str, max_age: int
) -> None:
    signed = cookie_utils.sign(value, secret=ctx.auth.secret)
    attrs = CookieAttributes(
        path="/",
        max_age=max_age,
        http_only=True,
        secure=_secure(ctx),
        same_site="lax",
    )
    ctx.set_cookies.append((name, signed, attrs))


# ----- user resolution -------------------------------------------------------


async def _session_user(ctx: EndpointContext) -> dict[str, Any] | None:
    if ctx.session is None:
        return None
    return await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="id", value=ctx.session.user_id),)
    )


async def _resolve_registration_user(
    opts: PasskeyOptions, ctx: EndpointContext
) -> dict[str, Any]:
    require_session = (
        opts.registration.require_session if opts.registration else True
    )
    if require_session:
        user = await _session_user(ctx)
        if not user or not user.get("id"):
            raise APIError(401, "SESSION_REQUIRED")
        name = user.get("email") or user["id"]
        return {"id": user["id"], "name": name, "displayName": name}

    user = await _session_user(ctx)
    if user and user.get("id"):
        name = user.get("email") or user["id"]
        return {"id": user["id"], "name": name, "displayName": name}

    if not opts.registration or not opts.registration.resolve_user:
        raise APIError(400, "RESOLVE_USER_REQUIRED")

    resolved = await _maybe_await(
        opts.registration.resolve_user(
            ctx=ctx, context=_query(ctx).get("context")
        )
    )
    if not resolved or not resolved.get("id") or not resolved.get("name"):
        raise APIError(400, "RESOLVED_USER_INVALID")
    return resolved


# ----- handlers --------------------------------------------------------------


async def _generate_register_options(ctx: EndpointContext) -> dict[str, Any]:
    opts = _opts(ctx)
    user = await _resolve_registration_user(opts, ctx)

    user_passkeys = await ctx.auth.adapter.find_many(
        model="passkey", where=(Where(field="userId", value=user["id"]),)
    )
    registration_extensions = await _resolve_extensions(
        opts.registration.extensions if opts.registration else None, ctx
    )
    base_url = ctx.auth.options.base_url

    exclude = []
    for pk in user_passkeys:
        from webauthn.helpers.structs import PublicKeyCredentialDescriptor

        exclude.append(
            PublicKeyCredentialDescriptor(
                id=_credential_id_bytes(pk["credentialID"]),
                transports=_parse_transports(pk.get("transports")),
            )
        )

    authenticator_selection = _build_authenticator_selection(ctx, opts)

    from webauthn.helpers.structs import AttestationConveyancePreference

    options = _wa.generate_registration_options(
        rp_name=opts.rp_name or _app_name(ctx),
        rp_id=_get_rp_id(opts, base_url),
        user_id=_generate_random_string(32).encode("utf-8"),
        user_name=_query(ctx).get("name") or user.get("name") or user["id"],
        user_display_name=user.get("displayName") or user.get("name") or user["id"],
        attestation=AttestationConveyancePreference.NONE,
        exclude_credentials=exclude or None,
        authenticator_selection=authenticator_selection,
    )
    options_dict = _options_dict(options)
    if registration_extensions is not None:
        options_dict["extensions"] = registration_extensions

    verification_token = _generate_random_string(32)
    _set_signed_cookie(
        ctx,
        _challenge_cookie_name(opts),
        verification_token,
        CHALLENGE_TTL_SECONDS,
    )
    expires_at = _now() + CHALLENGE_TTL_SECONDS
    await ctx.auth.adapter.create(
        model="verification",
        data={
            "identifier": verification_token,
            "value": json.dumps(
                {
                    "expectedChallenge": options_dict["challenge"],
                    "userData": {
                        "id": user["id"],
                        "name": user.get("name"),
                        "displayName": user.get("displayName"),
                    },
                    "context": _query(ctx).get("context"),
                }
            ),
            "expiresAt": expires_at,
            "createdAt": _now(),
            "updatedAt": _now(),
        },
    )
    return options_dict


def _build_authenticator_selection(ctx: EndpointContext, opts: PasskeyOptions) -> Any:
    from webauthn.helpers.structs import (
        AuthenticatorAttachment,
        AuthenticatorSelectionCriteria,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )

    custom = opts.authenticator_selection or {}
    attachment = _query(ctx).get("authenticatorAttachment") or custom.get(
        "authenticatorAttachment"
    )
    resident = custom.get("residentKey", "preferred")
    user_verification = custom.get("userVerification", "preferred")
    return AuthenticatorSelectionCriteria(
        authenticator_attachment=(
            AuthenticatorAttachment(attachment) if attachment else None
        ),
        resident_key=ResidentKeyRequirement(resident) if resident else None,
        user_verification=UserVerificationRequirement(user_verification),
    )


async def _generate_authenticate_options(ctx: EndpointContext) -> dict[str, Any]:
    opts = _opts(ctx)
    base_url = ctx.auth.options.base_url
    user = await _session_user(ctx)
    user_passkeys: list[dict[str, Any]] = []
    if user:
        user_passkeys = await ctx.auth.adapter.find_many(
            model="passkey", where=(Where(field="userId", value=user["id"]),)
        )
    authentication_extensions = await _resolve_extensions(
        opts.authentication.extensions if opts.authentication else None, ctx
    )

    allow_credentials = None
    if user_passkeys:
        from webauthn.helpers.structs import PublicKeyCredentialDescriptor

        allow_credentials = []
        for pk in user_passkeys:
            allow_credentials.append(
                PublicKeyCredentialDescriptor(
                    id=_credential_id_bytes(pk["credentialID"]),
                    transports=_parse_transports(pk.get("transports")),
                )
            )

    options = _wa.generate_authentication_options(
        rp_id=_get_rp_id(opts, base_url),
        user_verification=_user_verification("preferred"),
        allow_credentials=allow_credentials,
    )
    options_dict = _options_dict(options)
    if authentication_extensions is not None:
        options_dict["extensions"] = authentication_extensions

    verification_token = _generate_random_string(32)
    _set_signed_cookie(
        ctx,
        _challenge_cookie_name(opts),
        verification_token,
        CHALLENGE_TTL_SECONDS,
    )
    expires_at = _now() + CHALLENGE_TTL_SECONDS
    await ctx.auth.adapter.create(
        model="verification",
        data={
            "identifier": verification_token,
            "value": json.dumps(
                {
                    "expectedChallenge": options_dict["challenge"],
                    "userData": {"id": user["id"] if user else ""},
                }
            ),
            "expiresAt": expires_at,
            "createdAt": _now(),
            "updatedAt": _now(),
        },
    )
    return options_dict


def _user_verification(value: str) -> Any:
    from webauthn.helpers.structs import UserVerificationRequirement

    return UserVerificationRequirement(value)


async def _verify_registration(ctx: EndpointContext) -> dict[str, Any]:
    opts = _opts(ctx)
    require_session = (
        opts.registration.require_session if opts.registration else True
    )
    origin = _resolve_origin(ctx, opts)
    if not origin:
        raise APIError(400, "FAILED_TO_VERIFY_REGISTRATION")

    resp = ctx.body.response
    cookie_name = _challenge_cookie_name(opts)
    verification_token = _get_signed_cookie(ctx, cookie_name)
    if not verification_token:
        raise APIError(400, "CHALLENGE_NOT_FOUND")

    data = await ctx.auth.adapter.find_one(
        model="verification",
        where=(Where(field="identifier", value=verification_token),),
    )
    if not data:
        raise APIError(400, "CHALLENGE_NOT_FOUND")
    parsed = json.loads(str(data["value"]))
    expected_challenge = parsed["expectedChallenge"]
    user_data = parsed["userData"]
    context = parsed.get("context")

    session_user = await _session_user(ctx) if not require_session else None
    if require_session:
        session_user = await _session_user(ctx)
    if (
        session_user
        and session_user.get("id")
        and user_data["id"] != session_user["id"]
    ):
        raise APIError(401, "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY")

    try:
        base_url = ctx.auth.options.base_url
        verification = _wa.verify_registration_response(
            response=resp,
            expected_challenge=_b64url_decode(expected_challenge),
            expected_origin=origin,
            expected_rpid=_get_rp_id(opts, base_url),
            require_user_verification=False,
        )
    except APIError:
        raise
    except Exception:
        raise APIError(400, "FAILED_TO_VERIFY_REGISTRATION") from None

    if not verification.verified or not verification.registration_info:
        raise APIError(400, "FAILED_TO_VERIFY_REGISTRATION")

    info = verification.registration_info
    resolved_user = {
        "id": user_data["id"],
        "name": user_data.get("name") or user_data["id"],
        "displayName": user_data.get("displayName"),
    }
    target_user_id = resolved_user["id"]
    if opts.registration and opts.registration.after_verification:
        result = await _maybe_await(
            opts.registration.after_verification(
                ctx=ctx,
                verification=verification,
                user=resolved_user,
                clientData=resp,
                context=context,
            )
        )
        if result and result.get("userId"):
            new_id = result["userId"]
            if not isinstance(new_id, str) or not new_id:
                raise APIError(400, "RESOLVED_USER_INVALID")
            if (
                session_user
                and session_user.get("id")
                and new_id != session_user["id"]
            ):
                raise APIError(
                    401, "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"
                )
            target_user_id = new_id

    transports = ""
    resp_response = resp.get("response") if isinstance(resp, dict) else None
    if resp_response and resp_response.get("transports"):
        transports = ",".join(resp_response["transports"])

    new_passkey = await ctx.auth.adapter.create(
        model="passkey",
        data={
            "name": getattr(ctx.body, "name", None),
            "userId": target_user_id,
            "credentialID": info.credential.id,
            "publicKey": _b64url(info.credential.public_key),
            "counter": int(info.credential.counter),
            "deviceType": info.credential_device_type,
            "transports": transports,
            "backedUp": bool(info.credential_backed_up),
            "createdAt": _now(),
            "aaguid": info.aaguid,
        },
    )
    await ctx.auth.adapter.delete_many(
        model="verification",
        where=(Where(field="identifier", value=verification_token),),
    )
    return new_passkey


async def _verify_authentication(ctx: EndpointContext) -> dict[str, Any]:
    opts = _opts(ctx)
    origin = _resolve_origin(ctx, opts)
    if not origin:
        raise APIError(400, "INVALID_REQUEST", message="origin missing")

    resp = ctx.body.response
    cookie_name = _challenge_cookie_name(opts)
    verification_token = _get_signed_cookie(ctx, cookie_name)
    if not verification_token:
        raise APIError(400, "CHALLENGE_NOT_FOUND")

    data = await ctx.auth.adapter.find_one(
        model="verification",
        where=(Where(field="identifier", value=verification_token),),
    )
    if not data:
        raise APIError(400, "CHALLENGE_NOT_FOUND")
    parsed = json.loads(str(data["value"]))
    expected_challenge = parsed["expectedChallenge"]

    passkey = await ctx.auth.adapter.find_one(
        model="passkey",
        where=(Where(field="credentialID", value=resp["id"]),),
    )
    if not passkey:
        raise APIError(401, "PASSKEY_NOT_FOUND")

    try:
        base_url = ctx.auth.options.base_url
        verification = _wa.verify_authentication_response(
            response=resp,
            expected_challenge=_b64url_decode(expected_challenge),
            expected_origin=origin,
            expected_rpid=_get_rp_id(opts, base_url),
            credential={
                "id": passkey["credentialID"],
                "public_key": _credential_id_bytes(passkey["publicKey"]),
                "counter": int(passkey.get("counter") or 0),
            },
            require_user_verification=False,
        )
        if not verification.verified:
            raise APIError(401, "AUTHENTICATION_FAILED")

        if opts.authentication and opts.authentication.after_verification:
            await _maybe_await(
                opts.authentication.after_verification(
                    ctx=ctx, verification=verification, clientData=resp
                )
            )

        await ctx.auth.adapter.update(
            model="passkey",
            where=(Where(field="id", value=passkey["id"]),),
            update={"counter": int(verification.authentication_info.new_counter)},
        )
        session, cookies = await create_session(
            ctx.auth,
            user_id=passkey["userId"],
            ip_address=ctx.request.headers.get("x-forwarded-for"),
            user_agent=ctx.request.headers.get("user-agent"),
        )
        user = await ctx.auth.adapter.find_one(
            model="user", where=(Where(field="id", value=passkey["userId"]),)
        )
        if not user:
            raise APIError(500, "INTERNAL", message="User not found")
        ctx.set_cookies.extend(cookies)
        await ctx.auth.adapter.delete_many(
            model="verification",
            where=(Where(field="identifier", value=verification_token),),
        )
        return {
            "session": {
                "id": session.id,
                "userId": session.user_id,
                "token": session.token,
                "expiresAt": session.expires_at,
            },
            "user": _public_user(user),
        }
    except APIError:
        raise
    except Exception:
        raise APIError(400, "AUTHENTICATION_FAILED") from None


def _public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": user.get("id"),
        "email": user.get("email"),
        "emailVerified": user.get("emailVerified"),
        "name": user.get("name"),
        "image": user.get("image"),
        "createdAt": user.get("createdAt"),
        "updatedAt": user.get("updatedAt"),
    }


def _resolve_origin(ctx: EndpointContext, opts: PasskeyOptions) -> str:
    if opts.origin:
        if isinstance(opts.origin, list):
            return opts.origin[0] if opts.origin else ""
        return opts.origin
    return ctx.request.headers.get("origin") or ""


async def _list_passkeys(ctx: EndpointContext) -> list[dict[str, Any]]:
    passkeys = await ctx.auth.adapter.find_many(
        model="passkey",
        where=(Where(field="userId", value=ctx.session.user_id),),
    )
    return list(passkeys)


async def _require_ownership(ctx: EndpointContext, passkey_id: str) -> dict[str, Any]:
    existing = await ctx.auth.adapter.find_one(
        model="passkey", where=(Where(field="id", value=passkey_id),)
    )
    if not existing:
        raise APIError(404, "PASSKEY_NOT_FOUND")
    if existing.get("userId") != ctx.session.user_id:
        raise APIError(401, "PASSKEY_NOT_FOUND")
    return existing


async def _delete_passkey(ctx: EndpointContext) -> dict[str, Any]:
    await _require_ownership(ctx, ctx.body.id)
    await ctx.auth.adapter.delete_many(
        model="passkey", where=(Where(field="id", value=ctx.body.id),)
    )
    return {"status": True}


async def _update_passkey(ctx: EndpointContext) -> dict[str, Any]:
    await _require_ownership(ctx, ctx.body.id)
    updated = await ctx.auth.adapter.update(
        model="passkey",
        where=(Where(field="id", value=ctx.body.id),),
        update={"name": ctx.body.name},
    )
    if not updated:
        raise APIError(500, "FAILED_TO_UPDATE_PASSKEY")
    return {"passkey": updated}


# ----- bodies ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class VerifyRegistrationBody:
    response: dict[str, Any]
    name: str | None = None


@dataclass(frozen=True, slots=True)
class VerifyAuthenticationBody:
    response: dict[str, Any]


@dataclass(frozen=True, slots=True)
class DeletePasskeyBody:
    id: str


@dataclass(frozen=True, slots=True)
class UpdatePasskeyBody:
    id: str
    name: str


# ----- endpoint registry -----------------------------------------------------

# Set at plugin construction so handlers can read options even before init runs.
_OPTIONS_REGISTRY: dict[str, PasskeyOptions] = {}


def build_endpoints(opts: PasskeyOptions) -> tuple[AuthEndpoint, ...]:
    require_session = opts.registration.require_session if opts.registration else True
    return (
        create_auth_endpoint(
            "/passkey/generate-register-options",
            EndpointOptions(method="GET", requires_session=require_session),
            _generate_register_options,
        ),
        create_auth_endpoint(
            "/passkey/generate-authenticate-options",
            EndpointOptions(method="GET"),
            _generate_authenticate_options,
        ),
        create_auth_endpoint(
            "/passkey/verify-registration",
            EndpointOptions(
                method="POST",
                body=VerifyRegistrationBody,
                requires_session=require_session,
            ),
            _verify_registration,
        ),
        create_auth_endpoint(
            "/passkey/verify-authentication",
            EndpointOptions(method="POST", body=VerifyAuthenticationBody),
            _verify_authentication,
        ),
        create_auth_endpoint(
            "/passkey/list-user-passkeys",
            EndpointOptions(method="GET", requires_session=True),
            _list_passkeys,
        ),
        create_auth_endpoint(
            "/passkey/delete-passkey",
            EndpointOptions(
                method="POST", body=DeletePasskeyBody, requires_session=True
            ),
            _delete_passkey,
        ),
        create_auth_endpoint(
            "/passkey/update-passkey",
            EndpointOptions(
                method="POST", body=UpdatePasskeyBody, requires_session=True
            ),
            _update_passkey,
        ),
    )


__all__ = [
    "PASSKEY_ERROR_CODES",
    "build_endpoints",
]
