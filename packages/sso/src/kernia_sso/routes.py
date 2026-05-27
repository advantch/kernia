"""SSO endpoints — registration, domain verification, OIDC + SAML sign-in.

Path conventions match the lane H plan:

  * `/sso/register-provider`           (POST, admin)
  * `/sso/update-provider`             (POST, admin)
  * `/sso/delete-provider`             (POST, admin)
  * `/sso/list-providers`              (GET, admin)
  * `/sso/register-domain`             (POST, admin)
  * `/sso/verify-domain`               (POST, admin)
  * `/sso/oidc/sign-in/:provider_id`   (GET)
  * `/sso/oidc/callback/:provider_id`  (GET)
  * `/sso/saml/metadata/:provider_id`  (GET)
  * `/sso/saml/sign-in/:provider_id`   (GET)
  * `/sso/saml/acs/:provider_id`       (POST)
  * `/sso/saml/slo/:provider_id`       (POST)

The OIDC/SAML state values that survive the IdP round-trip are stored in the
core `verification` table, identifier-keyed with the `sso:` prefix; that keeps
us from having to add a fourth core table.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from typing import Any

import httpx
from pydantic import BaseModel, Field

from kernia.api.endpoint import create_auth_endpoint
from kernia.api.request import RedirectResponse
from kernia.context import create_session
from kernia.error import APIError
from kernia.types.adapter import Where
from kernia.types.context import EndpointContext
from kernia.types.endpoint import AuthEndpoint, EndpointOptions

from kernia_sso import oidc as oidc_helpers
from kernia_sso import saml as saml_helpers
from kernia_sso.domain import (
    email_domain,
    make_verification_token,
)


_OPTS_KEY = "sso"


def _now() -> int:
    return int(time.time())


def _opts(ctx: EndpointContext) -> dict[str, Any]:
    return dict(ctx.auth.options.advanced.get(_OPTS_KEY) or {})


async def _require_admin(ctx: EndpointContext) -> None:
    """Reject the request unless the caller is an administrator.

    Admin-ness is configurable. By default the plugin requires a session and
    allows it through; deployments should layer their own RBAC via the
    `is_admin` hook on the plugin options:

        advanced={"sso": {"is_admin": lambda user: user.email == "...", ...}}

    When `disable_admin_check` is True (only useful in tests) the check is
    skipped entirely.
    """
    opts = _opts(ctx)
    if opts.get("disable_admin_check"):
        return
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    is_admin = opts.get("is_admin")
    if is_admin is None:
        return
    user = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="id", value=ctx.session.user_id),),
    )
    if user is None or not bool(is_admin(user)):
        raise APIError(403, "SSO_ADMIN_REQUIRED")


def _http_client(ctx: EndpointContext) -> httpx.AsyncClient | None:
    """If the deployment supplied a test transport, hand back an AsyncClient on it."""
    transport = _opts(ctx).get("http_transport")
    if transport is None:
        return None
    return httpx.AsyncClient(transport=transport, timeout=30.0)


# ---------------------------------------------------------------------------
# Provider CRUD
# ---------------------------------------------------------------------------


class RegisterProviderBody(BaseModel):
    issuer: str
    kind: str  # "saml" | "oidc"
    name: str | None = None
    domains: list[str] = Field(default_factory=list)
    oidc_config: dict[str, Any] | None = Field(default=None, alias="oidcConfig")
    saml_config: dict[str, Any] | None = Field(default=None, alias="samlConfig")
    mapping: dict[str, str] | None = None

    model_config = {"populate_by_name": True}


class UpdateProviderBody(BaseModel):
    id: str
    name: str | None = None
    domains: list[str] | None = None
    oidc_config: dict[str, Any] | None = Field(default=None, alias="oidcConfig")
    saml_config: dict[str, Any] | None = Field(default=None, alias="samlConfig")
    mapping: dict[str, str] | None = None

    model_config = {"populate_by_name": True}


class DeleteProviderBody(BaseModel):
    id: str


class RegisterDomainBody(BaseModel):
    provider_id: str = Field(alias="ssoProviderId")
    domain: str

    model_config = {"populate_by_name": True}


class VerifyDomainBody(BaseModel):
    domain: str
    token: str


async def _register_provider(ctx: EndpointContext) -> dict[str, Any]:
    await _require_admin(ctx)
    body: RegisterProviderBody = ctx.body
    kind = body.kind.lower()
    if kind not in ("saml", "oidc"):
        raise APIError(400, "SSO_INVALID_KIND")
    if kind == "saml" and not body.saml_config:
        raise APIError(400, "SSO_MISSING_CONFIG", message="samlConfig is required")
    if kind == "oidc" and not body.oidc_config:
        raise APIError(400, "SSO_MISSING_CONFIG", message="oidcConfig is required")

    existing = await ctx.auth.adapter.find_one(
        model="ssoProvider",
        where=(Where(field="issuer", value=body.issuer),),
    )
    if existing is not None:
        raise APIError(409, "SSO_PROVIDER_EXISTS")

    now = _now()
    row = await ctx.auth.adapter.create(
        model="ssoProvider",
        data={
            "issuer": body.issuer,
            "kind": kind,
            "name": body.name,
            "domains": json.dumps(body.domains),
            "oidcConfig": json.dumps(body.oidc_config) if body.oidc_config else None,
            "samlConfig": json.dumps(body.saml_config) if body.saml_config else None,
            "userInfoMapping": json.dumps(body.mapping or {}),
            "createdAt": now,
            "updatedAt": now,
        },
    )
    return {"provider": _serialize_provider(row)}


async def _update_provider(ctx: EndpointContext) -> dict[str, Any]:
    await _require_admin(ctx)
    body: UpdateProviderBody = ctx.body
    update: dict[str, Any] = {"updatedAt": _now()}
    if body.name is not None:
        update["name"] = body.name
    if body.domains is not None:
        update["domains"] = json.dumps(body.domains)
    if body.oidc_config is not None:
        update["oidcConfig"] = json.dumps(body.oidc_config)
    if body.saml_config is not None:
        update["samlConfig"] = json.dumps(body.saml_config)
    if body.mapping is not None:
        update["userInfoMapping"] = json.dumps(body.mapping)
    row = await ctx.auth.adapter.update(
        model="ssoProvider",
        where=(Where(field="id", value=body.id),),
        update=update,
    )
    if row is None:
        raise APIError(404, "SSO_PROVIDER_NOT_FOUND")
    return {"provider": _serialize_provider(row)}


async def _delete_provider(ctx: EndpointContext) -> dict[str, Any]:
    await _require_admin(ctx)
    body: DeleteProviderBody = ctx.body
    await ctx.auth.adapter.delete_many(
        model="ssoDomain",
        where=(Where(field="ssoProviderId", value=body.id),),
    )
    await ctx.auth.adapter.delete(
        model="ssoProvider",
        where=(Where(field="id", value=body.id),),
    )
    return {"success": True}


async def _list_providers(ctx: EndpointContext) -> dict[str, Any]:
    await _require_admin(ctx)
    rows = await ctx.auth.adapter.find_many(model="ssoProvider")
    return {"providers": [_serialize_provider(r) for r in rows]}


def _serialize_provider(row: dict[str, Any]) -> dict[str, Any]:
    """Project the storage row onto the wire shape (decode JSON columns)."""
    return {
        "id": row["id"],
        "issuer": row["issuer"],
        "kind": row["kind"],
        "name": row.get("name"),
        "domains": json.loads(row.get("domains") or "[]"),
        "oidcConfig": json.loads(row["oidcConfig"]) if row.get("oidcConfig") else None,
        "samlConfig": json.loads(row["samlConfig"]) if row.get("samlConfig") else None,
        "mapping": json.loads(row.get("userInfoMapping") or "{}"),
        "createdAt": row.get("createdAt"),
        "updatedAt": row.get("updatedAt"),
    }


# ---------------------------------------------------------------------------
# Domain verification
# ---------------------------------------------------------------------------


async def _register_domain(ctx: EndpointContext) -> dict[str, Any]:
    await _require_admin(ctx)
    body: RegisterDomainBody = ctx.body
    domain = body.domain.strip().lower()
    if not domain:
        raise APIError(400, "INVALID_REQUEST", message="domain is required")

    provider = await ctx.auth.adapter.find_one(
        model="ssoProvider",
        where=(Where(field="id", value=body.provider_id),),
    )
    if provider is None:
        raise APIError(404, "SSO_PROVIDER_NOT_FOUND")

    token = make_verification_token()
    # If a row already exists for this domain, replace its token + un-verify it.
    existing = await ctx.auth.adapter.find_one(
        model="ssoDomain",
        where=(Where(field="domain", value=domain),),
    )
    if existing is not None:
        await ctx.auth.adapter.update(
            model="ssoDomain",
            where=(Where(field="id", value=existing["id"]),),
            update={
                "ssoProviderId": body.provider_id,
                "verified": False,
                "verificationToken": token,
            },
        )
    else:
        await ctx.auth.adapter.create(
            model="ssoDomain",
            data={
                "domain": domain,
                "ssoProviderId": body.provider_id,
                "verified": False,
                "verificationToken": token,
                "createdAt": _now(),
            },
        )
    return {
        "domain": domain,
        "token": token,
        "instructions": (
            f"Publish a DNS TXT record `_better-auth-token.{domain}` with value "
            f"`{token}`, or expose it at `https://{domain}/.well-known/"
            f"better-auth-domain.txt`, then POST /sso/verify-domain with the "
            f"same token."
        ),
    }


async def _verify_domain(ctx: EndpointContext) -> dict[str, Any]:
    await _require_admin(ctx)
    body: VerifyDomainBody = ctx.body
    domain = body.domain.strip().lower()
    row = await ctx.auth.adapter.find_one(
        model="ssoDomain",
        where=(Where(field="domain", value=domain),),
    )
    if row is None:
        raise APIError(404, "SSO_DOMAIN_NOT_FOUND")
    if not secrets.compare_digest(row["verificationToken"], body.token):
        raise APIError(400, "SSO_DOMAIN_VERIFICATION_FAILED")
    await ctx.auth.adapter.update(
        model="ssoDomain",
        where=(Where(field="id", value=row["id"]),),
        update={"verified": True},
    )
    return {"domain": domain, "verified": True}


# ---------------------------------------------------------------------------
# OIDC sign-in
# ---------------------------------------------------------------------------


async def _load_provider(ctx: EndpointContext, provider_id: str) -> dict[str, Any]:
    row = await ctx.auth.adapter.find_one(
        model="ssoProvider",
        where=(Where(field="id", value=provider_id),),
    )
    if row is None:
        raise APIError(404, "SSO_PROVIDER_NOT_FOUND")
    return row


async def _oidc_sign_in(ctx: EndpointContext) -> RedirectResponse:
    provider_id = ctx.path_params["provider_id"]
    provider = await _load_provider(ctx, provider_id)
    if provider["kind"] != "oidc":
        raise APIError(400, "SSO_INVALID_KIND", message="provider is not OIDC")

    config = oidc_helpers.parse_config(provider.get("oidcConfig"))
    callback = (
        ctx.request.query.get("callback")
        or ctx.request.query.get("callbackURL")
        or "/"
    )
    if isinstance(callback, list):
        callback = callback[0]

    client = _http_client(ctx)
    try:
        discovery = await oidc_helpers.discover(
            config["issuer"], http_client=client
        )
    finally:
        if client is not None:
            await client.aclose()

    state = secrets.token_urlsafe(24)
    redirect_uri = (
        config.get("redirectUri")
        or f"{ctx.auth.base_url}/sso/oidc/callback/{provider_id}"
    )

    # Persist state -> {provider_id, callback, code_verifier?} in verification table.
    await ctx.auth.adapter.create(
        model="verification",
        data={
            "identifier": f"sso:oidc-state:{state}",
            "value": json.dumps({
                "provider_id": provider_id,
                "callback": callback,
                "redirect_uri": redirect_uri,
            }),
            "expiresAt": _now() + 600,
            "createdAt": _now(),
            "updatedAt": _now(),
        },
    )
    authorize_endpoint = (
        config.get("authorizationEndpoint")
        or discovery["authorization_endpoint"]
    )
    url = oidc_helpers.build_authorize_url(
        authorization_endpoint=authorize_endpoint,
        client_id=config["clientId"],
        redirect_uri=redirect_uri,
        state=state,
        scopes=tuple(config.get("scopes") or ("openid", "email", "profile")),
    )
    return RedirectResponse(location=url)


async def _oidc_callback(ctx: EndpointContext) -> dict[str, Any]:
    provider_id = ctx.path_params["provider_id"]
    state = ctx.request.query.get("state")
    code = ctx.request.query.get("code")
    if isinstance(state, list):
        state = state[0]
    if isinstance(code, list):
        code = code[0]
    if not state or not code:
        raise APIError(400, "SSO_OIDC_STATE_INVALID")

    identifier = f"sso:oidc-state:{state}"
    where = (Where(field="identifier", value=identifier),)
    consume_one = getattr(ctx.auth.adapter, "consume_one", None)
    if consume_one is not None:
        verification = await consume_one(model="verification", where=where)
    else:
        verification = await ctx.auth.adapter.find_one(
            model="verification", where=where
        )
        if verification is not None:
            await ctx.auth.adapter.delete(model="verification", where=where)
    if verification is None:
        raise APIError(400, "SSO_OIDC_STATE_INVALID")

    data = json.loads(verification["value"])
    if data.get("provider_id") != provider_id:
        raise APIError(400, "SSO_OIDC_STATE_INVALID")

    provider = await _load_provider(ctx, provider_id)
    config = oidc_helpers.parse_config(provider.get("oidcConfig"))
    mapping = json.loads(provider.get("userInfoMapping") or "{}")
    redirect_uri = data["redirect_uri"]

    client = _http_client(ctx)
    try:
        discovery = await oidc_helpers.discover(
            config["issuer"], http_client=client
        )
        try:
            claims = await oidc_helpers.complete_signin(
                code=code,
                config=config,
                discovery=discovery,
                redirect_uri=redirect_uri,
                http_client=client,
            )
        except Exception as e:  # noqa: BLE001
            raise APIError(
                400, "SSO_OIDC_EXCHANGE_FAILED", message=str(e)
            ) from None
    finally:
        if client is not None:
            await client.aclose()

    user_fields = oidc_helpers.apply_mapping(claims, mapping)
    user = await _upsert_user_and_sign_in(ctx, user_fields)
    redirect = data.get("callback") or "/"
    return {
        "redirect": redirect,
        "user": user,
        "provider": _serialize_provider(provider),
    }


# ---------------------------------------------------------------------------
# SAML sign-in
# ---------------------------------------------------------------------------


def _saml_plan_for(ctx: EndpointContext, provider: dict[str, Any]) -> saml_helpers.SAMLPlan:
    config = saml_helpers.parse_config(provider.get("samlConfig"))
    # Default the SP entityId/acsUrl/sloUrl from our base URL if not set.
    sp = dict(config.get("sp") or {})
    sp.setdefault(
        "entityId", f"{ctx.auth.base_url}/sso/saml/metadata/{provider['id']}"
    )
    sp.setdefault(
        "acsUrl", f"{ctx.auth.base_url}/sso/saml/acs/{provider['id']}"
    )
    sp.setdefault(
        "sloUrl", f"{ctx.auth.base_url}/sso/saml/slo/{provider['id']}"
    )
    config["sp"] = sp
    return saml_helpers.plan_from_config(config)


async def _saml_metadata(ctx: EndpointContext) -> dict[str, Any]:
    provider_id = ctx.path_params["provider_id"]
    provider = await _load_provider(ctx, provider_id)
    plan = _saml_plan_for(ctx, provider)
    xml = await saml_helpers.sp_metadata_xml(plan)
    ctx.response_headers["content-type"] = "application/xml"
    return {"metadata": xml}


async def _saml_sign_in(ctx: EndpointContext) -> RedirectResponse:
    provider_id = ctx.path_params["provider_id"]
    provider = await _load_provider(ctx, provider_id)
    if provider["kind"] != "saml":
        raise APIError(400, "SSO_INVALID_KIND", message="provider is not SAML")
    plan = _saml_plan_for(ctx, provider)
    callback = (
        ctx.request.query.get("callback")
        or ctx.request.query.get("callbackURL")
        or "/"
    )
    if isinstance(callback, list):
        callback = callback[0]

    try:
        url, request_id = await saml_helpers.build_authn_request(plan)
    except Exception as e:  # noqa: BLE001
        raise APIError(500, "SSO_SAML_AUTHN_FAILED", message=str(e)) from None

    await ctx.auth.adapter.create(
        model="verification",
        data={
            "identifier": f"sso:saml-request:{request_id}",
            "value": json.dumps({
                "provider_id": provider_id,
                "callback": callback,
            }),
            "expiresAt": _now() + 600,
            "createdAt": _now(),
            "updatedAt": _now(),
        },
    )
    return RedirectResponse(location=url)


class SAMLAcsBody(BaseModel):
    saml_response: str | None = Field(default=None, alias="SAMLResponse")
    relay_state: str | None = Field(default=None, alias="RelayState")

    model_config = {"populate_by_name": True, "extra": "allow"}


async def _saml_acs(ctx: EndpointContext) -> dict[str, Any]:
    provider_id = ctx.path_params["provider_id"]
    provider = await _load_provider(ctx, provider_id)
    plan = _saml_plan_for(ctx, provider)

    body = ctx.body
    if isinstance(body, SAMLAcsBody):
        saml_response = body.saml_response
        relay_state = body.relay_state
    elif isinstance(body, dict):
        saml_response = body.get("SAMLResponse")
        relay_state = body.get("RelayState")
    else:
        saml_response = None
        relay_state = None
    if not saml_response:
        # Some clients put it in the query string instead.
        saml_response = ctx.request.query.get("SAMLResponse")
        if isinstance(saml_response, list):
            saml_response = saml_response[0]
    if not saml_response:
        raise APIError(
            400, "SSO_SAML_RESPONSE_INVALID", message="missing SAMLResponse"
        )

    # Pull the matching AuthnRequest if we have one (InResponseTo).
    in_response_to = None
    callback = "/"
    try:
        decoded = base64.b64decode(saml_response).decode("utf-8")
        # Cheap extract of InResponseTo without re-parsing the whole tree twice.
        idx = decoded.find('InResponseTo="')
        if idx != -1:
            end = decoded.find('"', idx + len('InResponseTo="'))
            in_response_to = decoded[idx + len('InResponseTo="') : end]
    except Exception:  # noqa: BLE001
        pass
    if in_response_to:
        identifier = f"sso:saml-request:{in_response_to}"
        where = (Where(field="identifier", value=identifier),)
        rec = await ctx.auth.adapter.find_one(model="verification", where=where)
        if rec is not None:
            await ctx.auth.adapter.delete(model="verification", where=where)
            try:
                stored = json.loads(rec["value"])
                callback = stored.get("callback") or callback
            except Exception:  # noqa: BLE001
                pass

    mode = _opts(ctx).get("saml_validation", "strict")
    try:
        if mode == "permissive":
            assertion = saml_helpers.validate_permissive(
                plan,
                saml_response_b64=saml_response,
                request_id=in_response_to,
            )
        else:
            assertion = await saml_helpers.validate_strict(
                plan,
                saml_response_b64=saml_response,
                request_id=in_response_to,
            )
    except saml_helpers.SAMLValidationError as e:
        raise APIError(400, "SSO_SAML_RESPONSE_INVALID", message=str(e)) from None

    mapping = json.loads(provider.get("userInfoMapping") or "{}")
    user_fields = saml_helpers.apply_mapping(assertion, mapping)
    if not user_fields.get("email") and assertion.name_id and "@" in assertion.name_id:
        user_fields["email"] = assertion.name_id

    if relay_state and isinstance(relay_state, str):
        callback = relay_state
    user = await _upsert_user_and_sign_in(ctx, user_fields)
    return {
        "redirect": callback,
        "user": user,
        "provider": _serialize_provider(provider),
    }


async def _saml_slo(ctx: EndpointContext) -> dict[str, Any]:
    # Best-effort SLO: revoke the current session if there is one. We don't
    # attempt to chain a LogoutRequest back to the IdP — that's a deployment
    # concern. Mirrors `enableSingleLogout` in the reference plugin.
    from kernia.context import revoke_session

    if ctx.session is not None:
        cookies = await revoke_session(ctx.auth, token=ctx.session.token)
        ctx.set_cookies.extend(cookies)
    return {"success": True}


# ---------------------------------------------------------------------------
# Shared sign-in: upsert + session
# ---------------------------------------------------------------------------


async def _upsert_user_and_sign_in(
    ctx: EndpointContext, user_fields: dict[str, Any]
) -> dict[str, Any]:
    email = user_fields.get("email")
    if not email:
        raise APIError(
            400,
            "SSO_OIDC_EXCHANGE_FAILED",
            message="IdP did not return an email claim",
        )
    user = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="email", value=email),),
    )
    now = _now()
    if user is None:
        user = await ctx.auth.adapter.create(
            model="user",
            data={
                "email": email,
                "name": user_fields.get("name"),
                "image": user_fields.get("picture") or user_fields.get("image"),
                "emailVerified": True,
                "createdAt": now,
                "updatedAt": now,
            },
        )
    elif not user.get("emailVerified"):
        await ctx.auth.adapter.update(
            model="user",
            where=(Where(field="id", value=user["id"]),),
            update={"emailVerified": True, "updatedAt": now},
        )
    session, cookies = await create_session(
        ctx.auth,
        user_id=user["id"],
        ip_address=ctx.request.headers.get("x-forwarded-for"),
        user_agent=ctx.request.headers.get("user-agent"),
    )
    ctx.set_cookies.extend(cookies)
    return user


# ---------------------------------------------------------------------------
# Endpoint registration
# ---------------------------------------------------------------------------


REGISTER_PROVIDER = create_auth_endpoint(
    "/sso/register-provider",
    EndpointOptions(method="POST", body=RegisterProviderBody),
    _register_provider,
)
UPDATE_PROVIDER = create_auth_endpoint(
    "/sso/update-provider",
    EndpointOptions(method="POST", body=UpdateProviderBody),
    _update_provider,
)
DELETE_PROVIDER = create_auth_endpoint(
    "/sso/delete-provider",
    EndpointOptions(method="POST", body=DeleteProviderBody),
    _delete_provider,
)
LIST_PROVIDERS = create_auth_endpoint(
    "/sso/list-providers",
    EndpointOptions(method="GET"),
    _list_providers,
)
REGISTER_DOMAIN = create_auth_endpoint(
    "/sso/register-domain",
    EndpointOptions(method="POST", body=RegisterDomainBody),
    _register_domain,
)
VERIFY_DOMAIN = create_auth_endpoint(
    "/sso/verify-domain",
    EndpointOptions(method="POST", body=VerifyDomainBody),
    _verify_domain,
)
OIDC_SIGN_IN = create_auth_endpoint(
    "/sso/oidc/sign-in/:provider_id",
    EndpointOptions(method="GET"),
    _oidc_sign_in,
)
OIDC_CALLBACK = create_auth_endpoint(
    "/sso/oidc/callback/:provider_id",
    EndpointOptions(method="GET"),
    _oidc_callback,
)
SAML_METADATA = create_auth_endpoint(
    "/sso/saml/metadata/:provider_id",
    EndpointOptions(method="GET"),
    _saml_metadata,
)
SAML_SIGN_IN = create_auth_endpoint(
    "/sso/saml/sign-in/:provider_id",
    EndpointOptions(method="GET"),
    _saml_sign_in,
)


SAML_ACS = create_auth_endpoint(
    "/sso/saml/acs/:provider_id",
    EndpointOptions(method="POST", body=SAMLAcsBody),
    _saml_acs,
)
SAML_SLO = create_auth_endpoint(
    "/sso/saml/slo/:provider_id",
    EndpointOptions(method="POST"),
    _saml_slo,
)


ALL: tuple[AuthEndpoint, ...] = (
    REGISTER_PROVIDER,
    UPDATE_PROVIDER,
    DELETE_PROVIDER,
    LIST_PROVIDERS,
    REGISTER_DOMAIN,
    VERIFY_DOMAIN,
    OIDC_SIGN_IN,
    OIDC_CALLBACK,
    SAML_METADATA,
    SAML_SIGN_IN,
    SAML_ACS,
    SAML_SLO,
)


__all__ = [
    "ALL",
    "DELETE_PROVIDER",
    "LIST_PROVIDERS",
    "OIDC_CALLBACK",
    "OIDC_SIGN_IN",
    "REGISTER_DOMAIN",
    "REGISTER_PROVIDER",
    "SAML_ACS",
    "SAML_METADATA",
    "SAML_SIGN_IN",
    "SAML_SLO",
    "UPDATE_PROVIDER",
    "VERIFY_DOMAIN",
]


