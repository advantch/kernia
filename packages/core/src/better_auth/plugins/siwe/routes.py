"""SIWE (Sign-In With Ethereum) plugin route handlers.

Mirrors `reference/packages/better-auth/src/plugins/siwe/index.ts`.

Like upstream, message verification is *pluggable*: ``verify_message`` and
``get_nonce`` are supplied via :class:`SIWEOptions`. The defaults fall back to a
real ``eth_account`` signature recovery + a 17-char alphanumeric nonce so the
plugin works out of the box, but tests (and apps with a different wallet stack)
can inject their own.

Endpoints:
  POST /siwe/nonce      — body {walletAddress|address, chainId?} → {nonce}
  POST /siwe/get-nonce  — alias of /siwe/nonce
  GET  /siwe/nonce      — back-compat: ?address=...&chainId=... → {nonce}
  POST /siwe/verify     — body {message, signature, walletAddress|address,
                                chainId?, email?} → {token, success, user}

Nonces are stored chain-scoped (``siwe:<checksumAddress>:<chainId>``), matching
upstream, and consumed on a successful verify (single use).
"""

from __future__ import annotations

import re
import secrets
import string
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

from better_auth.api.endpoint import create_auth_endpoint
from better_auth.context import create_session
from better_auth.error import APIError
from better_auth.types.adapter import Where
from better_auth.types.context import EndpointContext
from better_auth.types.endpoint import AuthEndpoint, EndpointOptions

NONCE_TTL_SECONDS = 15 * 60  # 15 minutes, matches reference impl
_ADDRESS_RE = re.compile(r"^0[xX][a-fA-F0-9]{40}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_NONCE_ALPHABET = string.ascii_letters + string.digits

VerifyMessage = Callable[[Mapping[str, Any]], Awaitable[bool]]
GetNonce = Callable[[], Awaitable[str]]
ENSLookup = Callable[[Mapping[str, Any]], Awaitable[Mapping[str, Any] | None]]


@dataclass(frozen=True, slots=True)
class SIWEOptions:
    """Per-instance SIWE configuration. Mirrors upstream ``SIWEPluginOptions``."""

    domain: str = "localhost"
    email_domain_name: str | None = None
    anonymous: bool = True
    get_nonce: GetNonce | None = None
    verify_message: VerifyMessage | None = None
    ens_lookup: ENSLookup | None = None


# Module-level options registry (keyed by plugin id, like the ENS resolver
# registry). The plugin dataclass is frozen, so route handlers look up options
# here rather than carrying them on the instance.
_OPTIONS: dict[str, SIWEOptions] = {}


def configure(opts: SIWEOptions) -> None:
    _OPTIONS["siwe"] = opts


def _options() -> SIWEOptions:
    return _OPTIONS.get("siwe", SIWEOptions())


async def _default_get_nonce() -> str:
    return "".join(secrets.choice(_NONCE_ALPHABET) for _ in range(17))


_NONCE_RE = re.compile(r"^Nonce:\s*(?P<nonce>\S+)\s*$", re.MULTILINE)


def _extract_nonce(message: str) -> str | None:
    m = _NONCE_RE.search(message)
    return m.group("nonce") if m else None


async def _default_verify_message(args: Mapping[str, Any]) -> bool:
    """Recover the signer from an EIP-191 message and compare to the address."""
    try:
        from eth_account import Account
        from eth_account.messages import encode_defunct
    except ImportError as exc:  # pragma: no cover
        raise APIError(500, "INTERNAL", message=f"eth-account not installed: {exc}") from exc

    message = args["message"]
    signature = args["signature"]
    address = args["address"]
    encoded = encode_defunct(text=message)
    try:
        recovered = Account.recover_message(encoded, signature=signature)
    except Exception:
        return False
    return _to_checksum(recovered) == _to_checksum(address)


def _to_checksum(addr: str) -> str:
    """EIP-55 checksum address (uses eth_utils via eth_account)."""
    from eth_utils import to_checksum_address

    return to_checksum_address(addr)


def _validate_address(raw: str | None) -> str:
    if not raw or not _ADDRESS_RE.match(raw):
        raise APIError(
            400,
            "BAD_REQUEST",
            message=(
                "[body.walletAddress] Invalid string: must match pattern "
                "/^0[xX][a-fA-F0-9]{40}$/i; [body.walletAddress] Too small: "
                "expected string to have >=42 characters"
            ),
        )
    return raw


def _q(qs: Mapping[str, Any], key: str) -> str | None:
    v = qs.get(key)
    if isinstance(v, list):
        return v[0] if v else None
    return v


# --------------------------------------------------------------------------------------
# Nonce endpoints
# --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _NonceBody:
    walletAddress: str | None = None
    address: str | None = None
    chainId: int = 1


async def _issue_nonce(ctx: EndpointContext, raw_address: str | None, chain_id: int) -> dict[str, object]:
    address = _to_checksum(_validate_address(raw_address))
    opts = _options()
    get_nonce = opts.get_nonce or _default_get_nonce
    nonce = await get_nonce()
    now = int(time.time())
    await ctx.auth.adapter.create(
        model="verification",
        data={
            "identifier": f"siwe:{address}:{chain_id}",
            "value": nonce,
            "expiresAt": now + NONCE_TTL_SECONDS,
        },
    )
    return {"nonce": nonce}


async def _post_nonce(ctx: EndpointContext) -> dict[str, object]:
    body: _NonceBody = ctx.body
    raw = body.walletAddress or body.address
    return await _issue_nonce(ctx, raw, body.chainId)


async def _get_nonce(ctx: EndpointContext) -> dict[str, object]:
    qs = ctx.request.query
    raw = _q(qs, "address") or _q(qs, "walletAddress")
    chain_id_raw = _q(qs, "chainId")
    chain_id = int(chain_id_raw) if chain_id_raw else 1
    return await _issue_nonce(ctx, raw, chain_id)


# --------------------------------------------------------------------------------------
# Verify endpoint
# --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class VerifyBody:
    message: str
    signature: str
    walletAddress: str | None = None
    address: str | None = None
    chainId: int = 1
    email: str | None = None


async def _verify(ctx: EndpointContext) -> dict[str, object]:
    body: VerifyBody = ctx.body
    opts = _options()
    is_anon = opts.anonymous

    raw_address = body.walletAddress or body.address
    address = _to_checksum(_validate_address(raw_address))
    chain_id = body.chainId

    # Email validation (only matters when anonymous is disabled).
    if not is_anon:
        if body.email is None:
            raise APIError(
                400,
                "BAD_REQUEST",
                message="[body.email] Email is required when the anonymous plugin option is disabled.",
            )
        if body.email == "":
            raise APIError(
                400,
                "BAD_REQUEST",
                message=(
                    "[body.email] Invalid email address; [body.email] Email is "
                    "required when the anonymous plugin option is disabled."
                ),
            )
        if not _EMAIL_RE.match(body.email):
            raise APIError(400, "BAD_REQUEST", message="[body.email] Invalid email address")

    identifier = f"siwe:{address}:{chain_id}"
    verification = await ctx.auth.adapter.find_one(
        model="verification",
        where=(Where(field="identifier", value=identifier),),
    )
    if not verification or int(verification.get("expiresAt", 0)) < int(time.time()):
        raise APIError(
            401,
            "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
            message="Unauthorized: Invalid or expired nonce",
        )

    nonce = verification["value"]
    verify_message = opts.verify_message or _default_verify_message
    verified = await verify_message(
        {
            "message": body.message,
            "signature": body.signature,
            "address": address,
            "chainId": chain_id,
            "cacao": {
                "h": {"t": "caip122"},
                "p": {
                    "domain": opts.domain,
                    "aud": opts.domain,
                    "nonce": nonce,
                    "iss": opts.domain,
                    "version": "1",
                },
                "s": {"t": "eip191", "s": body.signature},
            },
        }
    )
    if not verified:
        raise APIError(401, "UNAUTHORIZED", message="Unauthorized: Invalid SIWE signature")

    # Burn the nonce (single use).
    await ctx.auth.adapter.delete(
        model="verification",
        where=(Where(field="identifier", value=identifier),),
    )

    now = int(time.time())

    # Resolve / create the user via the walletAddress model.
    existing_wallet = await ctx.auth.adapter.find_one(
        model="walletAddress",
        where=(
            Where(field="address", value=address),
            Where(field="chainId", value=chain_id),
        ),
    )
    user = None
    if existing_wallet is not None:
        user = await ctx.auth.adapter.find_one(
            model="user", where=(Where(field="id", value=existing_wallet["userId"]),)
        )
    else:
        any_wallet = await ctx.auth.adapter.find_one(
            model="walletAddress", where=(Where(field="address", value=address),)
        )
        if any_wallet is not None:
            user = await ctx.auth.adapter.find_one(
                model="user", where=(Where(field="id", value=any_wallet["userId"]),)
            )

    # ENS / name lookup (best-effort; never blocks sign-in).
    ens_name: str | None = None
    avatar: str | None = None
    lookup = opts.ens_lookup or _ens_resolver_adapter()
    if lookup is not None:
        try:
            result = await lookup({"walletAddress": address})
        except Exception:
            result = None
        if result:
            ens_name = result.get("name")
            avatar = result.get("avatar")

    if user is None:
        domain = opts.email_domain_name or _origin(ctx.auth.base_url)
        user_email = body.email if (not is_anon and body.email) else f"{address}@{domain}"
        user = await ctx.auth.adapter.create(
            model="user",
            data={
                "email": user_email,
                "name": ens_name or address,
                "image": avatar or "",
                "walletAddress": address,
                "ensName": ens_name,
                "emailVerified": False,
                "createdAt": now,
                "updatedAt": now,
            },
        )
        await ctx.auth.adapter.create(
            model="walletAddress",
            data={
                "userId": user["id"],
                "address": address,
                "chainId": chain_id,
                "isPrimary": True,
                "createdAt": now,
            },
        )
        await ctx.auth.adapter.create(
            model="account",
            data={
                "userId": user["id"],
                "providerId": "siwe",
                "accountId": f"{address}:{chain_id}",
                "createdAt": now,
                "updatedAt": now,
            },
        )
    else:
        if existing_wallet is None:
            await ctx.auth.adapter.create(
                model="walletAddress",
                data={
                    "userId": user["id"],
                    "address": address,
                    "chainId": chain_id,
                    "isPrimary": False,
                    "createdAt": now,
                },
            )
            await ctx.auth.adapter.create(
                model="account",
                data={
                    "userId": user["id"],
                    "providerId": "siwe",
                    "accountId": f"{address}:{chain_id}",
                    "createdAt": now,
                    "updatedAt": now,
                },
            )
        if ens_name and user.get("ensName") != ens_name:
            await ctx.auth.adapter.update(
                model="user",
                where=(Where(field="id", value=user["id"]),),
                update={"ensName": ens_name, "updatedAt": now},
            )
            user["ensName"] = ens_name

    session, cookies = await create_session(
        ctx.auth,
        user_id=user["id"],
        ip_address=ctx.request.headers.get("x-forwarded-for"),
        user_agent=ctx.request.headers.get("user-agent"),
    )
    ctx.set_cookies.extend(cookies)
    return {
        "token": session.token,
        "success": True,
        "user": user,
    }


def _ens_resolver_adapter() -> ENSLookup | None:
    """Bridge the legacy ``ENSResolver`` registry into the upstream ``ensLookup``
    shape, so the existing ENS tests (which register a `(address) -> name`
    resolver) keep working."""
    from better_auth.plugins.siwe import _resolver_for

    resolver = _resolver_for("siwe")
    if resolver is None:
        return None

    async def _lookup(args: Mapping[str, Any]) -> Mapping[str, Any] | None:
        name = await resolver(args["walletAddress"])
        return {"name": name} if name is not None else {"name": None}

    return _lookup


def _origin(base_url: str | None) -> str:
    if not base_url:
        return "localhost"
    from urllib.parse import urlparse

    parsed = urlparse(base_url)
    return parsed.netloc or base_url


POST_NONCE = create_auth_endpoint(
    "/siwe/nonce",
    EndpointOptions(method="POST", body=_NonceBody),
    _post_nonce,
)

GET_NONCE = create_auth_endpoint(
    "/siwe/nonce",
    EndpointOptions(method="GET"),
    _get_nonce,
)

GET_NONCE_ALIAS = create_auth_endpoint(
    "/siwe/get-nonce",
    EndpointOptions(method="POST", body=_NonceBody),
    _post_nonce,
)

VERIFY = create_auth_endpoint(
    "/siwe/verify",
    EndpointOptions(method="POST", body=VerifyBody),
    _verify,
)


ALL: tuple[AuthEndpoint, ...] = (POST_NONCE, GET_NONCE, GET_NONCE_ALIAS, VERIFY)
