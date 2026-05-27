"""SIWE (Sign-In With Ethereum) plugin route handlers.

Mirrors `reference/packages/better-auth/src/plugins/siwe/index.ts` with a few
simplifications: we accept message + signature directly (rather than going via a
CACAO envelope) and parse the EIP-4361 message ourselves so we can replay the
nonce check + signer recovery.
"""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass

from kernia.api.endpoint import create_auth_endpoint
from kernia.context import create_session
from kernia.error import APIError
from kernia.types.adapter import Where
from kernia.types.context import EndpointContext
from kernia.types.endpoint import AuthEndpoint, EndpointOptions


NONCE_TTL_SECONDS = 15 * 60  # 15 minutes, matches reference impl


@dataclass(frozen=True, slots=True)
class GetNonceQuery:
    address: str


@dataclass(frozen=True, slots=True)
class VerifyBody:
    message: str
    signature: str
    address: str
    chain_id: int = 1
    email: str | None = None


def _to_checksum(addr: str) -> str:
    """EIP-55 checksum address (uses eth_utils via eth_account)."""
    from eth_utils import to_checksum_address

    return to_checksum_address(addr)


_NONCE_RE = re.compile(r"^Nonce:\s*(?P<nonce>\S+)\s*$", re.MULTILINE)
_ADDRESS_RE = re.compile(r"\n(?P<addr>0x[a-fA-F0-9]{40})\n")


def _extract_nonce(message: str) -> str | None:
    m = _NONCE_RE.search(message)
    return m.group("nonce") if m else None


async def _get_nonce(ctx: EndpointContext) -> dict[str, object]:
    address_raw = ctx.request.query.get("address")
    if isinstance(address_raw, list):
        address_raw = address_raw[0]
    if not address_raw:
        raise APIError(400, "INVALID_REQUEST", message="address query param required")
    address = _to_checksum(address_raw)
    nonce = secrets.token_hex(16)
    now = int(time.time())
    await ctx.auth.adapter.create(
        model="verification",
        data={
            "identifier": f"siwe:{address}",
            "value": nonce,
            "expiresAt": now + NONCE_TTL_SECONDS,
        },
    )
    return {"nonce": nonce}


async def _verify(ctx: EndpointContext) -> dict[str, object]:
    body: VerifyBody = ctx.body
    address = _to_checksum(body.address)

    # Parse and consume nonce.
    expected_nonce = _extract_nonce(body.message)
    if not expected_nonce:
        raise APIError(401, "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE")

    verification = await ctx.auth.adapter.find_one(
        model="verification",
        where=(
            Where(field="identifier", value=f"siwe:{address}"),
            Where(field="value", value=expected_nonce),
        ),
    )
    if not verification or int(verification.get("expiresAt", 0)) < int(time.time()):
        raise APIError(401, "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE")

    # Verify signature via eth_account.
    try:
        from eth_account.messages import encode_defunct
        from eth_account import Account
    except ImportError as exc:
        raise APIError(500, "INTERNAL", message=f"eth-account not installed: {exc}") from exc

    encoded = encode_defunct(text=body.message)
    try:
        recovered = Account.recover_message(encoded, signature=body.signature)
    except Exception as exc:  # pragma: no cover — bad sig
        raise APIError(401, "INVALID_SIWE_SIGNATURE", message=str(exc)) from exc
    if _to_checksum(recovered) != address:
        raise APIError(401, "INVALID_SIWE_SIGNATURE")

    # Burn the nonce.
    await ctx.auth.adapter.delete(
        model="verification",
        where=(
            Where(field="identifier", value=f"siwe:{address}"),
            Where(field="value", value=expected_nonce),
        ),
    )

    # Optional ENS reverse-lookup (best-effort; never blocks sign-in on failure).
    from kernia.plugins.siwe import _resolver_for

    ens_name: str | None = None
    resolver = _resolver_for("siwe")
    if resolver is not None:
        try:
            ens_name = await resolver(address)
        except Exception:
            ens_name = None

    # Lookup or create user.
    user = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="walletAddress", value=address),),
    )
    now = int(time.time())
    if not user:
        email = body.email or f"{address.lower()}@siwe.local"
        user = await ctx.auth.adapter.create(
            model="user",
            data={
                "email": email,
                "name": ens_name or address,
                "walletAddress": address,
                "ensName": ens_name,
                "emailVerified": False,
                "createdAt": now,
                "updatedAt": now,
            },
        )
        await ctx.auth.adapter.create(
            model="account",
            data={
                "userId": user["id"],
                "accountId": address,
                "providerId": "siwe",
                "createdAt": now,
                "updatedAt": now,
            },
        )
    elif ens_name and user.get("ensName") != ens_name:
        # Existing user: refresh stale ENS name on each sign-in.
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
        "user": user,
        "session": {"id": session.id, "expiresAt": session.expires_at},
        "token": session.token,
        "success": True,
    }


GET_NONCE = create_auth_endpoint(
    "/siwe/nonce",
    EndpointOptions(method="GET"),
    _get_nonce,
)

VERIFY = create_auth_endpoint(
    "/siwe/verify",
    EndpointOptions(method="POST", body=VerifyBody),
    _verify,
)


ALL: tuple[AuthEndpoint, ...] = (GET_NONCE, VERIFY)
