"""OAuth2 / OIDC primitives.

Mirrors `reference/packages/better-auth/src/oauth2/`. Provides the building blocks
(PKCE, code exchange, id_token verification) reused by every social provider.

The crypto here is deliberately the *only* place in the core that handles JWT
verification. Providers should never roll their own.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Mapping
from typing import Any

import httpx


def pkce_verifier() -> str:
    """Return a fresh PKCE code verifier."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def pkce_challenge(verifier: str) -> str:
    """Compute the S256 code challenge for a given verifier."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def random_state(n_bytes: int = 24) -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(n_bytes)).rstrip(b"=").decode("ascii")


async def exchange_code(
    *,
    token_url: str,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
    code_verifier: str | None,
    http_client: httpx.AsyncClient | None = None,
) -> Mapping[str, Any]:
    """Exchange an authorization code for tokens."""
    data: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    if code_verifier:
        data["code_verifier"] = code_verifier
    own_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=30.0)
    try:
        r = await client.post(
            token_url,
            data=data,
            headers={"accept": "application/json"},
        )
        r.raise_for_status()
        return r.json()
    finally:
        if own_client:
            await client.aclose()


async def fetch_userinfo(
    userinfo_url: str,
    *,
    access_token: str,
    http_client: httpx.AsyncClient | None = None,
) -> Mapping[str, Any]:
    """Fetch normalized userinfo from the OIDC userinfo endpoint."""
    own_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=30.0)
    try:
        r = await client.get(
            userinfo_url,
            headers={"authorization": f"Bearer {access_token}", "accept": "application/json"},
        )
        r.raise_for_status()
        return r.json()
    finally:
        if own_client:
            await client.aclose()


async def verify_id_token(
    *,
    id_token: str,
    jwks_url: str,
    audience: str,
    issuer: str,
    http_client: httpx.AsyncClient | None = None,
    now: int | None = None,
) -> Mapping[str, Any]:
    """Verify an OIDC id_token (RS256) against the provider's JWKS.

    Returns the verified claim set. Raises `ValueError` on any failure:
    bad signature, expired token, mismatched audience/issuer, missing kid, etc.

    Supports RS256 only — Google, Microsoft, Apple, and the bulk of OIDC IdPs use it.
    ES256 / EdDSA can be added later behind the same Protocol without disturbing
    callers.
    """
    header_b64, payload_b64, sig_b64 = id_token.split(".")
    header = json.loads(_b64decode(header_b64))
    if header.get("alg") != "RS256":
        raise ValueError(f"unsupported alg: {header.get('alg')}")
    kid = header.get("kid")
    if not kid:
        raise ValueError("id_token header missing kid")

    own_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=30.0)
    try:
        r = await client.get(jwks_url)
        r.raise_for_status()
        jwks = r.json()
    finally:
        if own_client:
            await client.aclose()

    key = next((k for k in jwks.get("keys", ()) if k.get("kid") == kid), None)
    if key is None:
        raise ValueError(f"no matching key for kid={kid!r}")

    _verify_rs256(
        signing_input=f"{header_b64}.{payload_b64}".encode("ascii"),
        signature=_b64decode(sig_b64),
        n_b64=key["n"],
        e_b64=key["e"],
    )

    claims = json.loads(_b64decode(payload_b64))
    _verify_claims(claims, audience=audience, issuer=issuer, now=now or int(time.time()))
    return claims


# ----- helpers -----


def _b64decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _verify_claims(claims: Mapping[str, Any], *, audience: str, issuer: str, now: int) -> None:
    if claims.get("iss") != issuer:
        raise ValueError(f"id_token issuer mismatch: {claims.get('iss')!r} != {issuer!r}")
    aud = claims.get("aud")
    if aud != audience and not (isinstance(aud, list) and audience in aud):
        raise ValueError("id_token audience mismatch")
    exp = claims.get("exp")
    if not isinstance(exp, int) or exp < now:
        raise ValueError("id_token expired or missing exp")
    nbf = claims.get("nbf")
    if isinstance(nbf, int) and nbf > now + 60:
        raise ValueError("id_token not yet valid")


def _verify_rs256(*, signing_input: bytes, signature: bytes, n_b64: str, e_b64: str) -> None:
    """Verify an RS256 signature using stdlib only.

    Reconstructs the RSA public key from JWKS (n, e), then runs PKCS#1 v1.5 verify.
    """
    n = int.from_bytes(_b64decode(n_b64), "big")
    e = int.from_bytes(_b64decode(e_b64), "big")
    sig_int = int.from_bytes(signature, "big")

    # RSA verify: m = sig^e mod n
    m_int = pow(sig_int, e, n)
    k = (n.bit_length() + 7) // 8
    em = m_int.to_bytes(k, "big")

    # Expected PKCS#1 v1.5 envelope: 0x00 || 0x01 || PS || 0x00 || T
    # T = DER(DigestInfo) || H(M)
    digest = hashlib.sha256(signing_input).digest()
    sha256_der = bytes([
        0x30, 0x31,
        0x30, 0x0D,
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00,
        0x04, 0x20,
    ])
    t = sha256_der + digest
    ps_len = k - 3 - len(t)
    if ps_len < 8:
        raise ValueError("intended encoded message length too short")
    expected = b"\x00\x01" + b"\xff" * ps_len + b"\x00" + t
    if not hmac.compare_digest(em, expected):
        raise ValueError("id_token signature is invalid")


__all__ = [
    "exchange_code",
    "fetch_userinfo",
    "pkce_challenge",
    "pkce_verifier",
    "random_state",
    "verify_id_token",
]
