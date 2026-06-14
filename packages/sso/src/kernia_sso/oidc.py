"""OIDC SSO — discovery + code exchange + userinfo mapping.

We deliberately use `kernia.oauth2` rather than `authlib` for the verify
path: it keeps the JWT verification code in one place (the same code that
verifies Google's id_tokens) and avoids pulling authlib's `JsonWebKey` into the
hot path. authlib remains a declared dependency for projects that want to swap
the discovery/userinfo client at the edges.

Test transports (`httpx.MockTransport`) are honored by passing an
`httpx.AsyncClient` built around them: the plugin owns the client lifetime.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import httpx
from kernia.oauth2 import exchange_code, fetch_userinfo, verify_id_token


async def discover(
    issuer: str,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Fetch the OIDC discovery document for `issuer`.

    The well-known path is `{issuer}/.well-known/openid-configuration`. We tolerate
    a trailing slash on the issuer.
    """
    base = issuer.rstrip("/")
    url = f"{base}/.well-known/openid-configuration"
    own_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=30.0)
    try:
        r = await client.get(url)
        r.raise_for_status()
        return r.json()
    finally:
        if own_client:
            await client.aclose()


def build_authorize_url(
    *,
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    scopes: tuple[str, ...] = ("openid", "email", "profile"),
    code_challenge: str | None = None,
    extra: Mapping[str, str] | None = None,
) -> str:
    """Build a standards-compliant OIDC authorize URL.

    PKCE (`code_challenge` + `S256`) is opt-in. `extra` adds vendor-specific
    params (e.g. Azure AD's `prompt`).
    """
    from urllib.parse import urlencode

    params: dict[str, str] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(scopes),
        "state": state,
    }
    if code_challenge is not None:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"
    if extra:
        params.update(extra)
    sep = "&" if "?" in authorization_endpoint else "?"
    return f"{authorization_endpoint}{sep}{urlencode(params)}"


async def complete_signin(
    *,
    code: str,
    config: Mapping[str, Any],
    discovery: Mapping[str, Any],
    redirect_uri: str,
    code_verifier: str | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Exchange `code`, verify the id_token, fetch userinfo, and merge the two.

    Returns the merged claim dict. Raises `ValueError` if any step fails (the
    caller should wrap into an `APIError` with `SSO_OIDC_EXCHANGE_FAILED`).
    """
    token_endpoint = config.get("tokenEndpoint") or discovery["token_endpoint"]
    userinfo_endpoint = config.get("userInfoEndpoint") or discovery.get("userinfo_endpoint")
    jwks_uri = config.get("jwksEndpoint") or discovery["jwks_uri"]

    tokens = await exchange_code(
        token_url=token_endpoint,
        client_id=config["clientId"],
        client_secret=config["clientSecret"],
        code=code,
        redirect_uri=redirect_uri,
        code_verifier=code_verifier,
        http_client=http_client,
    )
    claims: dict[str, Any] = {}
    id_token = tokens.get("id_token")
    if id_token:
        claims = dict(
            await verify_id_token(
                id_token=id_token,
                jwks_url=jwks_uri,
                audience=config["clientId"],
                issuer=discovery.get("issuer") or config["issuer"],
                http_client=http_client,
            )
        )
    access_token = tokens.get("access_token")
    if access_token and userinfo_endpoint:
        userinfo = await fetch_userinfo(
            userinfo_endpoint,
            access_token=access_token,
            http_client=http_client,
        )
        # id_token claims win on conflict — they're signed.
        for k, v in userinfo.items():
            claims.setdefault(k, v)
    return claims


def apply_mapping(claims: Mapping[str, Any], mapping: Mapping[str, str] | None) -> dict[str, Any]:
    """Translate IdP claims onto our user fields using `mapping`.

    `mapping` maps *our* field names to *their* claim names, so:

        mapping = {"email": "email", "name": "displayName"}

    yields ``{"email": claims["email"], "name": claims["displayName"]}``. Missing
    source claims are silently dropped; the caller decides whether the result is
    sufficient (typically requires at least `email`).
    """
    if not mapping:
        # Sensible default: pull the common OIDC claims.
        out: dict[str, Any] = {}
        for k in ("sub", "email", "name", "email_verified", "picture"):
            if k in claims:
                out[k] = claims[k]
        return out
    out = {}
    for our_field, their_claim in mapping.items():
        if their_claim in claims:
            out[our_field] = claims[their_claim]
    return out


def parse_config(raw: str | Mapping[str, Any] | None) -> dict[str, Any]:
    """Decode the OIDC config blob from storage (JSON-encoded) or a live dict."""
    if raw is None:
        return {}
    if isinstance(raw, str):
        return json.loads(raw)
    return dict(raw)


__all__ = [
    "apply_mapping",
    "build_authorize_url",
    "complete_signin",
    "discover",
    "parse_config",
]
