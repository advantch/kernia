"""OAuth2 primitives smoke: PKCE round-trip + RS256 id_token verification.

The RS256 test generates a fresh keypair (via `cryptography`), signs a JWT, exposes
the public key as a synthetic JWKS, and verifies through our pure-stdlib verifier.
This proves the verifier against a real RSA implementation without needing a live IdP.
"""

from __future__ import annotations

import base64
import json
import time

import httpx
import pytest

from kernia.oauth2 import (
    pkce_challenge,
    pkce_verifier,
    verify_id_token,
)


def test_pkce_round_trip() -> None:
    v = pkce_verifier()
    c = pkce_challenge(v)
    assert pkce_challenge(v) == c
    assert "=" not in c


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_int(i: int) -> str:
    length = (i.bit_length() + 7) // 8
    return _b64url(i.to_bytes(length, "big"))


@pytest.fixture(scope="module")
def rsa_key():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _sign_jwt(rsa_key, *, header: dict, claims: dict) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    signing_input = (
        _b64url(json.dumps(header, separators=(",", ":")).encode()) + "."
        + _b64url(json.dumps(claims, separators=(",", ":")).encode())
    )
    sig = rsa_key.sign(
        signing_input.encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return signing_input + "." + _b64url(sig)


def _jwks_for(rsa_key, *, kid: str) -> dict:
    pub = rsa_key.public_key().public_numbers()
    return {
        "keys": [
            {
                "kid": kid,
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": _b64url_int(pub.n),
                "e": _b64url_int(pub.e),
            }
        ]
    }


async def test_verify_id_token_happy_path(rsa_key) -> None:
    kid = "test-key-1"
    token = _sign_jwt(
        rsa_key,
        header={"alg": "RS256", "kid": kid, "typ": "JWT"},
        claims={
            "iss": "https://example.com",
            "aud": "client-id-A",
            "exp": int(time.time()) + 3600,
            "sub": "user-1",
        },
    )
    jwks = _jwks_for(rsa_key, kid=kid)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=jwks)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        claims = await verify_id_token(
            id_token=token,
            jwks_url="https://example.com/.well-known/jwks.json",
            audience="client-id-A",
            issuer="https://example.com",
            http_client=client,
        )
        assert claims["sub"] == "user-1"


async def test_verify_id_token_rejects_wrong_audience(rsa_key) -> None:
    kid = "test-key-1"
    token = _sign_jwt(
        rsa_key,
        header={"alg": "RS256", "kid": kid, "typ": "JWT"},
        claims={
            "iss": "https://example.com",
            "aud": "client-id-A",
            "exp": int(time.time()) + 3600,
            "sub": "user-1",
        },
    )
    jwks = _jwks_for(rsa_key, kid=kid)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=jwks)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="audience"):
            await verify_id_token(
                id_token=token,
                jwks_url="https://example.com/.well-known/jwks.json",
                audience="other-client",
                issuer="https://example.com",
                http_client=client,
            )


async def test_verify_id_token_rejects_expired(rsa_key) -> None:
    kid = "test-key-1"
    token = _sign_jwt(
        rsa_key,
        header={"alg": "RS256", "kid": kid, "typ": "JWT"},
        claims={
            "iss": "https://example.com",
            "aud": "client-id-A",
            "exp": int(time.time()) - 1,
            "sub": "user-1",
        },
    )
    jwks = _jwks_for(rsa_key, kid=kid)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=jwks)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="expired"):
            await verify_id_token(
                id_token=token,
                jwks_url="https://example.com/.well-known/jwks.json",
                audience="client-id-A",
                issuer="https://example.com",
                http_client=client,
            )


async def test_verify_id_token_rejects_bad_signature(rsa_key) -> None:
    """Use rsa_key to sign, but advertise a *different* JWKS — verify must fail."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa

    kid = "test-key-1"
    token = _sign_jwt(
        rsa_key,
        header={"alg": "RS256", "kid": kid, "typ": "JWT"},
        claims={
            "iss": "https://example.com",
            "aud": "client-id-A",
            "exp": int(time.time()) + 3600,
            "sub": "user-1",
        },
    )
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = _jwks_for(other_key, kid=kid)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=jwks)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="signature"):
            await verify_id_token(
                id_token=token,
                jwks_url="https://example.com/.well-known/jwks.json",
                audience="client-id-A",
                issuer="https://example.com",
                http_client=client,
            )
