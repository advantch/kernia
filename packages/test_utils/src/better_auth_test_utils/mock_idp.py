"""In-process OIDC IdP for OAuth/OIDC tests.

Generates an RSA keypair (via `cryptography`), signs id_tokens, and serves a
JWKS / discovery / token / userinfo surface via `httpx.MockTransport`. Tests can
plug the transport into an `httpx.AsyncClient` and exercise the full OIDC
authorization-code flow without a live IdP.

Mirrors what real providers (Google, Microsoft, Apple) expose so the core
`oauth2.verify_id_token` path is exercised end-to-end.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_int(i: int) -> str:
    length = (i.bit_length() + 7) // 8 or 1
    return _b64url(i.to_bytes(length, "big"))


@dataclass(slots=True)
class _UserProfile:
    sub: str
    email: str | None = None
    name: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class MockIdP:
    """In-memory OpenID Connect provider for tests.

    Usage:
        idp = MockIdP(issuer="https://test-idp", audience="client-1")
        idp.create_user(sub="u1", email="a@b.c", name="A")
        transport = idp.mock_transport()
        async with httpx.AsyncClient(transport=transport) as client:
            ...
    """

    issuer: str = "https://test-idp"
    audience: str = "client-1"
    kid: str = "test-key-1"
    token_ttl: int = 3600

    _key: rsa.RSAPrivateKey = field(init=False)
    _queue: deque[_UserProfile] = field(init=False, default_factory=deque)
    _access_tokens: dict[str, _UserProfile] = field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # ----- public API -----

    @property
    def jwks(self) -> dict[str, Any]:
        pub = self._key.public_key().public_numbers()
        return {
            "keys": [
                {
                    "kid": self.kid,
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "n": _b64url_int(pub.n),
                    "e": _b64url_int(pub.e),
                }
            ]
        }

    @property
    def discovery(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/authorize",
            "token_endpoint": f"{self.issuer}/token",
            "userinfo_endpoint": f"{self.issuer}/userinfo",
            "jwks_uri": f"{self.issuer}/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }

    def create_user(
        self,
        sub: str,
        email: str | None = None,
        name: str | None = None,
        **extra: Any,
    ) -> None:
        """Enqueue a profile for the next sign-in (token exchange)."""
        self._queue.append(_UserProfile(sub=sub, email=email, name=name, extra=dict(extra)))

    def id_token_for(self, sub: str, **claims: Any) -> str:
        """Return a signed id_token for direct verification tests."""
        now = int(time.time())
        payload: dict[str, Any] = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": sub,
            "iat": now,
            "exp": now + self.token_ttl,
        }
        payload.update(claims)
        return self._sign_jwt(payload)

    def mock_transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    # ----- internals -----

    def _sign_jwt(self, claims: dict[str, Any]) -> str:
        header = {"alg": "RS256", "kid": self.kid, "typ": "JWT"}
        signing_input = (
            _b64url(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + _b64url(json.dumps(claims, separators=(",", ":")).encode())
        )
        sig = self._key.sign(
            signing_input.encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return signing_input + "." + _b64url(sig)

    def _next_profile(self) -> _UserProfile:
        if self._queue:
            return self._queue.popleft()
        # Fallback so the IdP never errors out — tests that don't pre-enqueue
        # still get a deterministic profile.
        return _UserProfile(sub="anonymous", email="anonymous@test", name="anonymous")

    def _claims_for(self, profile: _UserProfile) -> dict[str, Any]:
        claims: dict[str, Any] = {"sub": profile.sub}
        if profile.email is not None:
            claims["email"] = profile.email
            claims["email_verified"] = True
        if profile.name is not None:
            claims["name"] = profile.name
        claims.update(profile.extra)
        return claims

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/.well-known/jwks.json"):
            return httpx.Response(200, json=self.jwks)
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json=self.discovery)
        if path.endswith("/token") and request.method == "POST":
            profile = self._next_profile()
            access_token = "at_" + secrets.token_urlsafe(16)
            self._access_tokens[access_token] = profile
            extra_claims = self._claims_for(profile)
            extra_claims.pop("sub", None)
            id_token = self.id_token_for(profile.sub, **extra_claims)
            return httpx.Response(
                200,
                json={
                    "access_token": access_token,
                    "token_type": "Bearer",
                    "expires_in": self.token_ttl,
                    "id_token": id_token,
                    "scope": "openid email profile",
                },
            )
        if path.endswith("/userinfo"):
            auth = request.headers.get("authorization", "")
            token = auth.removeprefix("Bearer ").strip()
            profile = self._access_tokens.get(token)
            if profile is None:
                return httpx.Response(401, json={"error": "invalid_token"})
            return httpx.Response(200, json=self._claims_for(profile))
        return httpx.Response(404, json={"error": "not_found", "path": path})


__all__ = ["MockIdP"]
