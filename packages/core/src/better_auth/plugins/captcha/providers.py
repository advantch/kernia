"""Built-in `CaptchaProvider` implementations.

Each provider posts to a public siteverify endpoint with httpx. The transport is
injectable so tests can swap in `httpx.MockTransport`. Mirrors handlers in
`reference/packages/better-auth/src/plugins/captcha/verify-handlers/`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

import httpx


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """Outcome of a captcha verification."""

    success: bool
    raw: dict[str, Any]
    error: str | None = None


@runtime_checkable
class CaptchaProvider(Protocol):
    """A pluggable captcha verifier.

    `verify` must POST to the provider's siteverify endpoint and return whether
    the token is valid for the given client IP (when supplied).
    """

    name: str

    async def verify(
        self, token: str, ip: str | None = None
    ) -> VerifyResult: ...


@dataclass
class _HttpProvider:
    """Shared base — owns the httpx client (which tests may override).

    Provider-specific request/response handling lives in subclasses.
    """

    name: str
    secret: str
    verify_url: str
    site_key: str | None = None
    min_score: float = 0.5  # only used by recaptcha v3
    transport: httpx.AsyncBaseTransport | None = None

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=self.transport, timeout=httpx.Timeout(10.0))


@dataclass
class _RecaptchaProvider(_HttpProvider):
    is_v3: bool = False

    async def verify(self, token: str, ip: str | None = None) -> VerifyResult:
        data = {"secret": self.secret, "response": token}
        if ip:
            data["remoteip"] = ip
        try:
            async with self._client() as c:
                r = await c.post(self.verify_url, data=data)
                payload = r.json()
        except Exception as e:  # network/parse failure → treat as failure
            return VerifyResult(success=False, raw={}, error=str(e))
        success = bool(payload.get("success"))
        if success and self.is_v3:
            score = float(payload.get("score") or 0)
            if score < self.min_score:
                return VerifyResult(success=False, raw=payload, error="low-score")
        return VerifyResult(
            success=success,
            raw=payload,
            error=None if success else ",".join(payload.get("error-codes", []) or []) or "failed",
        )


@dataclass
class _TurnstileProvider(_HttpProvider):
    async def verify(self, token: str, ip: str | None = None) -> VerifyResult:
        body: dict[str, Any] = {"secret": self.secret, "response": token}
        if ip:
            body["remoteip"] = ip
        try:
            async with self._client() as c:
                r = await c.post(self.verify_url, json=body)
                payload = r.json()
        except Exception as e:
            return VerifyResult(success=False, raw={}, error=str(e))
        success = bool(payload.get("success"))
        return VerifyResult(
            success=success,
            raw=payload,
            error=None if success else ",".join(payload.get("error-codes", []) or []) or "failed",
        )


@dataclass
class _HCaptchaProvider(_HttpProvider):
    async def verify(self, token: str, ip: str | None = None) -> VerifyResult:
        data = {"secret": self.secret, "response": token}
        if self.site_key:
            data["sitekey"] = self.site_key
        if ip:
            data["remoteip"] = ip
        try:
            async with self._client() as c:
                r = await c.post(self.verify_url, data=data)
                payload = r.json()
        except Exception as e:
            return VerifyResult(success=False, raw={}, error=str(e))
        success = bool(payload.get("success"))
        return VerifyResult(
            success=success,
            raw=payload,
            error=None if success else ",".join(payload.get("error-codes", []) or []) or "failed",
        )


# --- public constructors -----------------------------------------------------


def recaptcha_v3(
    secret: str,
    *,
    min_score: float = 0.5,
    transport: httpx.AsyncBaseTransport | None = None,
) -> CaptchaProvider:
    """Google reCAPTCHA v3 (score-based)."""
    return _RecaptchaProvider(
        name="recaptcha_v3",
        secret=secret,
        verify_url="https://www.google.com/recaptcha/api/siteverify",
        min_score=min_score,
        transport=transport,
        is_v3=True,
    )


def recaptcha_v2(
    secret: str,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> CaptchaProvider:
    """Google reCAPTCHA v2 (checkbox / invisible)."""
    return _RecaptchaProvider(
        name="recaptcha_v2",
        secret=secret,
        verify_url="https://www.google.com/recaptcha/api/siteverify",
        transport=transport,
        is_v3=False,
    )


def turnstile(
    secret: str,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> CaptchaProvider:
    """Cloudflare Turnstile."""
    return _TurnstileProvider(
        name="turnstile",
        secret=secret,
        verify_url="https://challenges.cloudflare.com/turnstile/v0/siteverify",
        transport=transport,
    )


def hcaptcha(
    secret: str,
    *,
    site_key: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> CaptchaProvider:
    """hCaptcha."""
    return _HCaptchaProvider(
        name="hcaptcha",
        secret=secret,
        verify_url="https://api.hcaptcha.com/siteverify",
        site_key=site_key,
        transport=transport,
    )


def captchafox(
    secret: str,
    *,
    site_key: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> CaptchaProvider:
    """CaptchaFox — same request shape as hCaptcha, different host."""
    return _HCaptchaProvider(
        name="captchafox",
        secret=secret,
        verify_url="https://api.captchafox.com/siteverify",
        site_key=site_key,
        transport=transport,
    )


__all__ = [
    "CaptchaProvider",
    "VerifyResult",
    "captchafox",
    "hcaptcha",
    "recaptcha_v2",
    "recaptcha_v3",
    "turnstile",
]
