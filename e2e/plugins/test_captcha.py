"""Captcha plugin end-to-end.

Validates the before-hook against all built-in providers using
`httpx.MockTransport`. Each provider:
  * accepts `success=True` payloads from its siteverify endpoint
  * rejects bad/missing tokens with `CAPTCHA_FAILED` / `CAPTCHA_TOKEN_MISSING`
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from kernia.auth import init
from kernia.plugins import captcha, email_and_password
from kernia.plugins.captcha import (
    hcaptcha,
    recaptcha_v2,
    recaptcha_v3,
    turnstile,
)
from kernia.types.init_options import (
    EmailPasswordOptions,
    KerniaOptions,
    RateLimitOptions,
)
from kernia_memory_adapter import memory_adapter
from kernia_test_utils import ASGIDriver


def _mock_transport(success: bool, *, score: float = 0.9) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        # The mock provider ignores the request body and returns a canned verdict.
        payload: dict[str, Any] = {"success": success}
        if "recaptcha" in str(request.url) and score is not None:
            payload["score"] = score
        if not success:
            payload["error-codes"] = ["invalid-input-response"]
        return httpx.Response(200, json=payload)

    return httpx.MockTransport(handler)


def _make_driver(provider_factory: Any, *, success: bool = True) -> ASGIDriver:
    transport = _mock_transport(success)
    provider = provider_factory("secret", transport=transport)
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="captcha-secret",
            email_and_password=EmailPasswordOptions(enabled=True),
            plugins=[email_and_password(), captcha(provider)],
            # Disable rate-limit to avoid interference with multi-request tests.
            rate_limit=RateLimitOptions(enabled=False),
        )
    )
    return ASGIDriver(app=auth.router.mount())


@pytest.mark.parametrize("factory", [recaptcha_v3, recaptcha_v2, turnstile, hcaptcha])
async def test_protected_endpoint_requires_captcha_header(factory: Any) -> None:
    driver = _make_driver(factory, success=True)
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "x@y.z", "password": "irrelevant"},
    )
    assert r.status == 400
    assert r.json()["code"] == "CAPTCHA_TOKEN_MISSING"


@pytest.mark.parametrize("factory", [recaptcha_v3, recaptcha_v2, turnstile, hcaptcha])
async def test_valid_token_passes_through_to_handler(factory: Any) -> None:
    driver = _make_driver(factory, success=True)
    # Sign up first so credentials exist, with a valid captcha header.
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "ok@example.com", "password": "validpassword"},
        headers={"x-captcha-token": "good-token"},
    )
    assert r.status == 200, r.json()


@pytest.mark.parametrize("factory", [recaptcha_v3, recaptcha_v2, turnstile, hcaptcha])
async def test_invalid_token_returns_captcha_failed(factory: Any) -> None:
    driver = _make_driver(factory, success=False)
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "x@y.z", "password": "abcdefgh"},
        headers={"x-captcha-token": "bad-token"},
    )
    assert r.status == 403
    assert r.json()["code"] == "CAPTCHA_FAILED"


async def test_direct_verify_endpoint_returns_provider_result() -> None:
    driver = _make_driver(turnstile, success=True)
    r = await driver.request(
        "POST",
        "/captcha/verify",
        json_body={"token": "any"},
    )
    assert r.status == 200
    assert r.json()["success"] is True


# ----- ported from reference captcha.test.ts -----


def _make_driver_with_transport(
    provider_factory: Any, transport: httpx.MockTransport, **provider_kwargs: Any
) -> ASGIDriver:
    provider = provider_factory("secret", transport=transport, **provider_kwargs)
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="captcha-secret",
            email_and_password=EmailPasswordOptions(enabled=True),
            plugins=[email_and_password(), captcha(provider)],
            rate_limit=RateLimitOptions(enabled=False),
        )
    )
    return ASGIDriver(app=auth.router.mount())


async def test_ignores_non_protected_endpoint() -> None:
    """Upstream: 'Should ignore non-protected endpoints'.

    A path outside the protected set passes through without a captcha token —
    no CAPTCHA_TOKEN_MISSING is raised.
    """
    driver = _make_driver(turnstile, success=True)
    # /get-session is not in DEFAULT_PROTECTED_ENDPOINTS; it should not be gated.
    # With no session it returns 200 + null body (never CAPTCHA_TOKEN_MISSING/400).
    r = await driver.request("GET", "/get-session")
    assert r.status == 200
    body = r.json()
    assert body is None or body.get("code") != "CAPTCHA_TOKEN_MISSING"


async def test_missing_secret_returns_500() -> None:
    """Upstream: 'Should return a 500 when missing secret key'."""
    # Provider built with an empty secret => server misconfiguration => 500.
    transport = _mock_transport(True)
    provider = turnstile("", transport=transport)
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="captcha-secret",
            email_and_password=EmailPasswordOptions(enabled=True),
            plugins=[email_and_password(), captcha(provider)],
            rate_limit=RateLimitOptions(enabled=False),
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "x@y.z", "password": "abcdefgh"},
        headers={"x-captcha-token": "good"},
    )
    assert r.status == 500
    assert r.json()["code"] == "CAPTCHA_SERVICE_UNAVAILABLE"


@pytest.mark.parametrize("factory", [recaptcha_v3, recaptcha_v2, turnstile, hcaptcha])
async def test_siteverify_failure_returns_500(factory: Any) -> None:
    """Upstream: 'Should return 500 if the call to /siteverify fails'.

    A transport-level failure reaching siteverify is a service error (500),
    distinct from a clean validation failure (403).
    """

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("siteverify unreachable", request=request)

    driver = _make_driver_with_transport(factory, httpx.MockTransport(boom))
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "x@y.z", "password": "abcdefgh"},
        headers={"x-captcha-token": "good"},
    )
    assert r.status == 500
    assert r.json()["code"] == "CAPTCHA_SERVICE_UNAVAILABLE"


async def test_recaptcha_v3_low_score_returns_403() -> None:
    """Upstream: 'Should return 403 in case of a too low score (ReCAPTCHA v3)'."""

    def handler(request: httpx.Request) -> httpx.Response:
        # success=True but score below the default 0.5 threshold.
        return httpx.Response(200, json={"success": True, "score": 0.1})

    driver = _make_driver_with_transport(recaptcha_v3, httpx.MockTransport(handler))
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "x@y.z", "password": "abcdefgh"},
        headers={"x-captcha-token": "good"},
    )
    assert r.status == 403
    assert r.json()["code"] == "CAPTCHA_FAILED"
