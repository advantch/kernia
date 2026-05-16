"""Captcha plugin end-to-end.

Validates the before-hook against all built-in providers using
`httpx.MockTransport`. Each provider:
  * accepts `success=True` payloads from its siteverify endpoint
  * rejects bad/missing tokens with `CAPTCHA_FAILED` / `CAPTCHA_TOKEN_MISSING`
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from better_auth.auth import init
from better_auth.plugins import captcha, email_and_password
from better_auth.plugins.captcha import (
    hcaptcha,
    recaptcha_v2,
    recaptcha_v3,
    turnstile,
)
from better_auth.types.init_options import (
    BetterAuthOptions,
    EmailPasswordOptions,
    RateLimitOptions,
)
from better_auth_memory_adapter import memory_adapter
from better_auth_test_utils import ASGIDriver


def _mock_transport(success: bool, *, score: float = 0.9) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        # Parse form or json body — providers vary
        if request.headers.get("content-type", "").startswith("application/json"):
            body = json.loads(request.content.decode("utf-8") or "{}")
        else:
            from urllib.parse import parse_qsl

            body = dict(parse_qsl((request.content or b"").decode("utf-8")))
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
        BetterAuthOptions(
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
