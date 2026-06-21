"""Unit tests for email-domain → SSO-provider routing.

These exercise `domain.provider_for_email` against the in-memory adapter so the
routing decision is testable without any IdP setup. The /sign-in/email hook
that uses this function is covered by the e2e suite.
"""

from __future__ import annotations

import pytest
from kernia.auth import init
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_sso import sso
from kernia_sso.domain import email_domain, provider_for_email


@pytest.fixture
def auth_ctx():
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret-key",
            plugins=[sso()],
        )
    )
    return auth.context


async def test_email_domain_parsing() -> None:
    assert email_domain("alice@ACME.com") == "acme.com"
    assert email_domain("alice+work@example.test") == "example.test"
    assert email_domain("no-at-sign") == ""


async def test_unmatched_email_returns_none(auth_ctx) -> None:
    assert await provider_for_email(auth_ctx, "nobody@unknown.test") is None


async def test_verified_domain_resolves_to_provider(auth_ctx) -> None:
    # Insert a provider + a verified domain row by hand to bypass admin gating.
    provider = await auth_ctx.adapter.create(
        model="ssoProvider",
        data={
            "issuer": "https://acme-idp",
            "kind": "saml",
            "name": "Acme",
            "domains": "[]",
            "oidcConfig": None,
            "samlConfig": "{}",
            "userInfoMapping": "{}",
            "createdAt": 0,
            "updatedAt": 0,
        },
    )
    await auth_ctx.adapter.create(
        model="ssoDomain",
        data={
            "domain": "acme.com",
            "ssoProviderId": provider["id"],
            "verified": True,
            "verificationToken": "tok",
            "createdAt": 0,
        },
    )
    match = await provider_for_email(auth_ctx, "alice@acme.com")
    assert match is not None
    pid, dom = match
    assert pid == provider["id"]
    assert dom == "acme.com"


async def test_unverified_domain_is_ignored(auth_ctx) -> None:
    provider = await auth_ctx.adapter.create(
        model="ssoProvider",
        data={
            "issuer": "https://x",
            "kind": "oidc",
            "name": "X",
            "domains": "[]",
            "oidcConfig": "{}",
            "samlConfig": None,
            "userInfoMapping": "{}",
            "createdAt": 0,
            "updatedAt": 0,
        },
    )
    await auth_ctx.adapter.create(
        model="ssoDomain",
        data={
            "domain": "pending.test",
            "ssoProviderId": provider["id"],
            "verified": False,
            "verificationToken": "tok",
            "createdAt": 0,
        },
    )
    assert await provider_for_email(auth_ctx, "u@pending.test") is None
