"""Org auto-provisioning for SSO sign-ins.

Ported from `reference/packages/sso/src/linking/org-assignment.test.ts`, adapted
to the Python SSO schema (a dedicated unique ``ssoDomain`` table instead of
``domain``/``domainVerified`` columns on the provider row).

The upstream "multiple providers claim the same domain" spoofing case has no
Python analogue: ``ssoDomain.domain`` is ``unique``, so a domain can have at most
one owning provider — the uniqueness constraint enforces what upstream achieves
by filtering on ``domainVerified``.
"""

from __future__ import annotations

import time

import pytest
from better_auth.auth import init
from better_auth.plugins import organization
from better_auth.types.adapter import Where
from better_auth.types.init_options import BetterAuthOptions
from better_auth_memory_adapter import memory_adapter
from better_auth_sso import (
    assign_organization_by_domain,
    assign_organization_from_provider,
    sso,
)


def _now() -> int:
    return int(time.time())


def _ctx(*, with_org: bool = True):
    """Build an auth instance (sso + optionally organization) and its adapter."""
    adapter = memory_adapter()
    plugins = [sso()]
    if with_org:
        plugins.append(organization())
    auth = init(
        BetterAuthOptions(
            database=adapter,
            secret="test-secret",
            base_url="http://localhost:3000",
            plugins=plugins,
        )
    )
    return auth.context, adapter


async def _seed_user(adapter, *, email: str = "alice@example.com") -> dict:
    return await adapter.create(
        model="user",
        data={
            "id": "user-1",
            "email": email,
            "name": "Alice",
            "emailVerified": True,
            "createdAt": _now(),
            "updatedAt": _now(),
        },
    )


async def _seed_org(adapter, *, org_id: str = "org-1") -> dict:
    return await adapter.create(
        model="organization",
        data={
            "id": org_id,
            "name": "Test Org",
            "slug": org_id,
            "createdAt": _now(),
        },
    )


async def _seed_provider(
    adapter, *, organization_id: str | None = "org-1", provider_id: str = "provider-1"
) -> dict:
    return await adapter.create(
        model="ssoProvider",
        data={
            "id": provider_id,
            "issuer": f"https://idp.example.com/{provider_id}",
            "kind": "oidc",
            "name": "Test Provider",
            "domains": "[]",
            "oidcConfig": None,
            "samlConfig": None,
            "userInfoMapping": "{}",
            "organizationId": organization_id,
            "createdAt": _now(),
            "updatedAt": _now(),
        },
    )


async def _seed_domain(
    adapter,
    *,
    domain: str = "example.com",
    verified: bool,
    provider_id: str = "provider-1",
) -> None:
    await adapter.create(
        model="ssoDomain",
        data={
            "domain": domain,
            "ssoProviderId": provider_id,
            "verified": verified,
            "verificationToken": "tok",
            "createdAt": _now(),
        },
    )


async def _members(adapter, user_id: str) -> list[dict]:
    return await adapter.find_many(
        model="member", where=(Where(field="userId", value=user_id),)
    )


# ---------------------------------------------------------------------------
# assign_organization_by_domain
# ---------------------------------------------------------------------------


async def test_by_domain_not_assigned_when_domain_unverified() -> None:
    ctx, adapter = _ctx()
    await _seed_org(adapter)
    await _seed_provider(adapter)
    await _seed_domain(adapter, verified=False)
    user = await _seed_user(adapter)

    await assign_organization_by_domain(
        ctx, user=user, domain_verification={"enabled": True}
    )
    assert await _members(adapter, user["id"]) == []


async def test_by_domain_assigned_when_domain_verified() -> None:
    ctx, adapter = _ctx()
    await _seed_org(adapter)
    await _seed_provider(adapter)
    await _seed_domain(adapter, verified=True)
    user = await _seed_user(adapter)

    await assign_organization_by_domain(
        ctx, user=user, domain_verification={"enabled": True}
    )
    members = await _members(adapter, user["id"])
    assert len(members) == 1
    assert members[0]["organizationId"] == "org-1"
    assert members[0]["role"] == "member"


async def test_by_domain_not_assigned_when_email_domain_mismatch() -> None:
    ctx, adapter = _ctx()
    await _seed_org(adapter)
    await _seed_provider(adapter)
    await _seed_domain(adapter, verified=True)
    user = await _seed_user(adapter, email="alice@other-domain.com")

    await assign_organization_by_domain(
        ctx, user=user, domain_verification={"enabled": True}
    )
    assert await _members(adapter, user["id"]) == []


async def test_by_domain_not_assigned_when_provider_has_no_org() -> None:
    ctx, adapter = _ctx()
    await _seed_provider(adapter, organization_id=None)
    await _seed_domain(adapter, verified=True)
    user = await _seed_user(adapter)

    await assign_organization_by_domain(
        ctx, user=user, domain_verification={"enabled": True}
    )
    assert await _members(adapter, user["id"]) == []


async def test_by_domain_assigned_when_verification_disabled() -> None:
    ctx, adapter = _ctx()
    await _seed_org(adapter)
    await _seed_provider(adapter)
    await _seed_domain(adapter, verified=False)  # unverified, but check disabled
    user = await _seed_user(adapter)

    await assign_organization_by_domain(
        ctx, user=user, domain_verification={"enabled": False}
    )
    members = await _members(adapter, user["id"])
    assert len(members) == 1
    assert members[0]["organizationId"] == "org-1"


async def test_by_domain_not_assigned_when_already_member() -> None:
    ctx, adapter = _ctx()
    await _seed_org(adapter)
    await _seed_provider(adapter)
    await _seed_domain(adapter, verified=True)
    user = await _seed_user(adapter)
    await adapter.create(
        model="member",
        data={
            "id": "member-1",
            "organizationId": "org-1",
            "userId": user["id"],
            "role": "admin",
            "createdAt": _now(),
        },
    )

    await assign_organization_by_domain(
        ctx, user=user, domain_verification={"enabled": True}
    )
    members = await _members(adapter, user["id"])
    assert len(members) == 1
    assert members[0]["role"] == "admin"  # unchanged


async def test_by_domain_noop_when_org_plugin_absent() -> None:
    ctx, adapter = _ctx(with_org=False)
    await _seed_provider(adapter)
    await _seed_domain(adapter, verified=True)
    user = await _seed_user(adapter)

    await assign_organization_by_domain(
        ctx, user=user, domain_verification={"enabled": True}
    )
    assert await _members(adapter, user["id"]) == []


async def test_by_domain_respects_disabled_flag() -> None:
    ctx, adapter = _ctx()
    await _seed_org(adapter)
    await _seed_provider(adapter)
    await _seed_domain(adapter, verified=True)
    user = await _seed_user(adapter)

    await assign_organization_by_domain(
        ctx,
        user=user,
        provisioning_options={"disabled": True},
        domain_verification={"enabled": True},
    )
    assert await _members(adapter, user["id"]) == []


async def test_by_domain_uses_default_role_and_get_role() -> None:
    # defaultRole
    ctx, adapter = _ctx()
    await _seed_org(adapter)
    await _seed_provider(adapter)
    await _seed_domain(adapter, verified=True)
    user = await _seed_user(adapter)
    await assign_organization_by_domain(
        ctx,
        user=user,
        provisioning_options={"default_role": "owner"},
        domain_verification={"enabled": True},
    )
    members = await _members(adapter, user["id"])
    assert members[0]["role"] == "owner"


async def test_by_domain_get_role_callback() -> None:
    ctx, adapter = _ctx()
    await _seed_org(adapter)
    await _seed_provider(adapter)
    await _seed_domain(adapter, verified=True)
    user = await _seed_user(adapter)

    async def _get_role(data: dict) -> str:
        assert data["provider"]["organizationId"] == "org-1"
        return "admin"

    await assign_organization_by_domain(
        ctx,
        user=user,
        provisioning_options={"get_role": _get_role},
        domain_verification={"enabled": True},
    )
    members = await _members(adapter, user["id"])
    assert members[0]["role"] == "admin"


# ---------------------------------------------------------------------------
# assign_organization_from_provider
# ---------------------------------------------------------------------------


async def test_from_provider_assigns_member() -> None:
    ctx, adapter = _ctx()
    await _seed_org(adapter)
    provider = await _seed_provider(adapter)
    user = await _seed_user(adapter)

    await assign_organization_from_provider(ctx, user=user, provider=provider)
    members = await _members(adapter, user["id"])
    assert len(members) == 1
    assert members[0]["organizationId"] == "org-1"
    assert members[0]["role"] == "member"


async def test_from_provider_noop_without_org_id() -> None:
    ctx, adapter = _ctx()
    provider = await _seed_provider(adapter, organization_id=None)
    user = await _seed_user(adapter)

    await assign_organization_from_provider(ctx, user=user, provider=provider)
    assert await _members(adapter, user["id"]) == []


async def test_from_provider_noop_when_disabled() -> None:
    ctx, adapter = _ctx()
    await _seed_org(adapter)
    provider = await _seed_provider(adapter)
    user = await _seed_user(adapter)

    await assign_organization_from_provider(
        ctx, user=user, provider=provider, provisioning_options={"disabled": True}
    )
    assert await _members(adapter, user["id"]) == []


async def test_from_provider_noop_when_org_plugin_absent() -> None:
    ctx, adapter = _ctx(with_org=False)
    provider = await _seed_provider(adapter)
    user = await _seed_user(adapter)

    await assign_organization_from_provider(ctx, user=user, provider=provider)
    assert await _members(adapter, user["id"]) == []


async def test_from_provider_idempotent_when_already_member() -> None:
    ctx, adapter = _ctx()
    await _seed_org(adapter)
    provider = await _seed_provider(adapter)
    user = await _seed_user(adapter)

    await assign_organization_from_provider(ctx, user=user, provider=provider)
    await assign_organization_from_provider(ctx, user=user, provider=provider)
    assert len(await _members(adapter, user["id"])) == 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
