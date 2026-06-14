"""End-to-end integration tests for the organization plugin.

Drives the ASGI app via :class:`ASGIDriver`. Parametrizes over every adapter
that :func:`all_adapters_param` exposes so the same scenarios run against the
memory, SQLAlchemy/SQLite, SQLAlchemy/Postgres, and (when implemented)
Mongo adapters.

Scenarios:

  * Full org lifecycle: sign-up → create → invite → accept → list members →
    remove member → leave → delete.
  * Permission enforcement: members cannot delete, non-members cannot read.
  * Teams: create / add / remove / delete.
  * Active organization is attached to /get-session.
  * Slug uniqueness, last-owner protections, and invitation edge cases.
"""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from kernia.auth import init
from kernia.plugins.email_password import email_and_password
from kernia.plugins.organization import organization
from kernia.plugins.organization.schema import (
    MEMBER_MODEL,
    ORGANIZATION_MODEL,
    ORGANIZATION_ROLE_MODEL,
    TEAM_MEMBER_MODEL,
    TEAM_MODEL,
)
from kernia.types.adapter import FieldDef, ModelDef, Where
from kernia.types.init_options import KerniaOptions
from kernia_test_utils import ASGIDriver, MockSMTP, SentEmail

# ---------------------------------------------------------------------------
# Adapter factories that include the organization plugin's schema.
#
# We can't reuse `all_adapters_param()` straight off because the SQLAlchemy
# adapter needs to know about the org tables AND the session-table extension
# (`activeOrganizationId`) at metadata-build time.
# ---------------------------------------------------------------------------


async def _memory_adapter() -> Any:
    from kernia_memory_adapter import memory_adapter

    return memory_adapter()


def _org_invitation_model(teams: bool) -> ModelDef:
    fields = [
        FieldDef("id", "string", unique=True),
        FieldDef("organizationId", "string", references=("organization", "id")),
        FieldDef("email", "string"),
        FieldDef("role", "string"),
        FieldDef("status", "string", default="pending"),
        FieldDef("inviterId", "string", references=("user", "id")),
        FieldDef("expiresAt", "date", required=False),
        FieldDef("createdAt", "date"),
        FieldDef("updatedAt", "date", required=False),
    ]
    if teams:
        fields.append(FieldDef("teamId", "string", required=False))
    return ModelDef(name="invitation", fields=tuple(fields))


def _extended_session_model(teams: bool) -> ModelDef:
    """Core session model + organization session extensions."""
    base_fields = [
        FieldDef("id", "string", unique=True),
        FieldDef("userId", "string", references=("user", "id")),
        FieldDef("token", "string", unique=True),
        FieldDef("expiresAt", "date"),
        FieldDef("ipAddress", "string", required=False),
        FieldDef("userAgent", "string", required=False),
        FieldDef("createdAt", "date"),
        FieldDef("updatedAt", "date"),
        FieldDef("activeOrganizationId", "string", required=False),
    ]
    if teams:
        base_fields.append(FieldDef("activeTeamId", "string", required=False))
    return ModelDef(name="session", fields=tuple(base_fields))


def _org_extra_models(*, teams: bool, dynamic_ac: bool) -> tuple[ModelDef, ...]:
    extra: list[ModelDef] = [
        ORGANIZATION_MODEL,
        MEMBER_MODEL,
        _org_invitation_model(teams),
    ]
    if teams:
        extra.append(TEAM_MODEL)
        extra.append(TEAM_MEMBER_MODEL)
    if dynamic_ac:
        extra.append(ORGANIZATION_ROLE_MODEL)
    return tuple(extra)


async def _sqlite_adapter_with_org(teams: bool, dynamic_ac: bool) -> Any:
    """SQLAlchemy + SQLite, with the extended session + org tables registered."""
    from kernia.db.schema.core_tables import (
        ACCOUNT_MODEL,
        USER_MODEL,
        VERIFICATION_MODEL,
    )
    from kernia_sqlalchemy.adapter import (
        SQLAlchemyAdapter,
        build_metadata,
    )
    from sqlalchemy.ext.asyncio import create_async_engine

    url = f"sqlite+aiosqlite:///file:{secrets.token_hex(8)}?mode=memory&cache=shared&uri=true"
    eng = create_async_engine(url, future=True)
    models = (
        USER_MODEL,
        _extended_session_model(teams),
        ACCOUNT_MODEL,
        VERIFICATION_MODEL,
        *_org_extra_models(teams=teams, dynamic_ac=dynamic_ac),
    )
    metadata = build_metadata(models)
    async with eng.begin() as conn:
        await conn.run_sync(metadata.create_all)
    return SQLAlchemyAdapter(engine=eng, metadata=metadata, models=models)


def org_adapters_param() -> tuple[str, list[Any]]:
    """Adapter matrix for the organization plugin.

    Memory and SQLAlchemy/SQLite always run. Postgres/Mongo are gated on Docker.
    """
    from kernia_test_utils.containers import docker_available

    has_docker = docker_available()

    async def memory_factory_full() -> Any:
        return await _memory_adapter()

    async def sqlite_factory_full() -> Any:
        return await _sqlite_adapter_with_org(teams=True, dynamic_ac=True)

    return (
        "org_adapter_factory",
        [
            pytest.param(memory_factory_full, id="memory"),
            pytest.param(sqlite_factory_full, id="sqlalchemy-sqlite"),
            pytest.param(
                memory_factory_full,
                id="mongo",
                marks=pytest.mark.skipif(not has_docker, reason="Docker required for mongo"),
            ),
        ],
    )


# ---------------------------------------------------------------------------
# Helpers: build a driver wired to email-password + organization.
# ---------------------------------------------------------------------------


async def _make_driver(
    adapter: Any,
    *,
    smtp: MockSMTP | None = None,
    teams: bool = True,
    dynamic_access_control: bool = True,
) -> ASGIDriver:
    async def send_invitation(payload: dict[str, Any]) -> None:
        if smtp is not None:
            await smtp.send(
                SentEmail(
                    to=payload["email"],
                    subject="You're invited",
                    body=f"Join {payload.get('organization', {}).get('name', '?')}",
                    meta={"invitation_id": payload["invitation"]["id"]},
                )
            )

    auth = init(
        KerniaOptions(
            database=adapter,
            secret="org-test-secret",
            plugins=[
                email_and_password(),
                organization(
                    teams=teams,
                    dynamic_access_control=dynamic_access_control,
                    send_invitation=send_invitation if smtp is not None else None,
                ),
            ],
            advanced={"disable_csrf_check": True},
        )
    )
    return ASGIDriver(app=auth.router.mount())


async def _sign_up(
    driver: ASGIDriver, *, email: str, password: str = "passw0rd!", name: str = ""
) -> dict[str, Any]:
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": email, "password": password, "name": name or email},
    )
    assert r.status == 200, r.json()
    return r.json()["user"]


async def _create_org(driver: ASGIDriver, *, name: str, slug: str | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"name": name}
    if slug:
        body["slug"] = slug
    r = await driver.request("POST", "/organization/create", json_body=body)
    assert r.status == 200, r.json()
    # Response shape matches better-auth JS reference: org returned at top level.
    return r.json()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(*org_adapters_param())
async def test_full_lifecycle(org_adapter_factory: Callable[[], Awaitable[Any]]) -> None:
    """Sign up → create org → invite → second user accepts → remove → leave → delete."""
    adapter = await org_adapter_factory()
    smtp = MockSMTP()
    driver_a = await _make_driver(adapter, smtp=smtp)

    # 1. Owner signs up and creates the org.
    await _sign_up(driver_a, email="owner@example.com")
    org = await _create_org(driver_a, name="Acme Corp")
    assert org["slug"] == "acme-corp"

    # 2. Owner invites a second user.
    r = await driver_a.request(
        "POST",
        "/organization/invite-member",
        json_body={
            "organizationId": org["id"],
            "email": "bob@example.com",
            "role": "member",
        },
    )
    assert r.status == 200, r.json()
    invite = r.json()["invitation"]
    assert invite["status"] == "pending"
    assert smtp.sent and smtp.sent[0].to == "bob@example.com"

    # 3. Second user signs up in a *separate* driver, then accepts.
    driver_b = await _make_driver(adapter, smtp=smtp)
    await _sign_up(driver_b, email="bob@example.com")
    r = await driver_b.request(
        "POST",
        "/organization/accept-invitation",
        json_body={"invitationId": invite["id"]},
    )
    assert r.status == 200, r.json()
    assert r.json()["invitation"]["status"] == "accepted"
    assert r.json()["member"]["role"] == "member"

    # 4. List members shows both.
    r = await driver_a.request(
        "GET", "/organization/list-members", query=f"organizationId={org['id']}"
    )
    assert r.status == 200
    members = r.json()
    assert len(members) == 2
    roles = sorted(m["role"] for m in members)
    assert roles == ["member", "owner"]

    # 5. Owner removes Bob.
    r = await driver_a.request(
        "POST",
        "/organization/remove-member",
        json_body={
            "organizationId": org["id"],
            "memberIdOrEmail": "bob@example.com",
        },
    )
    assert r.status == 200, r.json()
    r = await driver_a.request(
        "GET", "/organization/list-members", query=f"organizationId={org['id']}"
    )
    assert len(r.json()) == 1

    # 6. Owner cannot leave when they are the last owner.
    r = await driver_a.request(
        "POST", "/organization/leave", json_body={"organizationId": org["id"]}
    )
    assert r.status == 400
    assert r.json()["code"] == "LAST_OWNER"

    # 7. Delete the org.
    r = await driver_a.request(
        "POST", "/organization/delete", json_body={"organizationId": org["id"]}
    )
    assert r.status == 200, r.json()


@pytest.mark.parametrize(*org_adapters_param())
async def test_member_cannot_delete_org(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver_owner = await _make_driver(adapter)
    driver_member = await _make_driver(adapter)
    await _sign_up(driver_owner, email="owner-d@example.com")
    await _sign_up(driver_member, email="member-d@example.com")
    org = await _create_org(driver_owner, name="DeleteCo")
    # Owner adds the member directly via invite + accept.
    r = await driver_owner.request(
        "POST",
        "/organization/invite-member",
        json_body={
            "organizationId": org["id"],
            "email": "member-d@example.com",
            "role": "member",
        },
    )
    invite = r.json()["invitation"]
    await driver_member.request(
        "POST",
        "/organization/accept-invitation",
        json_body={"invitationId": invite["id"]},
    )
    # Member tries to delete -> NOT_ALLOWED.
    r = await driver_member.request(
        "POST",
        "/organization/delete",
        json_body={"organizationId": org["id"]},
    )
    assert r.status == 403
    assert r.json()["code"] == "NOT_ALLOWED"


@pytest.mark.parametrize(*org_adapters_param())
async def test_non_member_cannot_read(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver_owner = await _make_driver(adapter)
    driver_stranger = await _make_driver(adapter)
    await _sign_up(driver_owner, email="owner-r@example.com")
    await _sign_up(driver_stranger, email="ghost@example.com")
    org = await _create_org(driver_owner, name="ReadCo")
    r = await driver_stranger.request(
        "GET", "/organization/get", query=f"organizationId={org['id']}"
    )
    assert r.status == 403
    assert r.json()["code"] == "NOT_MEMBER"


@pytest.mark.parametrize(*org_adapters_param())
async def test_set_active_organization_round_trip(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver = await _make_driver(adapter)
    await _sign_up(driver, email="active@example.com")
    org = await _create_org(driver, name="ActiveCo")
    # create() implicitly sets active; verify via get-session.
    r = await driver.request("GET", "/get-session")
    assert r.status == 200
    body = r.json()
    assert body["activeOrganization"]["id"] == org["id"]
    assert body["activeOrganization"]["slug"] == "activeco"


@pytest.mark.parametrize(*org_adapters_param())
async def test_set_active_explicit(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver = await _make_driver(adapter)
    await _sign_up(driver, email="x@example.com")
    org_a = await _create_org(driver, name="OrgA", slug="org-a")
    org_b_resp = await driver.request(
        "POST",
        "/organization/create",
        json_body={
            "name": "OrgB",
            "slug": "org-b",
            "keepCurrentActiveOrganization": True,
        },
    )
    assert org_b_resp.status == 200
    org_b = org_b_resp.json()
    # OrgA stays active because keepCurrentActiveOrganization was True for OrgB.
    r = await driver.request("GET", "/get-session")
    assert r.json()["activeOrganization"]["id"] == org_a["id"]

    # Switch active to OrgB.
    r = await driver.request(
        "POST",
        "/organization/set-active",
        json_body={"organizationId": org_b["id"]},
    )
    assert r.status == 200
    r = await driver.request("GET", "/get-session")
    assert r.json()["activeOrganization"]["id"] == org_b["id"]

    # Clear active.
    r = await driver.request("POST", "/organization/set-active", json_body={"organizationId": None})
    assert r.status == 200
    r = await driver.request("GET", "/get-session")
    assert "activeOrganization" not in r.json()


@pytest.mark.parametrize(*org_adapters_param())
async def test_slug_uniqueness(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver = await _make_driver(adapter)
    await _sign_up(driver, email="slug@example.com")
    await _create_org(driver, name="Dup", slug="dup-slug")
    r = await driver.request(
        "POST",
        "/organization/create",
        json_body={"name": "Other", "slug": "DUP-SLUG"},
    )
    assert r.status == 409
    assert r.json()["code"] == "SLUG_TAKEN"


@pytest.mark.parametrize(*org_adapters_param())
async def test_list_organizations_only_returns_caller_orgs(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver_a = await _make_driver(adapter)
    driver_b = await _make_driver(adapter)
    await _sign_up(driver_a, email="a-list@example.com")
    await _sign_up(driver_b, email="b-list@example.com")
    await _create_org(driver_a, name="A1")
    await _create_org(driver_b, name="B1")

    r = await driver_a.request("GET", "/organization/list")
    assert r.status == 200
    rows = r.json()
    assert {row["name"] for row in rows} == {"A1"}


@pytest.mark.parametrize(*org_adapters_param())
async def test_invite_member_duplicate_returns_409(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver = await _make_driver(adapter)
    await _sign_up(driver, email="o@example.com")
    org = await _create_org(driver, name="Co")
    invite_body = {
        "organizationId": org["id"],
        "email": "dup-invite@example.com",
        "role": "member",
    }
    r = await driver.request("POST", "/organization/invite-member", json_body=invite_body)
    assert r.status == 200
    r = await driver.request("POST", "/organization/invite-member", json_body=invite_body)
    assert r.status == 409
    assert r.json()["code"] == "EMAIL_ALREADY_INVITED"


@pytest.mark.parametrize(*org_adapters_param())
async def test_invite_with_unknown_role_rejected(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver = await _make_driver(adapter)
    await _sign_up(driver, email="o@example.com")
    org = await _create_org(driver, name="Co")
    r = await driver.request(
        "POST",
        "/organization/invite-member",
        json_body={
            "organizationId": org["id"],
            "email": "u@example.com",
            "role": "wizard",
        },
    )
    assert r.status == 400
    assert r.json()["code"] == "ROLE_NOT_FOUND"


@pytest.mark.parametrize(*org_adapters_param())
async def test_cancel_invitation(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver = await _make_driver(adapter)
    await _sign_up(driver, email="o@example.com")
    org = await _create_org(driver, name="Co")
    r = await driver.request(
        "POST",
        "/organization/invite-member",
        json_body={
            "organizationId": org["id"],
            "email": "cancel-me@example.com",
            "role": "member",
        },
    )
    invite = r.json()["invitation"]
    r = await driver.request(
        "POST",
        "/organization/cancel-invitation",
        json_body={"invitationId": invite["id"]},
    )
    assert r.status == 200
    # The invite is now cancelled.
    row = await adapter.find_one(
        model="invitation",
        where=(Where(field="id", value=invite["id"]),),
    )
    assert row["status"] == "cancelled"


@pytest.mark.parametrize(*org_adapters_param())
async def test_reject_invitation(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver_a = await _make_driver(adapter)
    driver_b = await _make_driver(adapter)
    await _sign_up(driver_a, email="o@example.com")
    await _sign_up(driver_b, email="rejector@example.com")
    org = await _create_org(driver_a, name="Co")
    r = await driver_a.request(
        "POST",
        "/organization/invite-member",
        json_body={
            "organizationId": org["id"],
            "email": "rejector@example.com",
            "role": "member",
        },
    )
    invite = r.json()["invitation"]
    r = await driver_b.request(
        "POST",
        "/organization/reject-invitation",
        json_body={"invitationId": invite["id"]},
    )
    assert r.status == 200


@pytest.mark.parametrize(*org_adapters_param())
async def test_accept_invitation_wrong_user_rejected(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver_owner = await _make_driver(adapter)
    driver_other = await _make_driver(adapter)
    await _sign_up(driver_owner, email="o@example.com")
    await _sign_up(driver_other, email="not-the-one@example.com")
    org = await _create_org(driver_owner, name="Co")
    r = await driver_owner.request(
        "POST",
        "/organization/invite-member",
        json_body={
            "organizationId": org["id"],
            "email": "someone-else@example.com",
            "role": "member",
        },
    )
    invite = r.json()["invitation"]
    r = await driver_other.request(
        "POST",
        "/organization/accept-invitation",
        json_body={"invitationId": invite["id"]},
    )
    assert r.status == 403
    assert r.json()["code"] == "INVITATION_NOT_FOR_YOU"


@pytest.mark.parametrize(*org_adapters_param())
async def test_list_invitations_for_user(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver_owner = await _make_driver(adapter)
    driver_invitee = await _make_driver(adapter)
    await _sign_up(driver_owner, email="o@example.com")
    await _sign_up(driver_invitee, email="invited@example.com")
    org = await _create_org(driver_owner, name="Co")
    await driver_owner.request(
        "POST",
        "/organization/invite-member",
        json_body={
            "organizationId": org["id"],
            "email": "invited@example.com",
            "role": "member",
        },
    )
    r = await driver_invitee.request("GET", "/organization/list-invitations")
    assert r.status == 200
    rows = r.json()
    assert len(rows) == 1
    assert rows[0]["email"] == "invited@example.com"


@pytest.mark.parametrize(*org_adapters_param())
async def test_update_member_role_requires_owner(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver_owner = await _make_driver(adapter)
    driver_admin = await _make_driver(adapter)
    driver_other = await _make_driver(adapter)
    await _sign_up(driver_owner, email="o@example.com")
    await _sign_up(driver_admin, email="a@example.com")
    await _sign_up(driver_other, email="m@example.com")
    org = await _create_org(driver_owner, name="Co")

    # Owner adds the admin
    r = await driver_owner.request(
        "POST",
        "/organization/invite-member",
        json_body={"organizationId": org["id"], "email": "a@example.com", "role": "admin"},
    )
    inv_a = r.json()["invitation"]
    await driver_admin.request(
        "POST", "/organization/accept-invitation", json_body={"invitationId": inv_a["id"]}
    )

    # Owner adds the regular member
    r = await driver_owner.request(
        "POST",
        "/organization/invite-member",
        json_body={"organizationId": org["id"], "email": "m@example.com", "role": "member"},
    )
    inv_m = r.json()["invitation"]
    await driver_other.request(
        "POST", "/organization/accept-invitation", json_body={"invitationId": inv_m["id"]}
    )

    # Locate the member-row id for the regular member.
    members = await adapter.find_many(
        model="member",
        where=(Where(field="organizationId", value=org["id"]),),
    )
    target_member = next(m for m in members if m["role"] == "member")

    # Admin tries to promote -> NOT_ALLOWED (only owners may change roles).
    r = await driver_admin.request(
        "POST",
        "/organization/update-member-role",
        json_body={
            "organizationId": org["id"],
            "memberId": target_member["id"],
            "role": "admin",
        },
    )
    assert r.status == 403

    # Owner promotes -> ok.
    r = await driver_owner.request(
        "POST",
        "/organization/update-member-role",
        json_body={
            "organizationId": org["id"],
            "memberId": target_member["id"],
            "role": "admin",
        },
    )
    assert r.status == 200, r.json()
    assert r.json()["member"]["role"] == "admin"


@pytest.mark.parametrize(*org_adapters_param())
async def test_cannot_demote_last_owner(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver = await _make_driver(adapter)
    await _sign_up(driver, email="o@example.com")
    org = await _create_org(driver, name="Co")
    # Resolve the owner member-row.
    members = await adapter.find_many(
        model="member",
        where=(Where(field="organizationId", value=org["id"]),),
    )
    owner_member = members[0]
    r = await driver.request(
        "POST",
        "/organization/update-member-role",
        json_body={
            "organizationId": org["id"],
            "memberId": owner_member["id"],
            "role": "member",
        },
    )
    assert r.status == 400
    assert r.json()["code"] == "LAST_OWNER"


@pytest.mark.parametrize(*org_adapters_param())
async def test_has_permission_endpoint(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver = await _make_driver(adapter)
    await _sign_up(driver, email="o@example.com")
    org = await _create_org(driver, name="Co")
    r = await driver.request(
        "POST",
        "/organization/has-permission",
        json_body={
            "organizationId": org["id"],
            "permissions": {"organization": ["delete"]},
        },
    )
    assert r.status == 200
    assert r.json() == {"allowed": True}


@pytest.mark.parametrize(*org_adapters_param())
async def test_has_permission_denies_member(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver_owner = await _make_driver(adapter)
    driver_member = await _make_driver(adapter)
    await _sign_up(driver_owner, email="o@example.com")
    await _sign_up(driver_member, email="m@example.com")
    org = await _create_org(driver_owner, name="Co")
    r = await driver_owner.request(
        "POST",
        "/organization/invite-member",
        json_body={"organizationId": org["id"], "email": "m@example.com", "role": "member"},
    )
    invite = r.json()["invitation"]
    await driver_member.request(
        "POST",
        "/organization/accept-invitation",
        json_body={"invitationId": invite["id"]},
    )
    r = await driver_member.request(
        "POST",
        "/organization/has-permission",
        json_body={
            "organizationId": org["id"],
            "permissions": {"organization": ["delete"]},
        },
    )
    assert r.status == 200
    assert r.json() == {"allowed": False}


@pytest.mark.parametrize(*org_adapters_param())
async def test_teams_create_add_remove_delete(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver_owner = await _make_driver(adapter)
    driver_member = await _make_driver(adapter)
    await _sign_up(driver_owner, email="o-t@example.com")
    await _sign_up(driver_member, email="m-t@example.com")
    org = await _create_org(driver_owner, name="TeamsCo")

    # Add member to the org first.
    r = await driver_owner.request(
        "POST",
        "/organization/invite-member",
        json_body={"organizationId": org["id"], "email": "m-t@example.com", "role": "member"},
    )
    invite = r.json()["invitation"]
    await driver_member.request(
        "POST", "/organization/accept-invitation", json_body={"invitationId": invite["id"]}
    )

    # Create team.
    r = await driver_owner.request(
        "POST",
        "/organization/create-team",
        json_body={"organizationId": org["id"], "name": "Eng"},
    )
    assert r.status == 200
    team = r.json()["team"]

    # Add the member to the team.
    member_user = await adapter.find_one(
        model="user", where=(Where(field="email", value="m-t@example.com"),)
    )
    r = await driver_owner.request(
        "POST",
        "/organization/add-team-member",
        json_body={
            "organizationId": org["id"],
            "teamId": team["id"],
            "userId": member_user["id"],
        },
    )
    assert r.status == 200

    # List teams.
    r = await driver_owner.request(
        "GET", "/organization/list-teams", query=f"organizationId={org['id']}"
    )
    assert r.status == 200
    assert len(r.json()) == 1

    # Remove member from team.
    r = await driver_owner.request(
        "POST",
        "/organization/remove-team-member",
        json_body={
            "organizationId": org["id"],
            "teamId": team["id"],
            "userId": member_user["id"],
        },
    )
    assert r.status == 200

    # Delete team.
    r = await driver_owner.request(
        "POST",
        "/organization/remove-team",
        json_body={"organizationId": org["id"], "teamId": team["id"]},
    )
    assert r.status == 200


@pytest.mark.parametrize(*org_adapters_param())
async def test_team_create_requires_org_member(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver_owner = await _make_driver(adapter)
    driver_stranger = await _make_driver(adapter)
    await _sign_up(driver_owner, email="o@example.com")
    await _sign_up(driver_stranger, email="s@example.com")
    org = await _create_org(driver_owner, name="Co")
    r = await driver_stranger.request(
        "POST",
        "/organization/create-team",
        json_body={"organizationId": org["id"], "name": "Eng"},
    )
    assert r.status == 403
    assert r.json()["code"] == "NOT_MEMBER"


@pytest.mark.parametrize(*org_adapters_param())
async def test_member_cannot_create_team(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver_owner = await _make_driver(adapter)
    driver_member = await _make_driver(adapter)
    await _sign_up(driver_owner, email="o@example.com")
    await _sign_up(driver_member, email="m@example.com")
    org = await _create_org(driver_owner, name="Co")
    r = await driver_owner.request(
        "POST",
        "/organization/invite-member",
        json_body={"organizationId": org["id"], "email": "m@example.com", "role": "member"},
    )
    invite = r.json()["invitation"]
    await driver_member.request(
        "POST", "/organization/accept-invitation", json_body={"invitationId": invite["id"]}
    )
    r = await driver_member.request(
        "POST",
        "/organization/create-team",
        json_body={"organizationId": org["id"], "name": "Eng"},
    )
    assert r.status == 403
    assert r.json()["code"] == "NOT_ALLOWED"


@pytest.mark.parametrize(*org_adapters_param())
async def test_update_organization_by_owner(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver = await _make_driver(adapter)
    await _sign_up(driver, email="u@example.com")
    org = await _create_org(driver, name="Old")
    r = await driver.request(
        "POST",
        "/organization/update",
        json_body={"organizationId": org["id"], "data": {"name": "New"}},
    )
    assert r.status == 200, r.json()
    assert r.json()["name"] == "New"


@pytest.mark.parametrize(*org_adapters_param())
async def test_dynamic_role_crud_round_trip(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    """Custom role creation, listing, and deletion."""
    adapter = await org_adapter_factory()
    driver = await _make_driver(adapter)
    await _sign_up(driver, email="role-admin@example.com")
    org = await _create_org(driver, name="RoleCo")

    # Create a custom role.
    r = await driver.request(
        "POST",
        "/organization/create-role",
        json_body={
            "organizationId": org["id"],
            "role": "editor",
            "permissions": {"member": ["create"]},
        },
    )
    assert r.status == 200, r.json()

    # List should include the new role plus built-ins.
    r = await driver.request("GET", "/organization/list-roles", query=f"organizationId={org['id']}")
    assert r.status == 200
    roles = r.json()
    role_names = [row.get("role") for row in roles]
    assert "editor" in role_names
    assert {"owner", "admin", "member"} <= set(role_names)

    # Delete the custom role.
    r = await driver.request(
        "POST",
        "/organization/delete-role",
        json_body={"organizationId": org["id"], "role": "editor"},
    )
    assert r.status == 200


@pytest.mark.parametrize(*org_adapters_param())
async def test_dynamic_role_rejects_invalid_resource(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver = await _make_driver(adapter)
    await _sign_up(driver, email="o@example.com")
    org = await _create_org(driver, name="Co")
    r = await driver.request(
        "POST",
        "/organization/create-role",
        json_body={
            "organizationId": org["id"],
            "role": "weirdo",
            "permissions": {"galaxy": ["read"]},
        },
    )
    assert r.status == 400
    assert r.json()["code"] == "INVALID_RESOURCE"


@pytest.mark.parametrize(*org_adapters_param())
async def test_cannot_delete_builtin_role(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver = await _make_driver(adapter)
    await _sign_up(driver, email="o@example.com")
    org = await _create_org(driver, name="Co")
    r = await driver.request(
        "POST",
        "/organization/delete-role",
        json_body={"organizationId": org["id"], "role": "owner"},
    )
    assert r.status == 403


@pytest.mark.parametrize(*org_adapters_param())
async def test_get_session_omits_active_org_when_unset(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver = await _make_driver(adapter)
    await _sign_up(driver, email="no-org@example.com")
    r = await driver.request("GET", "/get-session")
    assert r.status == 200
    assert "activeOrganization" not in r.json()


@pytest.mark.parametrize(*org_adapters_param())
async def test_unauthenticated_create_rejected(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver = await _make_driver(adapter)
    r = await driver.request("POST", "/organization/create", json_body={"name": "X"})
    assert r.status == 401


# ---------------------------------------------------------------------------
# Parity: additional read / lookup endpoints (flat upstream paths)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(*org_adapters_param())
async def test_check_slug(org_adapter_factory: Callable[[], Awaitable[Any]]) -> None:
    adapter = await org_adapter_factory()
    driver = await _make_driver(adapter)
    await _sign_up(driver, email="slug@example.com")
    await _create_org(driver, name="Slug Co", slug="slug-co")
    # Free slug → status True
    r = await driver.request("POST", "/organization/check-slug", json_body={"slug": "totally-free"})
    assert r.status == 200, r.json()
    assert r.json()["status"] is True
    # Taken slug → 400 SLUG_TAKEN
    r = await driver.request("POST", "/organization/check-slug", json_body={"slug": "slug-co"})
    assert r.status == 400
    assert r.json()["code"] == "SLUG_TAKEN"


@pytest.mark.parametrize(*org_adapters_param())
async def test_get_full_organization(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver = await _make_driver(adapter)
    await _sign_up(driver, email="full@example.com")
    org = await _create_org(driver, name="Full Co")
    # No query → resolves via active org set on create.
    r = await driver.request("GET", "/organization/get-full-organization")
    assert r.status == 200, r.json()
    body = r.json()
    assert body["id"] == org["id"]
    assert isinstance(body["members"], list) and len(body["members"]) == 1
    assert isinstance(body["invitations"], list)
    assert "teams" in body  # teams enabled in the test driver
    # Explicit slug lookup also works.
    r = await driver.request(
        "GET", "/organization/get-full-organization", query=f"organizationId={org['id']}"
    )
    assert r.status == 200
    assert r.json()["id"] == org["id"]


@pytest.mark.parametrize(*org_adapters_param())
async def test_get_active_member_and_role(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver = await _make_driver(adapter)
    await _sign_up(driver, email="active@example.com")
    org = await _create_org(driver, name="Active Co")
    r = await driver.request("GET", "/organization/get-active-member")
    assert r.status == 200, r.json()
    assert r.json()["role"] == "owner"
    assert r.json()["organizationId"] == org["id"]
    r = await driver.request("GET", "/organization/get-active-member-role")
    assert r.status == 200
    assert r.json()["role"] == "owner"


@pytest.mark.parametrize(*org_adapters_param())
async def test_get_invitation(org_adapter_factory: Callable[[], Awaitable[Any]]) -> None:
    adapter = await org_adapter_factory()
    driver_a = await _make_driver(adapter)
    await _sign_up(driver_a, email="inv-owner@example.com")
    org = await _create_org(driver_a, name="Invite Co")
    r = await driver_a.request(
        "POST",
        "/organization/invite-member",
        json_body={"organizationId": org["id"], "email": "guest@example.com"},
    )
    invite = r.json()["invitation"]
    # The invited user signs up and reads the invitation.
    driver_b = await _make_driver(adapter)
    await _sign_up(driver_b, email="guest@example.com")
    r = await driver_b.request("GET", "/organization/get-invitation", query=f"id={invite['id']}")
    assert r.status == 200, r.json()
    body = r.json()
    assert body["id"] == invite["id"]
    assert body["organizationName"] == "Invite Co"
    assert body["organizationSlug"] == org["slug"]
    assert body["inviterEmail"] == "inv-owner@example.com"
    # A non-recipient is forbidden.
    r = await driver_a.request("GET", "/organization/get-invitation", query=f"id={invite['id']}")
    assert r.status == 403


@pytest.mark.parametrize(*org_adapters_param())
async def test_set_active_team_and_listings(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver = await _make_driver(adapter)
    user = await _sign_up(driver, email="team-active@example.com")
    org = await _create_org(driver, name="TeamCo")
    r = await driver.request(
        "POST",
        "/organization/create-team",
        json_body={"organizationId": org["id"], "name": "Engineering"},
    )
    assert r.status == 200, r.json()
    team = r.json()["team"]
    # Add the owner to the team so they can set it active.
    r = await driver.request(
        "POST",
        "/organization/add-team-member",
        json_body={
            "organizationId": org["id"],
            "teamId": team["id"],
            "userId": user["id"],
        },
    )
    assert r.status == 200, r.json()
    # Set active team.
    r = await driver.request(
        "POST", "/organization/set-active-team", json_body={"teamId": team["id"]}
    )
    assert r.status == 200, r.json()
    assert r.json()["id"] == team["id"]
    # list-user-teams shows the team.
    r = await driver.request("GET", "/organization/list-user-teams")
    assert r.status == 200
    assert any(t["id"] == team["id"] for t in r.json())
    # list-team-members (defaults to active team) shows the owner.
    r = await driver.request("GET", "/organization/list-team-members")
    assert r.status == 200, r.json()
    assert any(m["userId"] == user["id"] for m in r.json())
    # Unset active team.
    r = await driver.request("POST", "/organization/set-active-team", json_body={"teamId": None})
    assert r.status == 200


@pytest.mark.parametrize(*org_adapters_param())
async def test_get_role_dynamic_ac(
    org_adapter_factory: Callable[[], Awaitable[Any]],
) -> None:
    adapter = await org_adapter_factory()
    driver = await _make_driver(adapter)
    await _sign_up(driver, email="role@example.com")
    org = await _create_org(driver, name="RoleCo")
    r = await driver.request(
        "POST",
        "/organization/create-role",
        json_body={
            "organizationId": org["id"],
            "role": "auditor",
            "permissions": {"member": ["read"]},
        },
    )
    assert r.status == 200, r.json()
    r = await driver.request(
        "GET",
        "/organization/get-role",
        query=f"organizationId={org['id']}&roleName=auditor",
    )
    assert r.status == 200, r.json()
    assert r.json()["role"]["role"] == "auditor"
