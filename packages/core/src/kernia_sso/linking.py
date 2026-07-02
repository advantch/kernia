"""Organization auto-provisioning for SSO sign-ins.

Port of `reference/packages/sso/src/linking/org-assignment.ts`, adapted to the
Python SSO schema. Two entry points:

  * :func:`assign_organization_from_provider` — used inside the OIDC/SAML
    callbacks. When the provider row carries an ``organizationId`` (and the
    organization plugin is installed), the freshly signed-in user is added as a
    member of that organization.
  * :func:`assign_organization_by_domain` — used for *non-SSO* sign-ins (e.g. a
    plain OAuth login with a corporate email): the user's email domain is matched
    against the registered SSO domains, and if a verified domain maps to a
    provider linked to an organization, the user is provisioned there.

Schema note vs. upstream: the JS port stores ``domain`` + ``domainVerified`` on
the provider row, whereas this Python port keeps a dedicated unique ``ssoDomain``
table. The verification check therefore reads ``ssoDomain.verified`` rather than
``ssoProvider.domainVerified``. Because ``ssoDomain.domain`` is unique, the
upstream "multiple providers claim the same domain" spoofing vector is
structurally impossible here — the uniqueness constraint enforces a single owner
per domain.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from kernia.types.adapter import Where
from kernia.types.context import AuthContext

from kernia_sso.domain import email_domain

# A provisioning options bag (snake_case or camelCase keys both accepted):
#   disabled: bool
#   default_role / defaultRole: str
#   get_role / getRole: callable(dict) -> str | Awaitable[str]
ProvisioningOptions = Mapping[str, Any]


def _now() -> int:
    return int(time.time())


def _org_plugin_present(auth: AuthContext) -> bool:
    return any(getattr(p, "id", None) == "organization" for p in getattr(auth, "plugins", []) or [])


async def _resolve_role(
    provisioning_options: ProvisioningOptions | None,
    *,
    user: Mapping[str, Any],
    user_info: Mapping[str, Any],
    provider: Mapping[str, Any],
    token: Any = None,
) -> str:
    po = provisioning_options or {}
    get_role: Callable[..., Any] | None = po.get("get_role", po.get("getRole"))
    if get_role is not None:
        result = get_role(
            {
                "user": user,
                "userInfo": user_info,
                "token": token,
                "provider": provider,
            }
        )
        if isinstance(result, Awaitable):
            result = await result
        return str(result)
    return str(po.get("default_role", po.get("defaultRole")) or "member")


async def _already_member(auth: AuthContext, *, organization_id: str, user_id: str) -> bool:
    existing = await auth.adapter.find_one(
        model="member",
        where=(
            Where(field="organizationId", value=organization_id),
            Where(field="userId", value=user_id),
        ),
    )
    return existing is not None


async def _create_member(
    auth: AuthContext, *, organization_id: str, user_id: str, role: str
) -> None:
    now = _now()
    await auth.adapter.create(
        model="member",
        data={
            "organizationId": organization_id,
            "userId": user_id,
            "role": role,
            "createdAt": now,
            "updatedAt": now,
        },
    )


async def assign_organization_from_provider(
    auth: AuthContext,
    *,
    user: Mapping[str, Any],
    provider: Mapping[str, Any],
    token: Any = None,
    user_info: Mapping[str, Any] | None = None,
    provisioning_options: ProvisioningOptions | None = None,
) -> None:
    """Provision ``user`` into the provider's linked organization, if any.

    No-ops when: the provider has no ``organizationId``, provisioning is
    disabled, the organization plugin is absent, or the user is already a member.
    """
    organization_id = provider.get("organizationId")
    if not organization_id:
        return
    if (provisioning_options or {}).get("disabled"):
        return
    if not _org_plugin_present(auth):
        return
    user_id = str(user["id"])
    if await _already_member(auth, organization_id=str(organization_id), user_id=user_id):
        return
    role = await _resolve_role(
        provisioning_options,
        user=user,
        user_info=user_info or {},
        provider=provider,
        token=token,
    )
    await _create_member(auth, organization_id=str(organization_id), user_id=user_id, role=role)


async def assign_organization_by_domain(
    auth: AuthContext,
    *,
    user: Mapping[str, Any],
    provisioning_options: ProvisioningOptions | None = None,
    domain_verification: Mapping[str, Any] | None = None,
) -> None:
    """Provision ``user`` based on their email domain → SSO provider → org.

    When ``domain_verification`` is enabled, only *verified* domains are
    considered. No-ops on the same conditions as
    :func:`assign_organization_from_provider`, plus when the email domain matches
    no registered SSO domain.
    """
    if (provisioning_options or {}).get("disabled"):
        return
    if not _org_plugin_present(auth):
        return
    domain = email_domain(str(user.get("email") or ""))
    if not domain:
        return

    require_verified = bool((domain_verification or {}).get("enabled"))
    where = [Where(field="domain", value=domain)]
    if require_verified:
        where.append(Where(field="verified", value=True))
    sso_domain = await auth.adapter.find_one(model="ssoDomain", where=tuple(where))
    if sso_domain is None:
        return

    provider = await auth.adapter.find_one(
        model="ssoProvider",
        where=(Where(field="id", value=sso_domain["ssoProviderId"]),),
    )
    if not provider or not provider.get("organizationId"):
        return

    organization_id = str(provider["organizationId"])
    user_id = str(user["id"])
    if await _already_member(auth, organization_id=organization_id, user_id=user_id):
        return
    role = await _resolve_role(
        provisioning_options,
        user=user,
        user_info={},
        provider=provider,
        token=None,
    )
    await _create_member(auth, organization_id=organization_id, user_id=user_id, role=role)


__all__ = [
    "assign_organization_by_domain",
    "assign_organization_from_provider",
]
