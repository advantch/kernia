"""Database schema for the SSO plugin.

Two tables:

  * `ssoProvider` — declarative provider config. `oidcConfig` and `samlConfig` are
    JSON-encoded strings so adapters that don't natively support JSON columns can
    still store them. `domains` is a JSON-encoded list of strings.
  * `ssoDomain` — verified-domain registry. A domain is associated with exactly one
    provider; verification follows a DNS-TXT-style token flow.

These mirror the reference TS schema in `packages/sso/src/index.ts` but split the
domain rows into their own table so we can store the per-domain verification
token + state independently of the provider record.
"""

from __future__ import annotations

from kernia.types.adapter import FieldDef, ModelDef

SSO_PROVIDER_MODEL = ModelDef(
    name="ssoProvider",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("issuer", "string", unique=True),
        FieldDef("kind", "string"),  # "saml" | "oidc"
        FieldDef("name", "string", required=False),
        FieldDef("domains", "text", required=False),  # JSON list[str]
        FieldDef("oidcConfig", "text", required=False),  # JSON dict
        FieldDef("samlConfig", "text", required=False),  # JSON dict
        FieldDef("userInfoMapping", "text", required=False),  # JSON dict
        # Link a provider to an organization. When set (and the organization
        # plugin is installed) SSO sign-ins through this provider auto-provision
        # the user as a member. Mirrors upstream `ssoProvider.organizationId`.
        FieldDef("organizationId", "string", required=False),
        # The user who registered this provider. Mirrors upstream
        # ``ssoProvider.userId`` and underpins ownership-based access control on
        # the read/update/delete endpoints (the registering user owns the
        # provider unless it is linked to an organization, in which case org
        # admins/owners gain access).
        FieldDef("userId", "string", required=False),
        FieldDef("createdAt", "date"),
        FieldDef("updatedAt", "date"),
    ),
)


SSO_DOMAIN_MODEL = ModelDef(
    name="ssoDomain",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("domain", "string", unique=True),
        FieldDef("ssoProviderId", "string", references=("ssoProvider", "id")),
        FieldDef("verified", "boolean", default=False),
        FieldDef("verificationToken", "string"),
        FieldDef("createdAt", "date"),
    ),
)


SSO_MODELS = (SSO_PROVIDER_MODEL, SSO_DOMAIN_MODEL)


__all__ = ["SSO_DOMAIN_MODEL", "SSO_MODELS", "SSO_PROVIDER_MODEL"]
