"""Organization plugin DB schema.

Mirrors `reference/packages/better-auth/src/plugins/organization/schema.ts`.

Tables:
    * `organization`    — top-level tenant row
    * `member`          — user ↔ organization, with a string ``role``
    * `invitation`      — pending/accepted/cancelled/rejected/expired email invites
    * `team`            — optional, gated by ``teams.enabled``
    * `teamMember`      — optional, gated by ``teams.enabled``
    * `organizationRole`— optional, gated by ``dynamic_access_control.enabled``

We also extend ``session`` with ``activeOrganizationId`` (and ``activeTeamId`` when
teams are on) via :class:`PluginSchema.extend`.
"""

from __future__ import annotations

from collections.abc import Sequence

from kernia.types.adapter import FieldDef, ModelDef
from kernia.types.plugin import PluginSchema

ORGANIZATION_MODEL = ModelDef(
    name="organization",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("name", "string"),
        FieldDef("slug", "string", unique=True),
        FieldDef("logo", "string", required=False),
        FieldDef("metadata", "json", required=False),
        FieldDef("createdAt", "date"),
        FieldDef("updatedAt", "date", required=False),
    ),
)


MEMBER_MODEL = ModelDef(
    name="member",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("organizationId", "string", references=("organization", "id")),
        FieldDef("userId", "string", references=("user", "id")),
        FieldDef("role", "string", default="member"),
        FieldDef("createdAt", "date"),
        # The SQLAlchemy adapter unconditionally writes `updatedAt` on create/update;
        # we expose the column so SQL backends don't reject the insert.
        FieldDef("updatedAt", "date", required=False),
    ),
)


INVITATION_MODEL_FIELDS_BASE: tuple[FieldDef, ...] = (
    FieldDef("id", "string", unique=True),
    FieldDef("organizationId", "string", references=("organization", "id")),
    FieldDef("email", "string"),
    FieldDef("role", "string"),
    FieldDef("status", "string", default="pending"),
    FieldDef("inviterId", "string", references=("user", "id")),
    FieldDef("expiresAt", "date", required=False),
    FieldDef("createdAt", "date"),
    FieldDef("updatedAt", "date", required=False),
)


TEAM_MODEL = ModelDef(
    name="team",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("name", "string"),
        FieldDef("organizationId", "string", references=("organization", "id")),
        FieldDef("createdAt", "date"),
        FieldDef("updatedAt", "date", required=False),
    ),
)


TEAM_MEMBER_MODEL = ModelDef(
    name="teamMember",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("teamId", "string", references=("team", "id")),
        FieldDef("userId", "string", references=("user", "id")),
        FieldDef("createdAt", "date"),
        FieldDef("updatedAt", "date", required=False),
    ),
)


ORGANIZATION_ROLE_MODEL = ModelDef(
    name="organizationRole",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("organizationId", "string", references=("organization", "id")),
        FieldDef("role", "string"),
        FieldDef("permissions", "json"),
        FieldDef("createdAt", "date"),
        FieldDef("updatedAt", "date", required=False),
    ),
)


SESSION_EXTENSIONS_BASE: tuple[FieldDef, ...] = (
    FieldDef("activeOrganizationId", "string", required=False),
)

SESSION_EXTENSIONS_WITH_TEAMS: tuple[FieldDef, ...] = (
    *SESSION_EXTENSIONS_BASE,
    FieldDef("activeTeamId", "string", required=False),
)


def build_schema(
    *,
    teams_enabled: bool = False,
    dynamic_ac_enabled: bool = False,
) -> PluginSchema:
    """Compose the plugin schema based on toggles.

    Mirrors the conditional shape of ``OrganizationSchema<O>`` in the TS reference.
    """
    tables: list[ModelDef] = [ORGANIZATION_MODEL, MEMBER_MODEL]

    invitation_fields = list(INVITATION_MODEL_FIELDS_BASE)
    if teams_enabled:
        invitation_fields.append(FieldDef("teamId", "string", required=False))
    tables.append(ModelDef(name="invitation", fields=tuple(invitation_fields)))

    if teams_enabled:
        tables.append(TEAM_MODEL)
        tables.append(TEAM_MEMBER_MODEL)
    if dynamic_ac_enabled:
        tables.append(ORGANIZATION_ROLE_MODEL)

    session_extensions: Sequence[FieldDef] = (
        SESSION_EXTENSIONS_WITH_TEAMS if teams_enabled else SESSION_EXTENSIONS_BASE
    )

    return PluginSchema(
        tables=tuple(tables),
        extend={"session": tuple(session_extensions)},
    )


__all__ = [
    "INVITATION_MODEL_FIELDS_BASE",
    "MEMBER_MODEL",
    "ORGANIZATION_MODEL",
    "ORGANIZATION_ROLE_MODEL",
    "SESSION_EXTENSIONS_BASE",
    "SESSION_EXTENSIONS_WITH_TEAMS",
    "TEAM_MEMBER_MODEL",
    "TEAM_MODEL",
    "build_schema",
]
