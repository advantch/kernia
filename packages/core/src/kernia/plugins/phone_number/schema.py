"""Phone-number plugin schema additions.

Adds `phoneNumber` (unique, nullable) and `phoneNumberVerified` (boolean) to the
core `user` table. Mirrors `reference/packages/better-auth/src/plugins/phone-number/schema.ts`.
"""

from __future__ import annotations

from kernia.types.adapter import FieldDef
from kernia.types.plugin import PluginSchema


PHONE_NUMBER_USER_FIELDS: tuple[FieldDef, ...] = (
    FieldDef("phoneNumber", "string", required=False, unique=True),
    FieldDef("phoneNumberVerified", "boolean", required=False, default=False),
)


def phone_number_schema() -> PluginSchema:
    return PluginSchema(extend={"user": PHONE_NUMBER_USER_FIELDS})
