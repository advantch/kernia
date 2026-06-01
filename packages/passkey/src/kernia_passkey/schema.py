"""Passkey table schema.

1:1 port of ``reference/packages/passkey/src/schema.ts``. The logical model is
``passkey`` with the upstream field set (camelCase logical names, ``credentialID``
included verbatim).
"""

from __future__ import annotations

from kernia.types.adapter import FieldDef, ModelDef

PASSKEY_MODEL = ModelDef(
    name="passkey",
    fields=(
        FieldDef("name", "string", required=False),
        FieldDef("publicKey", "string"),
        FieldDef("userId", "string", references=("user", "id"), index=True),
        FieldDef("credentialID", "string", index=True),
        FieldDef("counter", "number"),
        FieldDef("deviceType", "string"),
        FieldDef("backedUp", "boolean"),
        FieldDef("transports", "string", required=False),
        FieldDef("createdAt", "date", required=False),
        FieldDef("aaguid", "string", required=False),
    ),
)


__all__ = ["PASSKEY_MODEL"]
