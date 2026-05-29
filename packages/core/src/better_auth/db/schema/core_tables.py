"""The four core tables.

Mirrors `reference/packages/better-auth/src/db/schema/index.ts`. Field names match
the reference verbatim so existing better-auth JS clients can talk to a Python server
without translation.
"""

from __future__ import annotations

from better_auth.types.adapter import FieldDef, ModelDef

USER_MODEL = ModelDef(
    name="user",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("email", "string", unique=True),
        FieldDef("emailVerified", "boolean", default=False),
        FieldDef("name", "string", required=False),
        FieldDef("image", "string", required=False),
        FieldDef("createdAt", "date"),
        FieldDef("updatedAt", "date"),
    ),
)


SESSION_MODEL = ModelDef(
    name="session",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("userId", "string", references=("user", "id")),
        FieldDef("token", "string", unique=True),
        FieldDef("expiresAt", "date"),
        FieldDef("ipAddress", "string", required=False),
        FieldDef("userAgent", "string", required=False),
        FieldDef("createdAt", "date"),
        FieldDef("updatedAt", "date"),
    ),
)


ACCOUNT_MODEL = ModelDef(
    name="account",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("userId", "string", references=("user", "id")),
        FieldDef("accountId", "string"),
        FieldDef("providerId", "string"),
        FieldDef("accessToken", "string", required=False),
        FieldDef("refreshToken", "string", required=False),
        FieldDef("idToken", "string", required=False),
        FieldDef("accessTokenExpiresAt", "date", required=False),
        FieldDef("refreshTokenExpiresAt", "date", required=False),
        FieldDef("scope", "string", required=False),
        FieldDef("password", "string", required=False),  # for email/password
        FieldDef("createdAt", "date"),
        FieldDef("updatedAt", "date"),
    ),
)


VERIFICATION_MODEL = ModelDef(
    name="verification",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("identifier", "string"),
        FieldDef("value", "string"),
        FieldDef("expiresAt", "date"),
        FieldDef("createdAt", "date"),
        FieldDef("updatedAt", "date"),
    ),
)


CORE_MODELS = (USER_MODEL, SESSION_MODEL, ACCOUNT_MODEL, VERIFICATION_MODEL)
