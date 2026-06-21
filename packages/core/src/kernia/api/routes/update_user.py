"""User-mutation routes.

Mirrors `reference/.../api/routes/update-user.ts`:
  POST   /update-user        — patch name/image (extensible via additional-fields plugin)
  POST   /change-email       — change email; sends verification if required
  POST   /change-password    — change password with current-password check
  POST   /delete-user        — permanent delete with current-password check
"""

from __future__ import annotations

import time

from pydantic import BaseModel, ConfigDict, Field

from kernia.api.endpoint import create_auth_endpoint
from kernia.crypto import hash_password, verify_password
from kernia.error import APIError
from kernia.types.adapter import Where
from kernia.types.context import EndpointContext
from kernia.types.endpoint import EndpointOptions


class UpdateUserBody(BaseModel):
    # ``populate_by_name`` lets the wire send ``displayUsername`` (camelCase) while
    # the field stays snake_case internally. ``username``/``display_username`` are
    # inert unless the username plugin's ``/update-user`` before-hook processes
    # them (validation, normalization, duplicate rejection).
    model_config = ConfigDict(populate_by_name=True)

    name: str | None = None
    image: str | None = None
    username: str | None = None
    display_username: str | None = Field(default=None, alias="displayUsername")


class ChangeEmailBody(BaseModel):
    new_email: str
    callback_url: str | None = None


class ChangePasswordBody(BaseModel):
    current_password: str
    new_password: str
    revoke_other_sessions: bool = True


class DeleteUserBody(BaseModel):
    current_password: str | None = None


async def _update_user(ctx: EndpointContext) -> dict[str, object]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: UpdateUserBody = ctx.body
    patch: dict[str, object] = {"updatedAt": int(time.time())}
    if body.name is not None:
        patch["name"] = body.name
    if body.image is not None:
        patch["image"] = body.image
    user = await ctx.auth.adapter.update(
        model="user",
        where=(Where(field="id", value=ctx.session.user_id),),
        update=patch,
    )
    return {"user": user}


async def _change_email(ctx: EndpointContext) -> dict[str, object]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: ChangeEmailBody = ctx.body
    # uniqueness check
    other = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="email", value=body.new_email),),
    )
    if other and other["id"] != ctx.session.user_id:
        raise APIError(409, "EMAIL_ALREADY_IN_USE")
    # if email verification is required, defer the change until verified
    if ctx.auth.options.email_and_password.require_email_verification:
        await ctx.auth.adapter.create(
            model="verification",
            data={
                "identifier": f"email-change:{ctx.session.user_id}",
                "value": body.new_email,
                "expiresAt": int(time.time()) + 3600,
            },
        )
        return {"status": "verification-required"}
    updated = await ctx.auth.adapter.update(
        model="user",
        where=(Where(field="id", value=ctx.session.user_id),),
        update={"email": body.new_email, "emailVerified": False, "updatedAt": int(time.time())},
    )
    return {"user": updated, "status": "updated"}


async def _change_password(ctx: EndpointContext) -> dict[str, object]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: ChangePasswordBody = ctx.body
    opts = ctx.auth.options.email_and_password
    if len(body.new_password) < opts.min_password_length:
        raise APIError(400, "PASSWORD_TOO_SHORT")
    if len(body.new_password) > opts.max_password_length:
        raise APIError(400, "PASSWORD_TOO_LONG")

    account = await ctx.auth.adapter.find_one(
        model="account",
        where=(
            Where(field="userId", value=ctx.session.user_id),
            Where(field="providerId", value="credential"),
        ),
    )
    if not account or not account.get("password"):
        raise APIError(400, "INVALID_REQUEST", message="No password set on this account.")
    if not verify_password(body.current_password, account["password"]):
        raise APIError(401, "INVALID_CREDENTIALS")

    await ctx.auth.adapter.update(
        model="account",
        where=(Where(field="id", value=account["id"]),),
        update={"password": hash_password(body.new_password), "updatedAt": int(time.time())},
    )
    if body.revoke_other_sessions:
        await ctx.auth.adapter.delete_many(
            model="session",
            where=(
                Where(field="userId", value=ctx.session.user_id),
                Where(field="token", value=ctx.session.token, operator="ne"),
            ),
        )
    return {"success": True}


async def _delete_user(ctx: EndpointContext) -> dict[str, bool]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: DeleteUserBody = ctx.body
    if body.current_password is not None:
        account = await ctx.auth.adapter.find_one(
            model="account",
            where=(
                Where(field="userId", value=ctx.session.user_id),
                Where(field="providerId", value="credential"),
            ),
        )
        if account and account.get("password"):
            if not verify_password(body.current_password, account["password"]):
                raise APIError(401, "INVALID_CREDENTIALS")
    # cascade delete: sessions, accounts, then user
    await ctx.auth.adapter.delete_many(
        model="session",
        where=(Where(field="userId", value=ctx.session.user_id),),
    )
    await ctx.auth.adapter.delete_many(
        model="account",
        where=(Where(field="userId", value=ctx.session.user_id),),
    )
    await ctx.auth.adapter.delete(
        model="user",
        where=(Where(field="id", value=ctx.session.user_id),),
    )
    return {"success": True}


UPDATE_USER_ROUTES = (
    create_auth_endpoint(
        "/update-user",
        EndpointOptions(method="POST", body=UpdateUserBody, requires_session=True),
        _update_user,
    ),
    create_auth_endpoint(
        "/change-email",
        EndpointOptions(method="POST", body=ChangeEmailBody, requires_session=True),
        _change_email,
    ),
    create_auth_endpoint(
        "/change-password",
        EndpointOptions(method="POST", body=ChangePasswordBody, requires_session=True),
        _change_password,
    ),
    create_auth_endpoint(
        "/delete-user",
        EndpointOptions(method="POST", body=DeleteUserBody, requires_session=True),
        _delete_user,
    ),
)
