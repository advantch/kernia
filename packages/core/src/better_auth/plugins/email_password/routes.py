"""Email/password endpoint definitions.

Mirrors the route handlers in
`reference/packages/better-auth/src/api/routes/sign-{up,in}-email.ts`. The handler
implementations are filled in during Phase 2/3; this module declares the route
table so that Phase 1 type-checks.
"""

from __future__ import annotations

from dataclasses import dataclass

from better_auth.api.endpoint import create_auth_endpoint
from better_auth.types.context import EndpointContext
from better_auth.types.endpoint import AuthEndpoint, EndpointOptions


# ----- Pydantic request models (kept inline so Phase 1 doesn't depend on routes/) -----

# Phase 1 uses dataclasses to avoid a hard pydantic dep at this layer; Phase 3 swaps
# these for pydantic.BaseModel so request validation is automatic. The endpoint
# factory accepts any type that provides a constructor-from-dict.


@dataclass(frozen=True, slots=True)
class SignUpEmailBody:
    email: str
    password: str
    name: str | None = None


@dataclass(frozen=True, slots=True)
class SignInEmailBody:
    email: str
    password: str
    remember_me: bool = True


@dataclass(frozen=True, slots=True)
class ForgetPasswordBody:
    email: str
    redirect_to: str | None = None


@dataclass(frozen=True, slots=True)
class ResetPasswordBody:
    token: str
    password: str


# ----- Handlers (Phase 2/3 fills these in) -----


async def _sign_up_email(ctx: EndpointContext) -> dict[str, object]:
    raise NotImplementedError("sign-up/email handler lands in Phase 3")


async def _sign_in_email(ctx: EndpointContext) -> dict[str, object]:
    raise NotImplementedError("sign-in/email handler lands in Phase 3")


async def _forget_password(ctx: EndpointContext) -> dict[str, object]:
    raise NotImplementedError("forget-password handler lands in Phase 3")


async def _reset_password(ctx: EndpointContext) -> dict[str, object]:
    raise NotImplementedError("reset-password handler lands in Phase 3")


# ----- Endpoint table -----

SIGN_UP_EMAIL = create_auth_endpoint(
    "/sign-up/email",
    EndpointOptions(method="POST", body=SignUpEmailBody),
    _sign_up_email,
)

SIGN_IN_EMAIL = create_auth_endpoint(
    "/sign-in/email",
    EndpointOptions(method="POST", body=SignInEmailBody),
    _sign_in_email,
)

FORGET_PASSWORD = create_auth_endpoint(
    "/forget-password",
    EndpointOptions(method="POST", body=ForgetPasswordBody),
    _forget_password,
)

RESET_PASSWORD = create_auth_endpoint(
    "/reset-password",
    EndpointOptions(method="POST", body=ResetPasswordBody),
    _reset_password,
)


ALL: tuple[AuthEndpoint, ...] = (
    SIGN_UP_EMAIL,
    SIGN_IN_EMAIL,
    FORGET_PASSWORD,
    RESET_PASSWORD,
)
