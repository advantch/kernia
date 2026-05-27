"""Generic-OAuth provider configuration.

Mirrors `GenericOAuthConfig` from
`reference/packages/better-auth/src/plugins/generic-oauth/types.ts`.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any


TokenGetter = Callable[
    [str, str, str | None],  # code, redirect_uri, code_verifier
    Awaitable[Mapping[str, Any]],
]
UserInfoGetter = Callable[[Mapping[str, Any]], Awaitable[Mapping[str, Any] | None]]
ProfileMapper = Callable[[Mapping[str, Any]], Mapping[str, Any]]


@dataclass
class GenericOAuthConfig:
    """Per-provider configuration for the generic OAuth plugin.

    Required: `provider_id`, `client_id`, `client_secret`, and either
    `discovery_url` or the explicit `authorization_url` + `token_url` pair.
    """

    provider_id: str
    client_id: str
    client_secret: str
    scopes: tuple[str, ...] = ()
    redirect_uri: str | None = None
    authorization_url: str | None = None
    token_url: str | None = None
    user_info_url: str | None = None
    discovery_url: str | None = None
    issuer: str | None = None
    require_issuer_validation: bool = False
    response_type: str = "code"
    response_mode: str | None = None
    prompt: str | None = None
    pkce: bool = False
    access_type: str | None = None
    authentication: str = "post"  # "post" | "basic"
    authorization_url_params: Mapping[str, str] = field(default_factory=dict)
    token_url_params: Mapping[str, str] = field(default_factory=dict)
    get_token: TokenGetter | None = None
    get_user_info: UserInfoGetter | None = None
    map_profile_to_user: ProfileMapper | None = None
    disable_implicit_sign_up: bool = False
    disable_sign_up: bool = False
    override_user_info: bool = False

    def __post_init__(self) -> None:
        if not self.authorization_url and not self.discovery_url:
            raise ValueError(
                f"GenericOAuthConfig({self.provider_id!r}): one of "
                "`authorization_url` or `discovery_url` must be provided."
            )
        if not self.token_url and not self.discovery_url:
            raise ValueError(
                f"GenericOAuthConfig({self.provider_id!r}): one of "
                "`token_url` or `discovery_url` must be provided."
            )


__all__ = ["GenericOAuthConfig", "TokenGetter", "UserInfoGetter", "ProfileMapper"]
