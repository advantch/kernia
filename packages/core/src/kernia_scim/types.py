"""SCIM plugin option types. Mirrors ``reference/packages/scim/src/types.ts``."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

# storeSCIMToken accepts a keyword ("plain"/"hashed"/"encrypted") or a dict with
# either a {"hash": fn} or {"encrypt": fn, "decrypt": fn} callable map.
StoreSCIMToken = str | Mapping[str, Callable[[str], Any]]


@dataclass(frozen=True, slots=True)
class ProviderOwnership:
    enabled: bool = False


@dataclass(frozen=True, slots=True)
class SCIMProvider:
    """A row in the ``scimProvider`` table (id omitted in default configs)."""

    provider_id: str
    scim_token: str
    organization_id: str | None = None
    user_id: str | None = None
    id: str | None = None


@dataclass(frozen=True, slots=True)
class SCIMOptions:
    """Configuration for the SCIM plugin.

    Field names mirror the upstream camelCase options:

      * ``provider_ownership`` — link each provider to the token's creator.
      * ``required_role`` — org role(s) allowed to manage SCIM providers.
        Defaults to ``["admin", creatorRole ?? "owner"]``.
      * ``default_scim`` — in-memory providers (used for testing). Take
        precedence over the database.
      * ``before_scim_token_generated`` / ``after_scim_token_generated`` — hooks.
      * ``store_scim_token`` — at-rest token representation (default "plain").
    """

    provider_ownership: ProviderOwnership | None = None
    required_role: Sequence[str] | None = None
    default_scim: Sequence[SCIMProvider] = ()
    before_scim_token_generated: Callable[[dict[str, Any]], Awaitable[None] | None] | None = None
    after_scim_token_generated: Callable[[dict[str, Any]], Awaitable[None] | None] | None = None
    store_scim_token: StoreSCIMToken = "plain"
    # Optional override of the organization creator role when computing the
    # default required role set (the Python organization plugin does not expose
    # a creatorRole option, so this is surfaced here for parity tests).
    creator_role: str | None = None


__all__ = [
    "ProviderOwnership",
    "SCIMOptions",
    "SCIMProvider",
    "StoreSCIMToken",
]
