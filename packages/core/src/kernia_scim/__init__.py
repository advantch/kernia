"""better-auth SCIM 2.0 plugin.

Mirrors ``reference/packages/scim/``. Exposes the standard SCIM 2.0 surface under
``/scim/v2/`` authenticated by a per-provider Bearer ``scimToken``, plus
org-scoped provider/token management endpoints (``/scim/generate-token`` etc.)
authenticated by a logged-in session.
"""

from kernia_scim.patch_operations import build_user_patch
from kernia_scim.plugin import scim
from kernia_scim.types import (
    ProviderOwnership,
    SCIMOptions,
    SCIMProvider,
    StoreSCIMToken,
)

__all__ = [
    "ProviderOwnership",
    "SCIMOptions",
    "SCIMProvider",
    "StoreSCIMToken",
    "build_user_patch",
    "scim",
]
