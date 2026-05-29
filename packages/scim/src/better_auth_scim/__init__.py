"""better-auth SCIM 2.0 plugin.

Mirrors `reference/packages/scim/`. Exposes the standard SCIM 2.0 surface under
`/scim/v2/`. Authentication can be either an admin session (resolved via the
`admin` plugin's role gate) OR an api_key carrying `scope.scim == True`.
"""

from better_auth_scim.patch import apply_patch_ops
from better_auth_scim.plugin import SCIMOptions, scim

__all__ = ["SCIMOptions", "apply_patch_ops", "scim"]
