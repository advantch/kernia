"""Kernia SCIM 2.0 plugin.

Mirrors `reference/packages/scim/`. Exposes the standard SCIM 2.0 surface under
`/scim/v2/`. Authentication can be either an admin session (resolved via the
`admin` plugin's role gate) OR an api_key carrying `scope.scim == True`.
"""

from kernia_scim.plugin import SCIMOptions, scim
from kernia_scim.patch import apply_patch_ops

__all__ = ["SCIMOptions", "apply_patch_ops", "scim"]
