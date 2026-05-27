"""admin plugin — user management surface gated on the `access` primitive.

Mirrors `reference/packages/better-auth/src/plugins/admin/`.

Schema extensions:
  * `user.role: string`
  * `user.banned: boolean`
  * `user.banReason: string?`
  * `user.banExpires: integer?`
  * `session.impersonatedBy: string?`

Endpoints under `/admin/*`. All require an admin role (resolved via the
`access` plugin's `Role.authorize`).
"""

from kernia.plugins.admin.plugin import AdminOptions, admin

__all__ = ["AdminOptions", "admin"]
