# Admin

> Module: `better_auth.plugins.admin`
> Constructor: `AdminOptions`

admin plugin — user management surface gated on the `access` primitive.

Mirrors `reference/packages/better-auth/src/plugins/admin/`.

Schema extensions:
  * `user.role: string`
  * `user.banned: boolean`
  * `user.banReason: string?`
  * `user.banExpires: integer?`
  * `session.impersonatedBy: string?`

Endpoints under `/admin/*`. All require an admin role (resolved via the
`access` plugin's `Role.authorize`).

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from better_auth.plugins.admin import AdminOptions
from better_auth import BetterAuthOptions
from better_auth.auth import init

auth = init(
    BetterAuthOptions(
        database=...,
        secret=...,
        plugins=[
            AdminOptions(),
        ],
    )
)
```
