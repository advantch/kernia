# Admin

> Module: `kernia.plugins.admin`
> Constructor: `admin`

admin plugin — user management surface gated on the `access` primitive.

Mirrors `Better Auth reference: plugins/admin/`.

Schema extensions:
  * `user.role: string`
  * `user.banned: boolean`
  * `user.banReason: string?`
  * `user.banExpires: integer?`
  * `session.impersonatedBy: string?`

Endpoints under `/admin/*`. All require an admin role (resolved via the
`access` plugin's `Role.authorize`).

## Endpoints

| Method | Path |
| --- | --- |
| `POST` | `/admin/list-users` |
| `POST` | `/admin/get-user` |
| `POST` | `/admin/create-user` |
| `POST` | `/admin/update-user` |
| `POST` | `/admin/set-role` |
| `POST` | `/admin/ban-user` |
| `POST` | `/admin/unban-user` |
| `POST` | `/admin/impersonate-user` |
| `POST` | `/admin/stop-impersonating` |
| `POST` | `/admin/list-user-sessions` |
| `POST` | `/admin/revoke-user-session` |
| `POST` | `/admin/revoke-user-sessions` |
| `POST` | `/admin/set-user-password` |
| `POST` | `/admin/remove-user` |
| `POST` | `/admin/has-permission` |

## Schema contributions


**Extends existing tables:**

- `user` adds: role, banned, banReason, banExpires
- `session` adds: impersonatedBy

## Usage

```python
from kernia.plugins.admin import admin
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            admin(),
        ],
    )
)
```
