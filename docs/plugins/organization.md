# Organization

> Module: `kernia.plugins.organization`
> Constructor: `organization`

organization — multi-tenant orgs, members, invitations, teams, dynamic AC.

Mirrors `Better Auth reference: plugins/organization/`.

Public surface::

    from kernia.plugins.organization import organization

    organization(
        teams=True,
        dynamic_access_control=True,
        send_invitation=mock_smtp.send,
    )

## Endpoints

| Method | Path |
| --- | --- |
| `POST` | `/organization/create` |
| `GET` | `/organization/list` |
| `GET` | `/organization/get` |
| `POST` | `/organization/update` |
| `POST` | `/organization/delete` |
| `POST` | `/organization/set-active` |
| `POST` | `/organization/invite-member` |
| `POST` | `/organization/cancel-invitation` |
| `POST` | `/organization/accept-invitation` |
| `POST` | `/organization/reject-invitation` |
| `GET` | `/organization/list-invitations` |
| `GET` | `/organization/list-members` |
| `POST` | `/organization/remove-member` |
| `POST` | `/organization/update-member-role` |
| `POST` | `/organization/leave` |
| `POST` | `/organization/has-permission` |

## Schema contributions

**New tables:**

- `organization` — fields: id, name, slug, logo, metadata, createdAt, updatedAt
- `member` — fields: id, organizationId, userId, role, createdAt, updatedAt
- `invitation` — fields: id, organizationId, email, role, status, inviterId, expiresAt, createdAt, updatedAt

**Extends existing tables:**

- `session` adds: activeOrganizationId

## Usage

```python
from kernia.plugins.organization import organization
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            organization(),
        ],
    )
)
```
