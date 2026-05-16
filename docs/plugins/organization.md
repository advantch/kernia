# Organization

> Module: `better_auth.plugins.organization`
> Constructor: `AccessControl`

organization — multi-tenant orgs, members, invitations, teams, dynamic AC.

Mirrors `reference/packages/better-auth/src/plugins/organization/`.

Public surface::

    from better_auth.plugins.organization import organization

    organization(
        teams=True,
        dynamic_access_control=True,
        send_invitation=mock_smtp.send,
    )

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from better_auth.plugins.organization import AccessControl
from better_auth import BetterAuthOptions
from better_auth.auth import init

auth = init(
    BetterAuthOptions(
        database=...,
        secret=...,
        plugins=[
            AccessControl(),
        ],
    )
)
```
