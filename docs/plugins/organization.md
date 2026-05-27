# Organization

> Module: `kernia.plugins.organization`
> Constructor: `AccessControl`

organization — multi-tenant orgs, members, invitations, teams, dynamic AC.

Mirrors `reference/packages/better-auth/src/plugins/organization/`.

Public surface::

    from kernia.plugins.organization import organization

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
from kernia.plugins.organization import AccessControl
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            AccessControl(),
        ],
    )
)
```
