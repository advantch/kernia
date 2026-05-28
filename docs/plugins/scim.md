# SCIM

Package: `kernia-scim`

```bash
pip install kernia-scim
```

```python
from kernia_scim import scim

plugins = [scim()]
```

## Contributed routes

SCIM user and group provisioning routes are mounted under the auth prefix.

## Schema

Adds SCIM identity and provisioning metadata.

## Coverage

Covered by `e2e/plugins/test_scim.py`.
