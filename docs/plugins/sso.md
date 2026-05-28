# SSO

Package: `kernia-sso`

```bash
pip install kernia-sso
```

```python
from kernia_sso import sso

plugins = [sso()]
```

## Contributed routes

Enterprise SSO routes for SAML and OIDC identity-provider discovery, callback,
and organization-linked sign-in.

## Schema

Adds enterprise SSO provider configuration and account linkage records.

## Coverage

Covered by `e2e/plugins/test_sso.py`, including strict SAML validation against a
mock IdP.
