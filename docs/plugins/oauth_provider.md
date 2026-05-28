# OAuth provider

Package: `kernia-oauth-provider`

```bash
pip install kernia-oauth-provider
```

```python
from kernia_oauth_provider import oauth_provider

plugins = [oauth_provider()]
```

## Contributed routes

OIDC discovery, authorization, token, userinfo, JWKS, consent, and client
management routes.

## Schema

Adds OAuth clients, authorization codes, grants, and consent records.

## Coverage

Covered by `e2e/plugins/test_oauth_provider.py`.
