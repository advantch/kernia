# API keys

Package: `kernia-api-key`

```bash
pip install kernia-api-key
```

```python
from kernia_api_key import api_key

plugins = [api_key()]
```

## Contributed routes

- `/api-key/create`
- `/api-key/list`
- `/api-key/revoke`
- `/api-key/verify`

## Schema

Adds an API key table with hashed key storage, expiration, enabled state, and
metadata.

## Coverage

Covered by `e2e/plugins/test_api_key.py` and the SaaS demo settings page.
