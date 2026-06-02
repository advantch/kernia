# Passkeys

Package: `kernia-passkey`

```bash
pip install kernia-passkey
```

```python
from kernia_passkey import passkey

plugins = [passkey()]
```

## Contributed routes

Passkey registration and authentication routes are mounted under the Kernia auth
prefix.

## Schema

Adds WebAuthn credential records linked to users.

## Coverage

Covered by `e2e/plugins/test_passkey.py` with a software authenticator that
exercises registration, authentication, and signature failure cases.
