# Jwt

> Module: `kernia.plugins.jwt`
> Constructor: `jwt`

JWT plugin.

Mirrors `Better Auth reference: plugins/jwt/`. Issues JSON Web Tokens
signed with a key managed in our `jwk` table; exposes a JWKS doc; supports key
rotation.

Endpoints:
  * GET  /token         — issue a JWT (requires session)
  * GET  /jwks          — return the JSON Web Key Set
  * POST /jwks/rotate   — rotate the active signing key (admin)

## Endpoints

| Method | Path |
| --- | --- |
| `GET` | `/token` |
| `GET` | `/jwks` |
| `POST` | `/jwks/rotate` |

## Schema contributions

**New tables:**

- `jwk` — fields: id, keyId, algorithm, publicKey, privateKey, isActive, createdAt, expiresAt

## Usage

```python
from kernia.plugins.jwt import jwt
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            jwt(),
        ],
    )
)
```
