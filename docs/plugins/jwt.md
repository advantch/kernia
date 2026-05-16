# Jwt

> Module: `better_auth.plugins.jwt`
> Constructor: `jwt`

JWT plugin.

Mirrors `reference/packages/better-auth/src/plugins/jwt/`. Issues JSON Web Tokens
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
from better_auth.plugins.jwt import jwt
from better_auth import BetterAuthOptions
from better_auth.auth import init

auth = init(
    BetterAuthOptions(
        database=...,
        secret=...,
        plugins=[
            jwt(),
        ],
    )
)
```
