# Two Factor

> Module: `kernia.plugins.two_factor`
> Constructor: `two_factor`

two_factor plugin — TOTP + backup codes.

Port of `Better Auth reference: plugins/two-factor/`. Adds two tables
(`twoFactorConfirmation`, `twoFactorBackupCode`) and extends `user` with
`twoFactorEnabled` + `twoFactorSecret`.

Hooks into `/sign-in/email`: if the user has 2FA enabled, the endpoint normally
returns a session; the after-hook intercepts that, deletes the just-created
session, and returns `{requiresTwoFactor: True, confirmationId: ...}` instead.
The follow-up `/two-factor/verify-totp` (or `/two-factor/verify-backup-code`)
exchanges the confirmation id for a real session.

Requires `pyotp` (declared under the `two-factor` extra of `Better Auth`).

## Endpoints

| Method | Path |
| --- | --- |
| `POST` | `/two-factor/enable` |
| `POST` | `/two-factor/verify-totp` |
| `POST` | `/two-factor/disable` |
| `POST` | `/two-factor/generate-backup-codes` |
| `POST` | `/two-factor/verify-backup-code` |

## Schema contributions

**New tables:**

- `twoFactorConfirmation` — fields: id, userId, expiresAt, createdAt
- `twoFactorBackupCode` — fields: id, userId, codeHash, used, createdAt

**Extends existing tables:**

- `user` adds: twoFactorEnabled, twoFactorSecret

## Usage

```python
from kernia.plugins.two_factor import two_factor
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            two_factor(),
        ],
    )
)
```
