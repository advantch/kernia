# Two Factor

> Module: `kernia.plugins.two_factor`
> Constructor: `TWO_FACTOR_ERROR_CODES`

two_factor plugin — TOTP + backup codes.

Port of `reference/packages/better-auth/src/plugins/two-factor/`. Adds two tables
(`twoFactorConfirmation`, `twoFactorBackupCode`) and extends `user` with
`twoFactorEnabled` + `twoFactorSecret`.

Hooks into `/sign-in/email`: if the user has 2FA enabled, the endpoint normally
returns a session; the after-hook intercepts that, deletes the just-created
session, and returns `{requiresTwoFactor: True, confirmationId: ...}` instead.
The follow-up `/two-factor/verify-totp` (or `/two-factor/verify-backup-code`)
exchanges the confirmation id for a real session.

Requires `pyotp` (declared under the `two-factor` extra of `kernia`).

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from kernia.plugins.two_factor import TWO_FACTOR_ERROR_CODES
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            TWO_FACTOR_ERROR_CODES(),
        ],
    )
)
```
