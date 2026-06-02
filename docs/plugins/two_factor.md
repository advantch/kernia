# Two Factor

> Module: `kernia.plugins.two_factor`
> Constructor: `two_factor`

two_factor plugin — TOTP + OTP + backup codes + trusted devices.

Port of `Better Auth reference: plugins/two-factor/`. Adds two tables
(`twoFactorConfirmation`, `twoFactorBackupCode`) and extends `user` with
`twoFactorEnabled` + `twoFactorSecret`.

Schema:
  * adds a `twoFactor` table (secret, backupCodes, verified, userId) — the
    upstream model.
  * extends `user` with `twoFactorEnabled`.

The challenge state between credential sign-in and the second factor travels
through signed cookies (`better-auth.two_factor`, `better-auth.trust_device`,
`better-auth.dont_remember`) plus rows on the core `verification` table.

Sign-in gating: an after-hook on `/sign-in/email`, `/sign-in/username`, and
`/sign-in/phone-number` inspects the freshly-minted session. When the user has
`twoFactorEnabled`, it deletes that session, clears its cookies, issues a signed
`two_factor` challenge cookie, and returns
`{twoFactorRedirect: True, twoFactorMethods: [...]}` instead of a full session.
A valid trust-device cookie short-circuits the gate (and is rotated).

Options are read from `BetterAuthOptions.advanced["two-factor"]`:

    advanced={
        "two-factor": {
            "otp_options": {"send_otp": async (data, ctx) -> None, ...},
            "skip_verification_on_enable": False,
            "allow_passwordless": False,
            "trust_device_max_age": 30*24*60*60,
            "two_factor_cookie_max_age": 600,
            "issuer": "My App",
            "totp_options": {"digits": 6, "period": 30, "disable": False},
        }
    }

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
