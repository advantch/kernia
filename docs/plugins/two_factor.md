# Two Factor

> Module: `better_auth.plugins.two_factor`
> Constructor: `TWO_FACTOR_ERROR_CODES`

two_factor plugin — TOTP + OTP + backup codes + trusted devices.

Port of `reference/packages/better-auth/src/plugins/two-factor/`.

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

Requires `pyotp` (declared under the `two-factor` extra of `better-auth`).

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from better_auth.plugins.two_factor import TWO_FACTOR_ERROR_CODES
from better_auth import BetterAuthOptions
from better_auth.auth import init

auth = init(
    BetterAuthOptions(
        database=...,
        secret=...,
        plugins=[
            TWO_FACTOR_ERROR_CODES(),
        ],
    )
)
```
