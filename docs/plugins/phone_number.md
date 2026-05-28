# Phone Number

> Module: `kernia.plugins.phone_number`
> Constructor: `phone_number`

phone_number — see Better Auth reference: plugins/phone-number/.

Adds `phoneNumber`/`phoneNumberVerified` to the user table and contributes
endpoints for SMS-OTP sign-in, phone verification, and SMS-backed password
reset.

## Endpoints

| Method | Path |
| --- | --- |
| `POST` | `/sign-in/phone-number` |
| `POST` | `/phone-number/send-otp` |
| `POST` | `/phone-number/verify` |
| `POST` | `/phone-number/request-password-reset` |
| `POST` | `/phone-number/reset-password` |

## Schema contributions


**Extends existing tables:**

- `user` adds: phoneNumber, phoneNumberVerified

## Usage

```python
from kernia.plugins.phone_number import phone_number
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            phone_number(),
        ],
    )
)
```
