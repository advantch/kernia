# Phone Number

> Module: `kernia.plugins.phone_number`
> Constructor: `PHONE_NUMBER_ERROR_CODES`

phone_number — see reference/packages/better-auth/src/plugins/phone-number/.

Adds `phoneNumber`/`phoneNumberVerified` to the user table and contributes
endpoints for SMS-OTP sign-in, phone verification, and SMS-backed password
reset.

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from kernia.plugins.phone_number import PHONE_NUMBER_ERROR_CODES
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            PHONE_NUMBER_ERROR_CODES(),
        ],
    )
)
```
