"""phone_number — see reference/packages/better-auth/src/plugins/phone-number/.

Adds `phoneNumber`/`phoneNumberVerified` to the user table and contributes
endpoints for SMS-OTP sign-in, phone verification, and SMS-backed password
reset.
"""

from kernia.plugins.phone_number.plugin import (
    PHONE_NUMBER_ERROR_CODES,
    phone_number,
)
from kernia.plugins.phone_number.routes import generate_otp
from kernia.plugins.phone_number.schema import (
    PHONE_NUMBER_USER_FIELDS,
    phone_number_schema,
)

__all__ = [
    "PHONE_NUMBER_ERROR_CODES",
    "PHONE_NUMBER_USER_FIELDS",
    "generate_otp",
    "phone_number",
    "phone_number_schema",
]
