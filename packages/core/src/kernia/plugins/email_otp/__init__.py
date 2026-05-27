"""email_otp — see reference/packages/better-auth/src/plugins/email-otp/.

Six-digit OTPs delivered out-of-band via a caller-provided `send_otp` callable.
Supports sign-in, email verification, password reset, and email change flows.
Tokens are stored on the core `verification` table keyed by
`email-otp:<purpose>:<email>`.
"""

from kernia.plugins.email_otp.plugin import (
    EMAIL_OTP_ERROR_CODES,
    email_otp,
)
from kernia.plugins.email_otp.routes import generate_otp

__all__ = ["EMAIL_OTP_ERROR_CODES", "email_otp", "generate_otp"]
