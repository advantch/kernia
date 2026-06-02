"""better-auth passkey plugin (WebAuthn).

Standalone workspace package — not bundled with `better-auth` core so the
`webauthn` dependency stays opt-in. Mirrors `reference/packages/passkey/src/`.
"""

from kernia_passkey import webauthn_server
from kernia_passkey.error_codes import PASSKEY_ERROR_CODES
from kernia_passkey.plugin import passkey
from kernia_passkey.types import (
    PasskeyAdvancedOptions,
    PasskeyAuthenticationOptions,
    PasskeyOptions,
    PasskeyRegistrationOptions,
)

__all__ = [
    "PASSKEY_ERROR_CODES",
    "PasskeyAdvancedOptions",
    "PasskeyAuthenticationOptions",
    "PasskeyOptions",
    "PasskeyRegistrationOptions",
    "passkey",
    "webauthn_server",
]
