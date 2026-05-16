"""better-auth passkey plugin (WebAuthn).

Standalone workspace package — not bundled with `better-auth` core so the
`webauthn` dependency stays opt-in. Mirrors `reference/packages/passkey/src/`.
"""

from better_auth_passkey.plugin import PASSKEY_ERROR_CODES, passkey

__all__ = ["PASSKEY_ERROR_CODES", "passkey"]
