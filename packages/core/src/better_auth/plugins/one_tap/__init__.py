"""Google One Tap plugin.

Mirrors `reference/packages/better-auth/src/plugins/one-tap/`. The browser
obtains an id_token from Google's One Tap library and POSTs it here; we verify
it via the existing `better_auth.oauth2.verify_id_token` against Google's JWKS
and resolve a user via `handle_oauth_user_info`.

Endpoint: POST /one-tap/verify
"""

from better_auth.plugins.one_tap.plugin import OneTapOptions, one_tap

__all__ = ["one_tap", "OneTapOptions"]
