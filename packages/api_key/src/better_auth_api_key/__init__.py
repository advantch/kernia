"""better-auth API key plugin.

Mirrors `reference/packages/api-key/`. Issues argon2-hashed bearer-style API
keys, exposes create/list/revoke/verify endpoints, and registers a global
on-request hook that resolves `Authorization: ApiKey <key>` headers into a
synthetic session attached to the request context.

The plaintext key is returned exactly once on `/api-key/create`; only the hash
and the prefix are persisted.
"""

from better_auth_api_key.plugin import (
    API_KEY_ERROR_CODES,
    ApiKeyOptions,
    api_key,
    generate_api_key,
    parse_api_key,
)

__all__ = [
    "API_KEY_ERROR_CODES",
    "ApiKeyOptions",
    "api_key",
    "generate_api_key",
    "parse_api_key",
]
