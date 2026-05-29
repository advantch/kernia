"""better-auth API key plugin.

Behavioral-parity port of ``reference/packages/api-key``. Issues SHA-256-hashed
API keys and exposes create/verify/get/update/delete/list/delete-all-expired
endpoints. Optionally (``enable_session_for_api_keys``) resolves a configured
API-key header into a session for every request.

The plaintext key is returned exactly once on ``/api-key/create``; only the hash
and the starting characters are persisted.
"""

from better_auth_api_key.plugin import (
    API_KEY_ERROR_CODES,
    API_KEY_TABLE_NAME,
    ApiKeyConfigurationOptions,
    ApiKeyOptions,
    KeyExpirationOptions,
    PermissionsOptions,
    RateLimitOptions,
    StartingCharactersConfig,
    api_key,
    default_key_generator,
    default_key_hasher,
    generate_api_key,
    parse_api_key,
    validate_api_key,
)

__all__ = [
    "API_KEY_ERROR_CODES",
    "API_KEY_TABLE_NAME",
    "ApiKeyConfigurationOptions",
    "ApiKeyOptions",
    "KeyExpirationOptions",
    "PermissionsOptions",
    "RateLimitOptions",
    "StartingCharactersConfig",
    "api_key",
    "default_key_generator",
    "default_key_hasher",
    "generate_api_key",
    "parse_api_key",
    "validate_api_key",
]
