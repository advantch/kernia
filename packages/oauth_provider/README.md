# kernia-oauth-provider

OAuth 2.0 and OpenID Connect provider (issuer side) plugin for Kernia. Registers clients, authorizes users, and exchanges authorization codes for access, refresh, and id tokens.

Part of [Kernia](https://kernia.dev), a framework-agnostic authentication library for Python.

## Installation

    pip install kernia-oauth-provider

## Usage

```python
from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_oauth_provider import OAuthProviderOptions, oauth_provider

auth = init(
    KerniaOptions(
        database=memory_adapter(),
        secret="dev-secret",
        plugins=[
            email_and_password(),
            oauth_provider(OAuthProviderOptions(issuer="https://auth.example.com")),
        ],
    )
)
```

Access tokens default to self-contained EdDSA JWTs; set `jwt_access_token=False` for opaque reference tokens.

## Documentation

Full documentation at [kernia.dev/docs](https://kernia.dev/docs). Source at [github.com/advantch/kernia](https://github.com/advantch/kernia).

## License

MIT
