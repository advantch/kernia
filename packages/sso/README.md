# kernia-sso

SAML 2.0 and OpenID Connect SSO plugin for Kernia. Adds provider CRUD, domain verification, an OIDC authorization-code flow, and a SAML service provider (metadata, AuthnRequest, ACS, and SLO).

Part of [Kernia](https://kernia.dev), a framework-agnostic authentication library for Python.

## Installation

    pip install kernia-sso

## Usage

```python
from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_sso import sso

auth = init(
    KerniaOptions(
        database=memory_adapter(),
        secret="dev-secret",
        plugins=[email_and_password(), sso()],
    )
)
```

All routes are served under `/sso/...`.

## Documentation

Full documentation at [kernia.dev/docs](https://kernia.dev/docs). Source at [github.com/advantch/kernia](https://github.com/advantch/kernia).

## License

MIT
