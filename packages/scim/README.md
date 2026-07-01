# kernia-scim

SCIM 2.0 provisioning plugin for Kernia. Exposes the standard SCIM 2.0 surface under `/scim/v2/`, authenticated by a per-provider bearer token, plus org-scoped provider and token management endpoints.

Part of [Kernia](https://kernia.dev), a framework-agnostic authentication library for Python.

## Installation

    pip install kernia-scim

## Usage

```python
from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_scim import scim

auth = init(
    KerniaOptions(
        database=memory_adapter(),
        secret="dev-secret",
        plugins=[email_and_password(), scim()],
    )
)
```

Pass `scim(SCIMOptions(...))` to configure provider ownership, required roles, and token storage.

## Documentation

Full documentation at [kernia.dev/docs](https://kernia.dev/docs). Source at [github.com/advantch/kernia](https://github.com/advantch/kernia).

## License

MIT
