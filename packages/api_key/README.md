# kernia-api-key

API key plugin for Kernia. Issues SHA-256-hashed API keys and exposes create, verify, get, update, delete, and list endpoints, with optional per-key rate limiting and permissions.

Part of [Kernia](https://kernia.dev), a framework-agnostic authentication library for Python.

## Installation

    pip install kernia-api-key

## Usage

```python
from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.types.init_options import KerniaOptions
from kernia_api_key import api_key
from kernia_memory_adapter import memory_adapter

auth = init(
    KerniaOptions(
        database=memory_adapter(),
        secret="dev-secret",
        plugins=[email_and_password(), api_key()],
    )
)
```

The plaintext key is returned exactly once on `/api-key/create`; only its hash and starting characters are persisted.

## Documentation

Full documentation at [kernia.dev/docs](https://kernia.dev/docs). Source at [github.com/advantch/kernia](https://github.com/advantch/kernia).

## License

MIT
