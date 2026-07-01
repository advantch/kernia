# kernia-memory-adapter

In-memory database adapter for Kernia. Intended for tests and local development; state is not persisted.

Part of [Kernia](https://kernia.dev), a framework-agnostic authentication library for Python.

## Installation

    pip install kernia-memory-adapter

## Usage

```python
from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter

auth = init(
    KerniaOptions(
        database=memory_adapter(),
        secret="dev-secret",
        plugins=[email_and_password()],
    )
)
```

## Documentation

Full documentation at [kernia.dev/docs](https://kernia.dev/docs). Source at [github.com/advantch/kernia](https://github.com/advantch/kernia).

## License

MIT
