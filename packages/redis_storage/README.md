# kernia-redis-storage

Redis-backed secondary storage for Kernia. Used for caching, rate limiting, and distributed coordination across plugins.

Part of [Kernia](https://kernia.dev), a framework-agnostic authentication library for Python.

## Installation

    pip install kernia-redis-storage

## Usage

The storage is an async factory: build it, then pass it as `secondary_storage`.

```python
from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_redis_storage import redis_storage

storage = await redis_storage(url="redis://localhost:6379")

auth = init(
    KerniaOptions(
        database=memory_adapter(),
        secret="dev-secret",
        secondary_storage=storage,
        plugins=[email_and_password()],
    )
)
```

## Documentation

Full documentation at [kernia.dev/docs](https://kernia.dev/docs). Source at [github.com/advantch/kernia](https://github.com/advantch/kernia).

## License

MIT
