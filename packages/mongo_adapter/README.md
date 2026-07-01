# kernia-mongo

MongoDB database adapter for Kernia, built on the async `motor` driver.

Part of [Kernia](https://kernia.dev), a framework-agnostic authentication library for Python.

## Installation

    pip install kernia-mongo

## Usage

The adapter is an async factory: connect it, then pass it as `database`.

```python
from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.types.init_options import KerniaOptions
from kernia_mongo import mongo_adapter

adapter = await mongo_adapter(url="mongodb://localhost:27017", db_name="app")

auth = init(
    KerniaOptions(
        database=adapter,
        secret="dev-secret",
        plugins=[email_and_password()],
    )
)
```

## Documentation

Full documentation at [kernia.dev/docs](https://kernia.dev/docs). Source at [github.com/advantch/kernia](https://github.com/advantch/kernia).

## License

MIT
