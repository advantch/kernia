# kernia-sqlalchemy

SQLAlchemy 2.x async database adapter for Kernia. Works with PostgreSQL, MySQL, and SQLite through SQLAlchemy Core.

Part of [Kernia](https://kernia.dev), a framework-agnostic authentication library for Python.

## Installation

    pip install kernia-sqlalchemy

## Usage

The adapter is an async factory: build it, then pass it as `database`.

```python
from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.types.init_options import KerniaOptions
from kernia_sqlalchemy import sqlalchemy_adapter

adapter = await sqlalchemy_adapter(url="postgresql+asyncpg://localhost/app")

auth = init(
    KerniaOptions(
        database=adapter,
        secret="dev-secret",
        plugins=[email_and_password()],
    )
)
```

Pass your own `AsyncEngine` via `engine=`, and set `create_schema=False` to manage the schema with migrations.

## Documentation

Full documentation at [kernia.dev/docs](https://kernia.dev/docs). Source at [github.com/advantch/kernia](https://github.com/advantch/kernia).

## License

MIT
