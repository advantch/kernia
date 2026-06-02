# Adapters

Kernia adapters provide the database contract used by core and plugin schemas.

## Packages

```bash
pip install kernia-memory-adapter
pip install kernia-sqlalchemy
pip install kernia-mongo
```

## Imports

```python
from kernia_memory_adapter import memory_adapter
from kernia_sqlalchemy import sqlalchemy_adapter
from kernia_mongo import mongo_adapter
```

## Coverage

The adapter conformance suite runs the same create, read, update, delete,
filtering, sorting, pagination, transaction, and relation checks against memory,
SQLAlchemy, and Mongo adapters.
