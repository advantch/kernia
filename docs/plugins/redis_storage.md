# Redis storage

Package: `kernia-redis-storage`

```bash
pip install kernia-redis-storage
```

```python
from kernia_redis_storage import RedisStorage

storage = RedisStorage.from_url("redis://localhost:6379/0")
```

## Purpose

Redis storage backs rate limiting and other short-lived server state that should
be shared across processes.

## Coverage

Covered by storage tests with an in-memory fallback and Redis-gated integration
paths.
