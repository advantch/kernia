# kernia-starlette

Starlette integration for Kernia. Mounts the auth router at your base path and provides request-aware session helpers for downstream routes.

Part of [Kernia](https://kernia.dev), a framework-agnostic authentication library for Python.

## Installation

    pip install kernia-starlette

## Usage

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from kernia_starlette import mount_kernia, require_session

app = Starlette()
mount_kernia(app, auth)  # serves /api/auth/*, using your init(KerniaOptions(...)) instance

async def me(request):
    session = await require_session(request)
    return JSONResponse({"user_id": session.user_id})
```

`get_session` is also available and returns `None` when there is no session.

## Documentation

Full documentation at [kernia.dev/docs](https://kernia.dev/docs). Source at [github.com/advantch/kernia](https://github.com/advantch/kernia).

## License

MIT
