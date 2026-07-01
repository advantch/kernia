# kernia-fastapi

FastAPI integration for Kernia. Mounts the auth router at your base path and provides session dependencies for downstream routes.

Part of [Kernia](https://kernia.dev), a framework-agnostic authentication library for Python.

## Installation

    pip install kernia-fastapi

## Usage

```python
from fastapi import Depends, FastAPI
from kernia_fastapi import get_session, mount_kernia, require_session

app = FastAPI()
mount_kernia(app, auth)  # serves /api/auth/*, using your init(KerniaOptions(...)) instance

@app.get("/me")
async def me(session=Depends(require_session)):
    return {"user_id": session.user_id}

@app.get("/whoami")
async def whoami(session=Depends(get_session)):
    return {"signed_in": session is not None}
```

`require_session` returns 401 when there is no session; `get_session` returns `None`.

## Documentation

Full documentation at [kernia.dev/docs](https://kernia.dev/docs). Source at [github.com/advantch/kernia](https://github.com/advantch/kernia).

## License

MIT
