# kernia-django

Django integration for Kernia. Mounts the auth router, populates `request.kernia_session` and `request.kernia_user`, and provides a view decorator for protected views.

Part of [Kernia](https://kernia.dev), a framework-agnostic authentication library for Python.

## Installation

    pip install kernia-django

## Usage

Add the app to `INSTALLED_APPS` and the middleware, then splice the auth routes into `urls.py`:

```python
# urls.py
from django.urls import path
from kernia_django import setup
from myproject.auth import auth   # your init(KerniaOptions(...)) instance

urlpatterns = [
    *setup(auth, url_prefix="/api/auth"),
]
```

```python
# views.py
from kernia_django import require_session

@require_session
def me(request):
    return JsonResponse({"user_id": request.kernia_user["id"]})
```

Django is sync-by-default; the bridge uses `asgiref.sync.async_to_sync` to call the async core.

## Documentation

Full documentation at [kernia.dev/docs](https://kernia.dev/docs). Source at [github.com/advantch/kernia](https://github.com/advantch/kernia).

## License

MIT
