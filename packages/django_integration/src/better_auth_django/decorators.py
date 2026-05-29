"""View decorators."""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Any

from django.http import HttpRequest, JsonResponse


def require_session(view_func: Callable[..., Any]) -> Callable[..., Any]:
    """Return 401 JSON if ``request.better_auth_session`` is not set.

    Relies on :class:`BetterAuthMiddleware` having already populated the
    attribute. Without the middleware in ``MIDDLEWARE`` the attribute will not
    exist; we treat that as unauthenticated as well (fail-closed).
    """

    @wraps(view_func)
    def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
        session = getattr(request, "better_auth_session", None)
        if session is None:
            return JsonResponse({"error": "UNAUTHORIZED"}, status=401)
        return view_func(request, *args, **kwargs)

    return wrapper
