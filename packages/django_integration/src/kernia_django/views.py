"""Django view that bridges to the Kernia ASGI router.

Approach: Django's request/response objects are a different shape from ASGI, so
the bridge converts a Django ``HttpRequest`` into an ASGI ``scope`` + receive
queue, drives the inner router, and reassembles the response body / headers
into a Django ``HttpResponse``.

The bridge is sync at the Django edge (``View.dispatch`` is sync by default)
and async on the inside. We use ``asgiref.sync.async_to_sync`` to cross the
boundary. Every Kernia request therefore costs one thread hop. This is a
known and intentional tradeoff: Django remains sync-friendly without forcing
ASGI workers on the user.
"""

from __future__ import annotations

from http.cookies import SimpleCookie
from typing import Any, ClassVar

from asgiref.sync import async_to_sync
from django.http import HttpRequest, HttpResponse
from django.urls import path
from django.views import View
from kernia.auth import Kernia
from kernia.integrations.session import strip_base_path


def django_request_to_scope(
    request: HttpRequest,
    *,
    base_path: str = "",
) -> dict[str, Any]:
    """Translate a Django HttpRequest into an ASGI HTTP scope.

    ``base_path`` is the mount prefix the auth router was registered under; we
    strip it from ``path`` so the inner router sees canonical relative paths
    (e.g. ``/sign-in/email``). Set to ``""`` to leave the path alone.
    """
    full_path = request.path
    # Build a minimal ASGI HTTP scope. We don't try to be exhaustive — only the
    # fields Kernia actually reads (path, method, headers, query_string,
    # raw_path, scheme, client).
    headers: list[tuple[bytes, bytes]] = []
    for key, value in request.META.items():
        if key.startswith("HTTP_"):
            name = key[5:].replace("_", "-").lower().encode("latin-1")
            headers.append((name, str(value).encode("latin-1")))
        elif key in ("CONTENT_TYPE", "CONTENT_LENGTH") and value:
            name = key.replace("_", "-").lower().encode("latin-1")
            headers.append((name, str(value).encode("latin-1")))

    # Django's request.GET is already parsed; the router doesn't need it as a
    # mapping, but does inspect raw query_string from scope.
    query_string = request.META.get("QUERY_STRING", "")
    if isinstance(query_string, str):
        query_string = query_string.encode("latin-1")

    scope: dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": request.method or "GET",
        "scheme": request.scheme or "http",
        "path": full_path,
        "raw_path": full_path.encode("latin-1"),
        "query_string": query_string,
        "root_path": "",
        "headers": headers,
        "server": (request.get_host().split(":")[0], request.get_port() or 80),
        "client": (request.META.get("REMOTE_ADDR", "") or "", 0),
    }
    if base_path:
        scope = strip_base_path(scope, base_path)
    return scope


async def _drive(
    inner: Any,
    scope: dict[str, Any],
    body: bytes,
) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
    """Drive a single HTTP exchange against an ASGI app, return the response."""
    sent_body = bytearray()
    status: int = 500
    headers: list[tuple[bytes, bytes]] = []

    request_sent = False

    async def receive() -> dict[str, Any]:
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        # If the app asks for more we report disconnect to avoid hanging.
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        nonlocal status, headers
        if message["type"] == "http.response.start":
            status = int(message["status"])
            headers = list(message.get("headers", []))
        elif message["type"] == "http.response.body":
            chunk = message.get("body", b"") or b""
            sent_body.extend(chunk)

    await inner(scope, receive, send)
    return status, headers, bytes(sent_body)


class KerniaView(View):
    """Class-based view that funnels every method onto the auth router.

    Usage::

        KerniaView.as_view(auth=my_auth, base_path="/api/auth")
    """

    auth: Kernia | None = None
    base_path: str = "/api/auth"

    http_method_names: ClassVar[list[str]] = [
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
    ]

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if self.auth is None:
            raise RuntimeError("KerniaView requires an `auth` kwarg passed via .as_view()")
        # ``rest`` is captured by the URL pattern; rebuild the full path because
        # the inner router decides routing from scope["path"].
        rest = kwargs.get("rest", "")
        full_path = self.base_path.rstrip("/") + "/" + rest if rest else self.base_path
        # Rewrite the Django request's path so the scope mirrors what would
        # have been hit if Django were ASGI-native.
        request.path = full_path
        request.path_info = full_path

        inner = self.auth.router.mount()
        scope = django_request_to_scope(request, base_path=self.base_path.rstrip("/"))
        body = request.body or b""

        status, headers, response_body = async_to_sync(_drive)(inner, scope, body)

        # Build Django response. Pull Content-Type for HttpResponse's ctor;
        # parse Set-Cookie lines into response.cookies so Django emits each
        # cookie on its own header (joining Set-Cookie with commas is broken
        # for cookies whose attributes contain commas, e.g. ``Expires``).
        content_type = None
        cookie_lines: list[str] = []
        remaining: list[tuple[bytes, bytes]] = []
        for k, v in headers:
            name = k.decode("latin-1")
            value = v.decode("latin-1")
            if name.lower() == "content-type" and content_type is None:
                content_type = value
            elif name.lower() == "set-cookie":
                cookie_lines.append(value)
            else:
                remaining.append((k, v))

        resp = HttpResponse(
            response_body,
            status=status,
            content_type=content_type,
        )
        for k, v in remaining:
            resp.headers[k.decode("latin-1")] = v.decode("latin-1")
        for line in cookie_lines:
            jar: SimpleCookie = SimpleCookie()
            jar.load(line)
            for morsel in jar.values():
                resp.cookies[morsel.key] = morsel.value
                for attr in (
                    "expires",
                    "path",
                    "domain",
                    "secure",
                    "httponly",
                    "samesite",
                    "max-age",
                ):
                    if morsel[attr]:
                        resp.cookies[morsel.key][attr] = morsel[attr]
        return resp


def setup(
    auth: Kernia,
    url_prefix: str = "/api/auth",
) -> list[Any]:
    """Return a list of urlpatterns ready to splice into ``urls.py``.

    The patterns use a catch-all ``<path:rest>`` so every sub-route under the
    prefix lands on ``KerniaView``.
    """
    prefix = url_prefix.strip("/")
    return [
        path(
            f"{prefix}/<path:rest>",
            KerniaView.as_view(auth=auth, base_path="/" + prefix),
        ),
        path(
            f"{prefix}",
            KerniaView.as_view(auth=auth, base_path="/" + prefix),
        ),
    ]
