"""ASGI router for auth endpoints.

Mirrors the dispatch logic in `reference/packages/better-auth/src/api/index.ts`.

Lookups are O(1) on `(method, path)`. The dispatch lifecycle is:

  1. Parse ASGI scope/body → RequestLike
  2. Resolve session from cookies (if any) → EndpointContext.session
  3. If endpoint.requires_session and no session → 401
  4. Run plugin.on_request hooks (global, per plugin)
  5. Run plugin before-hooks (matched by path)
  6. Decode body with endpoint.options.body type
  7. Invoke handler
  8. Run plugin after-hooks
  9. Run plugin.on_response hooks
 10. Render JSONResponse with Set-Cookie headers
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field, replace
from typing import Any, cast

from better_auth.api.request import (
    ASGIRequest,
    JSONResponse,
    headers_from_asgi,
    parse_query_string,
)
from better_auth.cookies import (
    parse_cookie_header,
    render_set_cookie,
)
from better_auth.error import APIError
from better_auth.types.context import AuthContext, EndpointContext
from better_auth.types.endpoint import AuthEndpoint


@dataclass
class Router:
    """In-memory route table for the auth surface."""

    auth: AuthContext
    _endpoints: dict[tuple[str, str], AuthEndpoint] = field(default_factory=dict)

    def register(self, endpoints: Iterable[AuthEndpoint]) -> None:
        for ep in endpoints:
            key = (ep.options.method, ep.path)
            if key in self._endpoints:
                existing = self._endpoints[key]
                raise ValueError(
                    f"Endpoint collision at {ep.options.method} {ep.path}: "
                    f"{existing.owner!r} vs {ep.owner!r}"
                )
            self._endpoints[key] = ep

    def lookup(self, method: str, path: str) -> AuthEndpoint | None:
        return self._endpoints.get((method, path))

    def mount(self) -> Callable[..., Awaitable[None]]:
        """Return an ASGI 3 callable mounted at `auth.options.base_path`.

        The caller is responsible for trimming the mount prefix from the incoming
        path. This callable expects already-trimmed paths (i.e. `/sign-in/email`,
        not `/api/auth/sign-in/email`).
        """

        async def app(scope: dict, receive: Callable, send: Callable) -> None:
            if scope["type"] != "http":
                # Lifespan + websocket are forwarded as no-ops here.
                if scope["type"] == "lifespan":
                    await _drain_lifespan(receive, send)
                return

            await _handle_http(self, scope, receive, send)

        return app


# --------------------------------------------------------------------------- helpers


async def _drain_lifespan(receive: Callable, send: Callable) -> None:
    while True:
        msg = await receive()
        if msg["type"] == "lifespan.startup":
            await send({"type": "lifespan.startup.complete"})
        elif msg["type"] == "lifespan.shutdown":
            await send({"type": "lifespan.shutdown.complete"})
            return


async def _handle_http(
    router: Router,
    scope: dict,
    receive: Callable,
    send: Callable,
) -> None:
    headers = headers_from_asgi(scope.get("headers", []))
    cookies = parse_cookie_header(headers.get("cookie", ""))
    query = parse_query_string(scope.get("query_string", b""))
    body_bytes = await _drain_body(receive)
    path = scope["path"]
    method = scope["method"]

    request = ASGIRequest(
        method=method,
        path=path,
        headers=headers,
        query=query,
        cookies=cookies,
        _body_bytes=body_bytes,
    )

    endpoint = router.lookup(method, path)
    if endpoint is None:
        await _send_json(send, JSONResponse({"code": "NOT_FOUND"}, status=404))
        return

    ctx = EndpointContext(request=request, auth=router.auth)

    try:
        # Resolve session (Phase 2b will fill the real lookup; for now: cookie-only)
        await _attach_session(ctx)
        if endpoint.options.requires_session and ctx.session is None:
            raise APIError(401, "UNAUTHORIZED")

        # Decode body
        if endpoint.options.body is not None and body_bytes:
            raw = await request.json()
            ctx = replace(ctx, body=_construct_body(endpoint.options.body, raw))

        # on_request hooks
        for plugin in router.auth.plugins:
            hook = getattr(plugin, "on_request", None)
            if hook is not None:
                await hook(ctx)

        # before hooks (matched by path)
        for plugin in router.auth.plugins:
            hooks = getattr(plugin, "hooks", None)
            if hooks is None:
                continue
            for before in hooks.before or ():
                if _hook_matches(before.match, ctx):
                    await before.handler(ctx)

        result = await endpoint.handler(ctx)

        # after hooks
        for plugin in router.auth.plugins:
            hooks = getattr(plugin, "hooks", None)
            if hooks is None:
                continue
            for after in hooks.after or ():
                if _hook_matches(after.match, ctx):
                    new_result = await after.handler(ctx, result)
                    if new_result is not None:
                        result = new_result

        # on_response hooks
        for plugin in router.auth.plugins:
            hook = getattr(plugin, "on_response", None)
            if hook is not None:
                await hook(ctx, result)

        response = JSONResponse(body=result, status=200)
    except APIError as e:
        response = JSONResponse(body=e.to_dict(), status=e.status)
    except Exception as e:  # pragma: no cover — last-resort envelope
        response = JSONResponse(
            body={"code": "INTERNAL", "message": str(e)},
            status=500,
        )

    await _send_json(send, response, set_cookies=ctx.set_cookies, extra_headers=ctx.response_headers)


def _construct_body(body_type: type, raw: Any) -> Any:
    """Construct a body model from a parsed JSON payload.

    Phase-1 dataclass models accept kwargs from a dict; Pydantic v2 models accept
    `.model_validate`. We try both so plugins can choose either.
    """
    if hasattr(body_type, "model_validate"):
        return cast(Any, body_type).model_validate(raw)
    if not isinstance(raw, dict):
        raise APIError(400, "INVALID_REQUEST", message="Body must be a JSON object")
    try:
        return body_type(**raw)
    except TypeError as e:
        raise APIError(400, "INVALID_REQUEST", message=str(e)) from None


def _hook_matches(matcher: Any, ctx: EndpointContext) -> bool:
    if callable(matcher):
        return bool(matcher(ctx))
    if isinstance(matcher, str):
        if matcher.endswith("/*"):
            return ctx.request.path.startswith(matcher[:-2])
        return ctx.request.path == matcher
    return False


async def _attach_session(ctx: EndpointContext) -> None:
    """Resolve a session from the session_token cookie. Phase 2b expands this."""
    from better_auth.cookies import verify
    from better_auth.types.adapter import Where
    from better_auth.types.context import Session

    cookie = ctx.request.cookies.get("better-auth.session_token")
    if not cookie:
        return
    token = verify(cookie, secret=ctx.auth.secret)
    if not token:
        return
    row = await ctx.auth.adapter.find_one(
        model="session",
        where=(Where(field="token", value=token),),
    )
    if not row:
        return
    ctx.session = Session(
        id=row["id"],
        user_id=row["userId"],
        expires_at=int(row["expiresAt"]),
        token=row["token"],
        ip_address=row.get("ipAddress"),
        user_agent=row.get("userAgent"),
    )


async def _drain_body(receive: Callable) -> bytes:
    chunks: list[bytes] = []
    more = True
    while more:
        msg = await receive()
        if msg["type"] == "http.request":
            chunks.append(msg.get("body") or b"")
            more = msg.get("more_body", False)
        elif msg["type"] == "http.disconnect":
            break
    return b"".join(chunks)


async def _send_json(
    send: Callable,
    response: JSONResponse,
    *,
    set_cookies: list[tuple[str, str, Any]] | None = None,
    extra_headers: dict[str, str] | None = None,
) -> None:
    headers: list[tuple[bytes, bytes]] = [(b"content-type", b"application/json")]
    for k, v in response.headers:
        headers.append((k.encode("latin-1"), v.encode("latin-1")))
    for k, v in (extra_headers or {}).items():
        headers.append((k.encode("latin-1"), v.encode("latin-1")))
    for name, value, attrs in set_cookies or ():
        headers.append((b"set-cookie", render_set_cookie(name, value, attrs).encode("latin-1")))

    body_bytes = response.to_bytes()
    await send({
        "type": "http.response.start",
        "status": response.status,
        "headers": headers,
    })
    await send({
        "type": "http.response.body",
        "body": body_bytes,
    })


__all__ = ["Router"]
