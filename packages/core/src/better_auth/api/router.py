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
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
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
    """In-memory route table for the auth surface.

    Static routes (no `:param` segments) are dispatched via O(1) dict lookup.
    Dynamic routes (e.g. `/callback/:provider`) are stored separately and matched
    by template; captured params are returned alongside the endpoint.
    """

    auth: AuthContext
    _endpoints: dict[tuple[str, str], AuthEndpoint] = field(default_factory=dict)
    _dynamic: list[tuple[str, list[str], AuthEndpoint]] = field(default_factory=list)

    def register(self, endpoints: Iterable[AuthEndpoint]) -> None:
        for ep in endpoints:
            if ":" in ep.path:
                parts = ep.path.strip("/").split("/")
                self._dynamic.append((ep.options.method, parts, ep))
                continue
            key = (ep.options.method, ep.path)
            if key in self._endpoints:
                existing = self._endpoints[key]
                raise ValueError(
                    f"Endpoint collision at {ep.options.method} {ep.path}: "
                    f"{existing.owner!r} vs {ep.owner!r}"
                )
            self._endpoints[key] = ep

    def match(
        self, method: str, path: str
    ) -> tuple[AuthEndpoint, dict[str, str]] | None:
        """Resolve a (method, path) → (endpoint, path_params).

        Static routes hit the O(1) dict; dynamic routes are matched by template.
        """
        ep = self._endpoints.get((method, path))
        if ep is not None:
            return ep, {}
        path_parts = path.strip("/").split("/")
        for ep_method, parts, dyn_ep in self._dynamic:
            if ep_method != method or len(parts) != len(path_parts):
                continue
            params: dict[str, str] = {}
            ok = True
            for tmpl, actual in zip(parts, path_parts, strict=False):
                if tmpl.startswith(":"):
                    params[tmpl[1:]] = actual
                elif tmpl != actual:
                    ok = False
                    break
            if ok:
                return dyn_ep, params
        return None

    def lookup(self, method: str, path: str) -> AuthEndpoint | None:
        """Legacy convenience: return just the endpoint (no path params)."""
        result = self.match(method, path)
        return result[0] if result is not None else None

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

    # Ensure plugin `init` callbacks have run. Idempotent: a no-op when `init()`
    # already initialized eagerly (no running loop at construction); the real
    # work happens here on the first request when the handle was built inside an
    # async framework's startup.
    await router.auth.ensure_initialized()

    matched = router.match(method, path)
    if matched is None:
        await _send_json(send, JSONResponse({"code": "NOT_FOUND"}, status=404))
        return
    endpoint, path_params = matched

    ctx = EndpointContext(request=request, auth=router.auth, path_params=path_params)

    try:
        # Trusted-origins / CSRF check on state-changing requests.
        from better_auth.auth.trusted_origins import is_state_changing, is_trusted

        if is_state_changing(method) and not router.auth.options.advanced.get(
            "disable_csrf_check", False
        ):
            if not is_trusted(
                origin=headers.get("origin"),
                referer=headers.get("referer"),
                base_url=router.auth.base_url,
                trusted_origins=router.auth.options.trusted_origins,
            ):
                raise APIError(403, "FORBIDDEN", message="Origin is not trusted.")

        # Resolve session (Phase 2b will fill the real lookup; for now: cookie-only)
        await _attach_session(ctx)

        # Rate-limit. Runs before bodies are decoded so abusive clients can't burn
        # CPU just by sending huge payloads. See `auth.rate_limit`.
        from better_auth.auth.rate_limit import enforce_rate_limit

        await enforce_rate_limit(ctx, router.auth.rate_limit_store)

        # Decode body
        if endpoint.options.body is not None and body_bytes:
            raw = await request.json()
            ctx = replace(ctx, body=_construct_body(endpoint.options.body, raw))

        # on_request hooks (may attach a session — e.g. the bearer plugin).
        for plugin in router.auth.plugins:
            hook = getattr(plugin, "on_request", None)
            if hook is not None:
                await hook(ctx)

        # Enforce requires_session AFTER on_request so plugins can supply sessions.
        if endpoint.options.requires_session and ctx.session is None:
            raise APIError(401, "UNAUTHORIZED")

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

        if isinstance(result, (HTMLResponse, RedirectResponse)):
            response = result
        else:
            response = JSONResponse(body=result, status=200)
    except APIError as e:
        err_body = e.to_dict()
        # Run on_response hooks for error envelopes too — this lets i18n
        # translate localized messages on the error path.
        for plugin in router.auth.plugins:
            hook = getattr(plugin, "on_response", None)
            if hook is not None:
                await hook(ctx, err_body)
        response = JSONResponse(body=err_body, status=e.status)
    except Exception as e:  # pragma: no cover — last-resort envelope
        response = JSONResponse(
            body={"code": "INTERNAL", "message": str(e)},
            status=500,
        )

    if isinstance(response, HTMLResponse):
        await _send_html(send, response, set_cookies=ctx.set_cookies, extra_headers=ctx.response_headers)
    elif isinstance(response, RedirectResponse):
        await _send_redirect(send, response, set_cookies=ctx.set_cookies, extra_headers=ctx.response_headers)
    else:
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
    # Filter unknown kwargs for dataclasses (lets plugins like `additional_fields`
    # extend the request body without breaking the strict dataclass constructor).
    import dataclasses as _dc

    filtered = raw
    if _dc.is_dataclass(body_type):
        known = {f.name for f in _dc.fields(body_type)}
        filtered = {k: v for k, v in raw.items() if k in known}
    try:
        return body_type(**filtered)
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
    provider = ctx.auth.plugin_state.get("session_provider")
    if provider is not None and hasattr(provider, "get_session"):
        row = await provider.get_session(token=token)
    else:
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


async def _send_html(
    send: Callable,
    response: HTMLResponse,
    *,
    set_cookies: list[tuple[str, str, Any]] | None = None,
    extra_headers: dict[str, str] | None = None,
) -> None:
    headers: list[tuple[bytes, bytes]] = [
        (b"content-type", b"text/html; charset=utf-8"),
    ]
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
    await send({"type": "http.response.body", "body": body_bytes})


async def _send_redirect(
    send: Callable,
    response: RedirectResponse,
    *,
    set_cookies: list[tuple[str, str, Any]] | None = None,
    extra_headers: dict[str, str] | None = None,
) -> None:
    headers: list[tuple[bytes, bytes]] = [
        (b"location", response.location.encode("latin-1")),
    ]
    for k, v in (extra_headers or {}).items():
        headers.append((k.encode("latin-1"), v.encode("latin-1")))
    for name, value, attrs in set_cookies or ():
        headers.append((b"set-cookie", render_set_cookie(name, value, attrs).encode("latin-1")))
    await send({
        "type": "http.response.start",
        "status": response.status,
        "headers": headers,
    })
    await send({"type": "http.response.body", "body": b""})


__all__ = ["Router"]
