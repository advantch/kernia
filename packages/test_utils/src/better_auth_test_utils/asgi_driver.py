"""ASGIDriver — calls an ASGI app like a client without a real server.

Maintains a cookie jar between calls so tests can chain sign-up → get-session.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ASGIResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes

    def json(self) -> Any:
        if not self.body:
            return None
        return json.loads(self.body.decode("utf-8"))

    def set_cookies(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for k, v in self.headers:
            if k.lower() != "set-cookie":
                continue
            name, _, rest = v.partition("=")
            value, _, _attrs = rest.partition(";")
            out[name.strip()] = value
        return out


@dataclass
class ASGIDriver:
    app: Callable[..., Awaitable[None]]
    cookies: dict[str, str] = field(default_factory=dict)

    async def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        headers: Mapping[str, str] | None = None,
        query: str = "",
    ) -> ASGIResponse:
        body_bytes = b""
        req_headers: list[tuple[bytes, bytes]] = []
        for k, v in (headers or {}).items():
            req_headers.append((k.lower().encode("latin-1"), v.encode("latin-1")))
        if json_body is not None:
            body_bytes = json.dumps(json_body).encode("utf-8")
            if not any(k == b"content-type" for k, _ in req_headers):
                req_headers.append((b"content-type", b"application/json"))
        if self.cookies:
            cookie_header = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            req_headers.append((b"cookie", cookie_header.encode("latin-1")))

        scope = {
            "type": "http",
            "method": method,
            "path": path,
            "query_string": query.encode("utf-8"),
            "headers": req_headers,
        }

        sent_body = b""
        more = True

        async def receive() -> dict:
            nonlocal more
            if more:
                more = False
                return {"type": "http.request", "body": body_bytes, "more_body": False}
            return {"type": "http.disconnect"}

        captured: dict[str, Any] = {"status": None, "headers": [], "body": b""}

        async def send(msg: dict) -> None:
            nonlocal sent_body
            if msg["type"] == "http.response.start":
                captured["status"] = msg["status"]
                captured["headers"] = msg.get("headers", [])
            elif msg["type"] == "http.response.body":
                sent_body += msg.get("body") or b""

        await self.app(scope, receive, send)

        captured["body"] = sent_body
        decoded_headers = tuple(
            (k.decode("latin-1"), v.decode("latin-1")) for k, v in captured["headers"]
        )
        response = ASGIResponse(
            status=captured["status"],
            headers=decoded_headers,
            body=sent_body,
        )
        # Update cookie jar
        for name, value in response.set_cookies().items():
            if value:
                self.cookies[name] = value
            elif name in self.cookies:
                del self.cookies[name]
        return response
