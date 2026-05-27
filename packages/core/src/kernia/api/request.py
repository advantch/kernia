"""ASGI Request/Response adapter.

The core depends only on a minimal `RequestLike` Protocol (see types/context.py).
This module provides the ASGI implementation used by `Router.mount`. Integration
packages (FastAPI, Starlette) wrap their own request types around the same Protocol.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs


@dataclass
class ASGIRequest:
    """RequestLike implementation backed by an ASGI scope + body bytes.

    Constructed by the router after the receive() callable has been drained. Caches
    the parsed body so handlers can call `json()` and `body()` idempotently.
    """

    method: str
    path: str
    headers: Mapping[str, str]
    query: Mapping[str, str | list[str]]
    cookies: Mapping[str, str]
    _body_bytes: bytes
    _parsed: Any = field(default=None)
    _parsed_done: bool = False

    async def body(self) -> bytes:
        return self._body_bytes

    async def json(self) -> Any:
        if not self._parsed_done:
            self._parsed = json.loads(self._body_bytes.decode("utf-8")) if self._body_bytes else None
            self._parsed_done = True
        return self._parsed


def parse_query_string(qs: bytes) -> dict[str, str | list[str]]:
    raw = parse_qs(qs.decode("utf-8"))
    out: dict[str, str | list[str]] = {}
    for k, v in raw.items():
        out[k] = v[0] if len(v) == 1 else v
    return out


def headers_from_asgi(headers_raw: list[tuple[bytes, bytes]]) -> dict[str, str]:
    return {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in headers_raw}


@dataclass(frozen=True, slots=True)
class JSONResponse:
    """Response envelope returned by router. Set-Cookie headers come from
    `EndpointContext.set_cookies`, response headers from
    `EndpointContext.response_headers`."""

    body: Any
    status: int = 200
    headers: tuple[tuple[str, str], ...] = ()

    def to_bytes(self) -> bytes:
        if self.body is None:
            return b""
        return json.dumps(self.body, default=str).encode("utf-8")


@dataclass(frozen=True, slots=True)
class RedirectResponse:
    """302 redirect envelope produced by handlers (OAuth, magic-link, etc.)."""

    location: str
    status: int = 302
    headers: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class HTMLResponse:
    """HTML response envelope (used by /device landing, debug pages, etc.)."""

    body: str
    status: int = 200
    headers: tuple[tuple[str, str], ...] = ()

    def to_bytes(self) -> bytes:
        return self.body.encode("utf-8")
