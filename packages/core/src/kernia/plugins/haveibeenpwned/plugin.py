"""Have-I-Been-Pwned plugin construction + range-API client.

The hook runs `before` on a configurable set of password-bearing endpoints
(default: `/sign-up/email`, `/reset-password`). The candidate password is
pulled from the parsed body (`body.password`), SHA-1 hashed (uppercase hex),
and looked up via the k-anonymity range API.

Results are cached for 6h in `AuthContext.secondary_storage` (if available)
to keep repeated calls cheap.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

import httpx

from kernia.error import APIError
from kernia.types.context import EndpointContext
from kernia.types.hooks import BeforeHook, PluginHooks
from kernia.types.plugin import KerniaPlugin

HIBP_ERROR_CODES: Mapping[str, str] = {
    "PASSWORD_COMPROMISED": (
        "This password has appeared in known data breaches. Choose a stronger one."
    ),
}


_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
_CACHE_TTL = 6 * 60 * 60  # 6 hours
_DEFAULT_PATHS: tuple[str, ...] = ("/sign-up/email", "/reset-password")


async def _fetch_range(
    prefix: str,
    *,
    secondary_storage: object | None,
    transport: httpx.AsyncBaseTransport | None,
) -> str:
    """Fetch the prefix bucket — k-anonymity API returns `suffix:count` lines."""
    cache_key = f"hibp:{prefix}"
    if secondary_storage is not None:
        cached = await secondary_storage.get(cache_key)  # type: ignore[attr-defined]
        if cached is not None:
            return cached
    async with httpx.AsyncClient(
        transport=transport, timeout=httpx.Timeout(10.0)
    ) as client:
        resp = await client.get(
            _RANGE_URL.format(prefix=prefix),
            headers={"User-Agent": "kernia", "Add-Padding": "true"},
        )
        if resp.status_code != 200:
            raise APIError(
                500,
                "INTERNAL",
                message=f"HIBP lookup failed ({resp.status_code})",
            )
        text = resp.text
    if secondary_storage is not None:
        try:
            await secondary_storage.set(cache_key, text, ttl=_CACHE_TTL)  # type: ignore[attr-defined]
        except Exception:
            pass
    return text


def _count_in_range(body: str, suffix: str) -> int:
    """Return the breach count for a SHA-1 suffix, or 0 if absent."""
    needle = suffix.upper()
    for line in body.splitlines():
        head, _, tail = line.partition(":")
        if head.strip().upper() == needle:
            try:
                return int(tail.strip())
            except ValueError:
                return 1
    return 0


@dataclass
class _HIBPConfig:
    enabled: bool = True
    count_threshold: int = 0
    paths: tuple[str, ...] = _DEFAULT_PATHS
    transport: httpx.AsyncBaseTransport | None = None


def _build_hook(cfg: _HIBPConfig) -> BeforeHook:
    paths = set(cfg.paths)

    def matcher(ctx: EndpointContext) -> bool:
        return cfg.enabled and ctx.request.path in paths

    async def handler(ctx: EndpointContext) -> None:
        password = getattr(ctx.body, "password", None)
        if not password:
            return
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        body_text = await _fetch_range(
            prefix,
            secondary_storage=ctx.auth.secondary_storage,
            transport=cfg.transport,
        )
        count = _count_in_range(body_text, suffix)
        if count > cfg.count_threshold:
            raise APIError(
                400,
                "PASSWORD_COMPROMISED",
                message=HIBP_ERROR_CODES["PASSWORD_COMPROMISED"],
                data={"breachCount": count},
            )

    return BeforeHook(match=matcher, handler=handler)


@dataclass(frozen=True, slots=True)
class _HIBPPlugin:
    id: str
    hooks: PluginHooks
    error_codes: Mapping[str, str]
    version: str | None = None
    endpoints: None = None
    schema: None = None
    middlewares: None = None
    on_request: None = None
    on_response: None = None
    rate_limit: None = None
    init: None = None


def have_i_been_pwned(
    *,
    enabled: bool = True,
    count_threshold: int = 0,
    paths: Sequence[str] = _DEFAULT_PATHS,
    transport: httpx.AsyncBaseTransport | None = None,
) -> KerniaPlugin:
    """Build the HIBP plugin.

    - `enabled=False` short-circuits all checks (useful for tests).
    - `count_threshold` — reject only when breachCount strictly exceeds this.
    - `paths` — endpoints to gate (default: sign-up + reset-password).
    - `transport` — inject an httpx transport for tests.
    """
    cfg = _HIBPConfig(
        enabled=enabled,
        count_threshold=count_threshold,
        paths=tuple(paths),
        transport=transport,
    )
    hooks = PluginHooks(before=(_build_hook(cfg),))
    return _HIBPPlugin(  # type: ignore[return-value]
        id="have-i-been-pwned",
        hooks=hooks,
        error_codes=dict(HIBP_ERROR_CODES),
    )


__all__ = ["have_i_been_pwned", "HIBP_ERROR_CODES"]
