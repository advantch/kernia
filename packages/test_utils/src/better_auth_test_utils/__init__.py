"""Shared test fixtures.

Mirrors `reference/packages/test-utils/`. Exposes an ASGI driver that lets tests
call an auth app without an HTTP server.
"""

from better_auth_test_utils.asgi_driver import ASGIDriver, ASGIResponse

__all__ = ["ASGIDriver", "ASGIResponse"]
