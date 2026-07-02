"""kernia MCP integration, built on FastMCP.

Re-exports the core ``mcp`` plugin (the kernia-side authorization endpoints)
plus the FastMCP server-side integration (:func:`mcp_auth`) that lets a
``FastMCP`` server accept and validate the tokens that plugin issues.
"""

from __future__ import annotations

from kernia.plugins.mcp.plugin import (
    MCPOptions,
    introspect_mcp_token,
    mcp,
)

from kernia_mcp.auth import BetterAuthTokenVerifier, mcp_auth

__all__ = [
    "BetterAuthTokenVerifier",
    "MCPOptions",
    "introspect_mcp_token",
    "mcp",
    "mcp_auth",
]
