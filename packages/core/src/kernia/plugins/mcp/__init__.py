"""MCP (Model Context Protocol) authorization plugin.

Mirrors `reference/packages/better-auth/src/plugins/mcp/`. Builds on the
OIDC provider plugin with MCP-specific quirks: a structured authorize endpoint
designed for an AI agent rather than a browser redirect, and a separate
`.well-known/oauth-authorization-server` discovery doc.

Endpoints:
  * POST /mcp/authorize
  * GET  /.well-known/oauth-authorization-server
"""

from kernia.plugins.mcp.plugin import MCPOptions, mcp

__all__ = ["MCPOptions", "mcp"]
