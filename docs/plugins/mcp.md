# Mcp

> Module: `kernia.plugins.mcp`
> Constructor: `mcp`

MCP (Model Context Protocol) authorization plugin.

Mirrors `reference/packages/better-auth/src/plugins/mcp/`. Builds on the
OIDC provider plugin with MCP-specific quirks: a structured authorize endpoint
designed for an AI agent rather than a browser redirect, and a separate
`.well-known/oauth-authorization-server` discovery doc.

Endpoints:
  * POST /mcp/authorize
  * GET  /.well-known/oauth-authorization-server

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from kernia.plugins.mcp import mcp
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            mcp(),
        ],
    )
)
```
