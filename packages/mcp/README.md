# kernia-mcp

OAuth-protected Model Context Protocol (MCP) integration for Kernia, built on FastMCP. Kernia issues and introspects MCP access tokens; a FastMCP server validates them.

Part of [Kernia](https://kernia.dev), a framework-agnostic authentication library for Python.

## Installation

    pip install kernia-mcp

## Usage

Enable the `mcp` plugin on your auth instance, then gate a FastMCP server with `mcp_auth`:

```python
from fastmcp import FastMCP
from kernia_mcp import MCPOptions, mcp, mcp_auth

# On the auth server: add the plugin to your plugins=[...] list
mcp(MCPOptions(issuer="https://auth.example.com"))

# On the MCP resource server:
provider = mcp_auth(
    auth.context,
    base_url="https://mcp.example.com",
    authorization_servers=["https://auth.example.com"],
)
server = FastMCP("my-mcp", auth=provider)

@server.tool
def ping() -> str:
    return "pong"
```

## Documentation

Full documentation at [kernia.dev/docs](https://kernia.dev/docs). Source at [github.com/advantch/kernia](https://github.com/advantch/kernia).

## License

MIT
