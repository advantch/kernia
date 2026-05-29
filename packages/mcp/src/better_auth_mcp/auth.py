"""FastMCP authentication backed by a better-auth issuer.

This is the Python analogue of better-auth's ``withMcpAuth`` (JS
``packages/better-auth/src/plugins/mcp``): it lets a `FastMCP` server accept the
OAuth access tokens minted by the better-auth ``mcp`` / ``oauth_provider``
plugins, validate them against the issuer's JWKS, and gate tools by scope.

Usage::

    from fastmcp import FastMCP
    from better_auth_mcp import mcp_auth

    server = FastMCP("my-server", auth=mcp_auth(auth_context))

    @server.tool
    def whoami(ctx) -> str:
        token = ctx.fastmcp_context.auth  # AccessToken with .claims["sub"]
        return token.claims["sub"]

The returned :class:`fastmcp.server.auth.RemoteAuthProvider` automatically serves
``/.well-known/oauth-protected-resource`` and answers unauthenticated requests
with ``WWW-Authenticate: Bearer resource_metadata=...`` (RFC 9728), pointing MCP
clients at the better-auth authorization server.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from better_auth.plugins.mcp.plugin import introspect_mcp_token
from fastmcp.server.auth.auth import AccessToken, RemoteAuthProvider, TokenVerifier

if TYPE_CHECKING:
    from better_auth.types.context import AuthContext


class BetterAuthTokenVerifier(TokenVerifier):
    """Validates better-auth-issued MCP access tokens against the local JWKS.

    A token is accepted only when it verifies against the issuer's signing keys
    *and* (when ``resource_base_url`` is configured) its audience matches the
    protected resource — the RFC 8707 resource-indicator check that prevents a
    token minted for one MCP server being replayed against another.
    """

    def __init__(
        self,
        auth: AuthContext,
        *,
        base_url: str | None = None,
        required_scopes: list[str] | None = None,
        resource_base_url: str | None = None,
    ) -> None:
        super().__init__(
            base_url=base_url,
            required_scopes=required_scopes,
            resource_base_url=resource_base_url,
        )
        self._auth = auth

    async def verify_token(self, token: str) -> AccessToken | None:
        expected_resource = (
            str(self.resource_base_url) if self.resource_base_url is not None else None
        )
        try:
            claims = await introspect_mcp_token(
                self._auth, token, expected_resource=expected_resource
            )
        except ValueError:
            return None

        scopes = [s for s in str(claims.get("scope", "")).split() if s]
        # Enforce the verifier-level required scopes (mirrors FastMCP's contract).
        if self.required_scopes:
            granted = set(scopes)
            if not set(self.required_scopes).issubset(granted):
                return None

        aud = claims.get("aud")
        resource = claims.get("resource")
        if resource is None and isinstance(aud, str):
            resource = aud

        exp = claims.get("exp")
        client_id = claims.get("client_id") or (aud if isinstance(aud, str) else None)
        return AccessToken(
            token=token,
            client_id=str(client_id) if client_id is not None else "",
            scopes=scopes,
            expires_at=int(exp) if isinstance(exp, int | float) else None,
            resource=str(resource) if resource is not None else None,
            claims=dict(claims),
        )


def mcp_auth(
    auth: AuthContext,
    *,
    base_url: str,
    authorization_servers: list[str] | None = None,
    required_scopes: list[str] | None = None,
    resource_base_url: str | None = None,
    scopes_supported: list[str] | None = None,
    **kwargs: Any,
) -> RemoteAuthProvider:
    """Build a FastMCP auth provider that accepts better-auth MCP tokens.

    ``base_url`` is this MCP resource server's public URL. ``authorization_servers``
    defaults to the better-auth issuer derived from the ``mcp`` plugin options, so
    the protected-resource metadata advertises where clients should obtain tokens.
    Pass to ``FastMCP(auth=mcp_auth(...))``.
    """
    issuer = _issuer(auth)
    servers = authorization_servers or ([issuer] if issuer else [])
    verifier = BetterAuthTokenVerifier(
        auth,
        base_url=base_url,
        required_scopes=required_scopes,
        resource_base_url=resource_base_url or base_url,
    )
    return RemoteAuthProvider(
        token_verifier=verifier,
        authorization_servers=servers,  # type: ignore[arg-type]
        base_url=base_url,
        scopes_supported=scopes_supported,
        resource_base_url=resource_base_url,
        **kwargs,
    )


def _issuer(auth: AuthContext) -> str | None:
    for p in auth.plugins:
        if getattr(p, "id", None) == "mcp":
            opts = getattr(p, "opts", None)
            issuer = getattr(opts, "issuer", None)
            if isinstance(issuer, str):
                return issuer
    return None


__all__ = ["BetterAuthTokenVerifier", "mcp_auth"]
