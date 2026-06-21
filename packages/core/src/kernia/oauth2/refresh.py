"""OAuth2 access-token refresh.

Mirrors `refreshAccessToken` in `reference/packages/core/src/oauth2/`. Sends a
`grant_type=refresh_token` request to the provider's token endpoint and returns
the new token bundle.

Providers may return a new refresh_token or none — callers should fall back to
the previous refresh_token if missing.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx


async def refresh_access_token(
    *,
    token_url: str,
    client_id: str,
    client_secret: str,
    refresh_token: str,
    scopes: list[str] | None = None,
    authentication: str = "post",  # or "basic"
    http_client: httpx.AsyncClient | None = None,
) -> Mapping[str, Any]:
    """Refresh an OAuth2 access token. Returns the provider's raw response dict.

    Set `authentication="basic"` for providers (e.g. Apple, some Auth0 setups) that
    require client credentials in the Authorization header instead of the body.
    """
    data: dict[str, str] = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    if scopes:
        data["scope"] = " ".join(scopes)

    headers: dict[str, str] = {"accept": "application/json"}
    auth: tuple[str, str] | None = None
    if authentication == "basic":
        auth = (client_id, client_secret)
    else:
        data["client_id"] = client_id
        data["client_secret"] = client_secret

    own_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=30.0)
    try:
        # httpx accepts auth=None at runtime (meaning "no auth") but its stubs
        # only admit the sentinel/tuple/callable forms.
        r = await client.post(token_url, data=data, headers=headers, auth=auth)  # type: ignore[arg-type]
        r.raise_for_status()
        payload: dict[str, Any] = r.json()
        return payload
    finally:
        if own_client:
            await client.aclose()


__all__ = ["refresh_access_token"]
