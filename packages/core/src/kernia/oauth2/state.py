"""OAuth2 `state` token — CSRF-bound payload carried through the redirect.

Mirrors `reference/packages/better-auth/src/oauth2/state.ts`. The state token
carries the callback URL, requested provider, optional `errorCallbackURL`, the
PKCE verifier (if used), and a random nonce. It is signed with the active secret
so callbacks can't be forged.

Wire format:
    <urlsafe-b64(json)>.<hmac>

Embedded JSON:
    {
      "v": 1,
      "callbackURL": "...",
      "errorCallbackURL": "...",
      "newUserCallbackURL": "...",
      "providerId": "...",
      "codeVerifier": "...",
      "nonce": "...",
      "linkToUserId": "...",         # set when linking an OAuth account to a signed-in user
      "createdAt": <unix-seconds>
    }
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from typing import Any

from kernia.cookies import sign, verify


def generate_state(
    *,
    secret: str,
    callback_url: str,
    provider_id: str,
    error_callback_url: str | None = None,
    new_user_callback_url: str | None = None,
    code_verifier: str | None = None,
    nonce: str | None = None,
    link_to_user_id: str | None = None,
) -> str:
    """Build a signed state token for an outgoing OAuth authorize request."""
    payload: dict[str, Any] = {
        "v": 1,
        "callbackURL": callback_url,
        "providerId": provider_id,
        "nonce": nonce or _random_nonce(),
        "createdAt": int(time.time()),
    }
    if error_callback_url:
        payload["errorCallbackURL"] = error_callback_url
    if new_user_callback_url:
        payload["newUserCallbackURL"] = new_user_callback_url
    if code_verifier:
        payload["codeVerifier"] = code_verifier
    if link_to_user_id:
        payload["linkToUserId"] = link_to_user_id

    raw = (
        base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        .rstrip(b"=")
        .decode("ascii")
    )
    return sign(raw, secret)


def parse_state(state: str, *, secret: str, max_age: int = 600) -> dict[str, Any]:
    """Verify + decode an incoming state token.

    Raises ValueError on bad signature, malformed payload, or expired token.
    """
    raw = verify(state, secret)
    if raw is None:
        raise ValueError("state signature is invalid")
    pad = "=" * (-len(raw) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(raw + pad))
    except Exception as e:
        raise ValueError(f"state payload is malformed: {e}") from None
    if not isinstance(data, dict):
        raise ValueError("state payload must be a JSON object")
    if data.get("v") != 1:
        raise ValueError("state payload version is not supported")
    created_at = data.get("createdAt")
    if not isinstance(created_at, int):
        raise ValueError("state payload missing createdAt")
    if int(time.time()) - created_at >= max_age:
        raise ValueError("state is expired")
    return data


def _random_nonce() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode("ascii")


__all__ = ["generate_state", "parse_state"]
