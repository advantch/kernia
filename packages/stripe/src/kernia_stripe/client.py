"""Async Stripe REST client used by the plugin.

Stripe's official Python SDK is synchronous and tricky to inject for tests, so
we issue REST calls ourselves via `httpx.AsyncClient`. The same client surface
talks to a real Stripe account or to the in-memory `MockStripe` fixture (just
hand the constructor a transport pointing at the mock).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


_STRIPE_API_BASE = "https://api.stripe.com"


@dataclass
class StripeClient:
    """Minimal async Stripe REST client.

    `transport` lets tests inject `MockStripe.mock_transport()`. The real
    production path takes `api_key` and uses the default httpx transport.
    """

    api_key: str = ""
    transport: httpx.AsyncBaseTransport | None = None
    base_url: str = _STRIPE_API_BASE
    timeout: float = 10.0

    def _new_client(self) -> httpx.AsyncClient:
        headers: dict[str, str] = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return httpx.AsyncClient(
            transport=self.transport,
            base_url=self.base_url,
            headers=headers,
            timeout=httpx.Timeout(self.timeout),
        )

    async def _post(self, path: str, data: dict[str, Any]) -> dict[str, Any]:
        async with self._new_client() as c:
            r = await c.post(path, data=_flatten(data))
        if r.status_code >= 400:
            raise StripeAPIError(r.status_code, r.text)
        return r.json()

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        async with self._new_client() as c:
            r = await c.get(path, params=params or {})
        if r.status_code >= 400:
            raise StripeAPIError(r.status_code, r.text)
        return r.json()

    # ----- customers --------------------------------------------------------

    async def create_customer(
        self, *, email: str | None = None, name: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if email:
            body["email"] = email
        if name:
            body["name"] = name
        if metadata:
            body["metadata"] = metadata
        return await self._post("/v1/customers", body)

    async def get_customer(self, customer_id: str) -> dict[str, Any]:
        return await self._get(f"/v1/customers/{customer_id}")

    # ----- checkout sessions ------------------------------------------------

    async def create_checkout_session(self, **params: Any) -> dict[str, Any]:
        return await self._post("/v1/checkout/sessions", params)

    # ----- billing portal ---------------------------------------------------

    async def create_billing_portal_session(self, **params: Any) -> dict[str, Any]:
        return await self._post("/v1/billing_portal/sessions", params)

    # ----- subscriptions ----------------------------------------------------

    async def get_subscription(self, subscription_id: str) -> dict[str, Any]:
        return await self._get(f"/v1/subscriptions/{subscription_id}")

    async def update_subscription(
        self, subscription_id: str, **params: Any
    ) -> dict[str, Any]:
        return await self._post(f"/v1/subscriptions/{subscription_id}", params)

    async def cancel_subscription(
        self, subscription_id: str, *, at_period_end: bool = True
    ) -> dict[str, Any]:
        if at_period_end:
            return await self.update_subscription(
                subscription_id, cancel_at_period_end="true"
            )
        # immediate cancel — DELETE in Stripe's REST
        async with self._new_client() as c:
            r = await c.delete(f"/v1/subscriptions/{subscription_id}")
        if r.status_code >= 400:
            raise StripeAPIError(r.status_code, r.text)
        return r.json()


class StripeAPIError(Exception):
    """Surface Stripe REST failures with status + body."""

    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"Stripe API error {status}: {body}")
        self.status = status
        self.body = body


def _flatten(data: dict[str, Any], prefix: str = "") -> dict[str, str]:
    """Encode a nested dict using Stripe's bracket form (e.g. `metadata[foo]=bar`)."""
    out: dict[str, str] = {}
    for k, v in data.items():
        key = f"{prefix}[{k}]" if prefix else str(k)
        if isinstance(v, dict):
            out.update(_flatten(v, key))
        elif isinstance(v, list):
            for i, item in enumerate(v):
                idx_key = f"{key}[{i}]"
                if isinstance(item, dict):
                    out.update(_flatten(item, idx_key))
                else:
                    out[idx_key] = str(item)
        elif v is None:
            continue
        else:
            out[key] = str(v).lower() if isinstance(v, bool) else str(v)
    return out


__all__ = ["StripeAPIError", "StripeClient"]
