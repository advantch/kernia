"""In-memory Stripe mock — REST surface + webhook signing.

The transport mocks just enough of the Stripe API for the stripe-plugin tests:
- POST   /v1/customers              -> creates a customer
- GET    /v1/customers/{id}         -> retrieves it
- POST   /v1/checkout/sessions      -> creates a checkout session
- GET    /v1/subscriptions/{id}     -> retrieves a subscription
- POST   /v1/subscriptions          -> creates a subscription
- GET    /v1/prices/{id}            -> retrieves a price (stub)

`emit_webhook()` produces a payload bytes + headers tuple with a valid
`Stripe-Signature` header (Stripe's `t=<ts>,v1=<hmac>` scheme).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

import httpx


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(12)}"


@dataclass
class MockStripe:
    customers: dict[str, dict[str, Any]] = field(default_factory=dict)
    subscriptions: dict[str, dict[str, Any]] = field(default_factory=dict)
    sessions: dict[str, dict[str, Any]] = field(default_factory=dict)
    capture_events: list[dict[str, Any]] = field(default_factory=list)
    # Pre-seeded price objects keyed by price id and/or lookup key. Lets tests
    # declare a metered price (``recurring.usage_type == "metered"``) so the
    # plugin's usage-based code paths can be exercised end-to-end.
    prices: dict[str, dict[str, Any]] = field(default_factory=dict)

    def add_price(
        self,
        price_id: str,
        *,
        usage_type: str = "licensed",
        interval: str = "month",
        unit_amount: int = 1000,
        lookup_key: str | None = None,
    ) -> dict[str, Any]:
        """Register a price object so /v1/prices lookups return it.

        ``usage_type="metered"`` marks the price as usage-based.
        """
        obj = {
            "id": price_id,
            "object": "price",
            "unit_amount": unit_amount,
            "currency": "usd",
            "lookup_key": lookup_key,
            "active": True,
            "recurring": {"interval": interval, "usage_type": usage_type},
        }
        self.prices[price_id] = obj
        if lookup_key:
            self.prices[lookup_key] = obj
        return obj

    # ----- transport -----

    def mock_transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        method = request.method
        path = request.url.path
        body = self._parse_form(request.content)

        # /v1/customers
        if path == "/v1/customers" and method == "POST":
            obj = {
                "id": _new_id("cus"),
                "object": "customer",
                "email": body.get("email"),
                "name": body.get("name"),
                "metadata": self._collect_metadata(body),
            }
            self.customers[obj["id"]] = obj
            self.capture_events.append({"type": "customer.create", "object": obj})
            return httpx.Response(200, json=obj)
        if path.startswith("/v1/customers/") and method == "GET":
            cid = path.rsplit("/", 1)[-1]
            obj = self.customers.get(cid)
            if obj is None:
                return self._err(404, f"No such customer: {cid}")
            return httpx.Response(200, json=obj)

        # /v1/checkout/sessions
        if path == "/v1/checkout/sessions" and method == "POST":
            obj = {
                "id": _new_id("cs"),
                "object": "checkout.session",
                "url": f"https://checkout.stripe.test/c/{_new_id('pay')}",
                "mode": body.get("mode", "subscription"),
                "customer": body.get("customer"),
                "success_url": body.get("success_url"),
                "cancel_url": body.get("cancel_url"),
                "line_items": self._collect_line_items(body),
                "subscription_data": self._collect_subscription_data(body),
                "metadata": self._collect_metadata(body),
            }
            self.sessions[obj["id"]] = obj
            self.capture_events.append({"type": "checkout.session.create", "object": obj})
            return httpx.Response(200, json=obj)

        # /v1/subscriptions
        if path == "/v1/subscriptions" and method == "POST":
            obj = {
                "id": _new_id("sub"),
                "object": "subscription",
                "customer": body.get("customer"),
                "status": "active",
                "items": {"data": []},
                "metadata": self._collect_metadata(body),
            }
            self.subscriptions[obj["id"]] = obj
            self.capture_events.append({"type": "subscription.create", "object": obj})
            return httpx.Response(200, json=obj)
        if path.startswith("/v1/subscriptions/") and method == "GET":
            sid = path.rsplit("/", 1)[-1]
            obj = self.subscriptions.get(sid)
            if obj is None:
                return self._err(404, f"No such subscription: {sid}")
            return httpx.Response(200, json=obj)
        if path.startswith("/v1/subscriptions/") and method == "POST":
            sid = path.rsplit("/", 1)[-1]
            obj = self.subscriptions.get(sid)
            if obj is None:
                return self._err(404, f"No such subscription: {sid}")
            line_items = self._collect_line_items(body, prefix="items")
            if line_items:
                # Reflect the swapped prices back into items.data so callers can
                # inspect whether a metered item omitted `quantity`.
                obj["items"] = {
                    "data": [
                        {
                            "id": li.get("id", _new_id("si")),
                            "price": {"id": li.get("price")},
                            **({"quantity": int(li["quantity"])} if "quantity" in li else {}),
                        }
                        for li in line_items
                    ]
                }
            for k, v in body.items():
                if k.startswith("items[") or k.startswith("metadata["):
                    continue
                if k == "cancel_at_period_end":
                    obj["cancel_at_period_end"] = v in ("true", "True", True)
                elif k == "status":
                    obj["status"] = v
                else:
                    obj[k] = v
            meta = self._collect_metadata(body)
            if meta:
                obj["metadata"] = {**(obj.get("metadata") or {}), **meta}
            self.capture_events.append({"type": "subscription.update", "object": obj})
            return httpx.Response(200, json=obj)
        if path.startswith("/v1/subscriptions/") and method == "DELETE":
            sid = path.rsplit("/", 1)[-1]
            obj = self.subscriptions.get(sid)
            if obj is None:
                return self._err(404, f"No such subscription: {sid}")
            obj["status"] = "canceled"
            self.capture_events.append({"type": "subscription.delete", "object": obj})
            return httpx.Response(200, json=obj)

        # /v1/billing_portal/sessions
        if path == "/v1/billing_portal/sessions" and method == "POST":
            obj = {
                "id": _new_id("bps"),
                "object": "billing_portal.session",
                "customer": body.get("customer"),
                "return_url": body.get("return_url"),
                "url": f"https://billing.stripe.test/p/{_new_id('sess')}",
            }
            self.capture_events.append({"type": "billing_portal.create", "object": obj})
            return httpx.Response(200, json=obj)

        # /v1/prices — list (supports lookup_keys[] filtering) and retrieve.
        if path == "/v1/prices" and method == "GET":
            params = dict(request.url.params.multi_items())
            lookup_keys = [
                v for k, v in request.url.params.multi_items()
                if k in ("lookup_keys[]", "lookup_keys")
            ]
            data: list[dict[str, Any]] = []
            if lookup_keys:
                seen: set[str] = set()
                for lk in lookup_keys:
                    obj = self.prices.get(lk)
                    if obj is not None and obj["id"] not in seen:
                        seen.add(obj["id"])
                        data.append(obj)
            else:
                seen = set()
                for obj in self.prices.values():
                    if obj["id"] not in seen:
                        seen.add(obj["id"])
                        data.append(obj)
            try:
                limit = int(params.get("limit", "10"))
            except ValueError:
                limit = 10
            return httpx.Response(
                200,
                json={"object": "list", "data": data[:limit], "has_more": False},
            )
        if path.startswith("/v1/prices/") and method == "GET":
            pid = path.rsplit("/", 1)[-1]
            obj = self.prices.get(pid)
            if obj is not None:
                return httpx.Response(200, json=obj)
            # Fall back to a default licensed price for unregistered ids.
            return httpx.Response(
                200,
                json={
                    "id": pid,
                    "object": "price",
                    "unit_amount": 1000,
                    "currency": "usd",
                    "recurring": {"interval": "month", "usage_type": "licensed"},
                },
            )

        return self._err(404, f"unhandled {method} {path}")

    # ----- webhook -----

    @staticmethod
    def emit_webhook(payload: dict[str, Any], secret: str) -> tuple[bytes, dict[str, str]]:
        """Build a signed Stripe webhook payload + headers.

        Returns `(body_bytes, headers)` where headers contains a valid
        `Stripe-Signature` header (`t=<ts>,v1=<hmac>`).
        """
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        timestamp = int(time.time())
        signed_payload = f"{timestamp}.".encode("ascii") + body
        sig = hmac.new(
            secret.encode("utf-8"), signed_payload, hashlib.sha256
        ).hexdigest()
        return body, {
            "Stripe-Signature": f"t={timestamp},v1={sig}",
            "Content-Type": "application/json",
        }

    # ----- helpers -----

    @staticmethod
    def _err(status: int, message: str) -> httpx.Response:
        return httpx.Response(status, json={"error": {"message": message, "type": "invalid_request_error"}})

    @staticmethod
    def _parse_form(content: bytes) -> dict[str, str]:
        if not content:
            return {}
        # Stripe SDK sends application/x-www-form-urlencoded.
        from urllib.parse import parse_qsl

        return dict(parse_qsl(content.decode("utf-8"), keep_blank_values=True))

    @staticmethod
    def _collect_metadata(body: dict[str, str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for k, v in body.items():
            if k.startswith("metadata[") and k.endswith("]"):
                out[k[len("metadata[") : -1]] = v
        return out

    @staticmethod
    def _collect_line_items(
        body: dict[str, str], prefix: str = "line_items"
    ) -> list[dict[str, Any]]:
        """Reassemble Stripe's bracket-encoded ``<prefix>[i][field]`` form.

        Captures both ``price`` and ``quantity`` so tests can assert that
        metered line items omit ``quantity``. Checkout uses ``line_items``;
        subscription updates use ``items``.
        """
        open_br = f"{prefix}["
        items: dict[int, dict[str, Any]] = {}
        for k, v in body.items():
            if not k.startswith(open_br):
                continue
            rest = k[len(open_br) :]
            idx_str, _, field_part = rest.partition("]")
            try:
                idx = int(idx_str)
            except ValueError:
                continue
            field = field_part.lstrip("[").rstrip("]")
            items.setdefault(idx, {})[field] = v
        return [items[i] for i in sorted(items)]

    @staticmethod
    def _collect_subscription_data(body: dict[str, str]) -> dict[str, Any]:
        """Reassemble ``subscription_data[field]`` (e.g. trial_period_days)."""
        out: dict[str, Any] = {}
        prefix = "subscription_data["
        for k, v in body.items():
            if k.startswith(prefix) and k.endswith("]"):
                out[k[len(prefix) : -1]] = v
        return out


__all__ = ["MockStripe"]
