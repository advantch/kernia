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
            for k, v in body.items():
                if k == "cancel_at_period_end":
                    obj["cancel_at_period_end"] = v in ("true", "True", True)
                elif k == "status":
                    obj["status"] = v
                else:
                    obj[k] = v
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

        if path.startswith("/v1/prices/") and method == "GET":
            pid = path.rsplit("/", 1)[-1]
            return httpx.Response(
                200,
                json={
                    "id": pid,
                    "object": "price",
                    "unit_amount": 1000,
                    "currency": "usd",
                    "recurring": {"interval": "month"},
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


__all__ = ["MockStripe"]
