"""Kernia Stripe billing + webhooks plugin.

Mirrors `reference/packages/stripe/src/`. Public entry points:

  * `stripe(options)` — plugin constructor.
  * `StripeOptions`, `StripePlan` — declarative configuration.
  * `StripeClient` — async REST client used to talk to Stripe (or to
    `MockStripe.mock_transport()` in tests).
  * `SUBSCRIPTION_MODEL` — the table the plugin contributes.
"""

from kernia_stripe.client import StripeAPIError, StripeClient
from kernia_stripe.plugin import STRIPE_ERROR_CODES, stripe
from kernia_stripe.schema import (
    SUBSCRIPTION_MODEL,
    USER_EXTENSIONS,
    StripeOptions,
    StripePlan,
)
from kernia_stripe.webhook import verify_signature

__all__ = [
    "STRIPE_ERROR_CODES",
    "SUBSCRIPTION_MODEL",
    "USER_EXTENSIONS",
    "StripeAPIError",
    "StripeClient",
    "StripeOptions",
    "StripePlan",
    "stripe",
    "verify_signature",
]
