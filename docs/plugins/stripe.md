# Stripe

Package: `kernia-stripe`

```bash
pip install kernia-stripe
```

```python
from kernia_stripe import StripeClient, StripeOptions, stripe

plugins = [
    stripe(
        StripeOptions(
            client=StripeClient(api_key="sk_test_..."),
            webhook_secret="whsec_...",
        )
    )
]
```

## Contributed routes

- `/stripe/checkout`
- `/stripe/portal`
- `/stripe/webhook`
- `/stripe/subscription/cancel`
- `/stripe/subscription/resume`
- `/stripe/subscriptions`
- `/stripe/catalog/sync`
- `/stripe/products`
- `/stripe/prices`
- `/billing/check`
- `/billing/track`
- `/billing/customer`
- `/billing/portal`
- `/billing/usage`

## Schema

Adds subscription state plus billing catalog, plan, feature, entitlement,
customer, usage, and sync-state tables.

## Coverage

Covered by `e2e/plugins/test_stripe.py` with mocked Stripe products, prices,
checkout, portal, webhooks, catalog import, entitlement checks, and usage
tracking.
