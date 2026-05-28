# Billing and entitlements

`kernia-stripe` keeps the existing Better Auth-compatible Stripe routes and adds
a Stripe-import-first billing layer for SaaS products.

## Install

```bash
pip install kernia-stripe
```

```python
from kernia_stripe import StripeClient, StripeOptions, stripe

auth = init(
    KerniaOptions(
        database=adapter,
        secret="change-me",
        plugins=[
            stripe(
                StripeOptions(
                    client=StripeClient(api_key="sk_live_..."),
                    webhook_secret="whsec_...",
                )
            )
        ],
    )
)
```

## Catalog sync

Kernia imports Stripe as the source of truth first:

```http
POST /api/auth/stripe/catalog/sync
```

The sync imports Stripe products and prices into `billingProduct` and
`billingPrice`, then records progress in `billingSyncState`. You can map those
imported records to plans, features, and entitlements in your own admin surface.

## Billing routes

| Route | Purpose |
| --- | --- |
| `GET /api/auth/stripe/products` | List imported products. |
| `GET /api/auth/stripe/prices` | List imported prices. |
| `POST /api/auth/billing/check` | Check boolean, quantity, seat, or metered access. |
| `POST /api/auth/billing/track` | Record usage and update balances. |
| `GET /api/auth/billing/customer` | Read the current user's billing customer state. |
| `GET /api/auth/billing/portal` | Create a Stripe billing portal session. |
| `GET /api/auth/billing/usage` | List usage events for the current customer. |

## Feature model

The schema supports boolean features, consumable metered features,
non-consumable quantities, included grants, reset periods, overage flags, and
seat-style quantities. `check` returns whether the requested quantity is allowed;
`track` records usage for metered enforcement.

Existing checkout, portal, webhook, cancel, resume, and subscription list routes
remain available.
