# kernia-stripe

Stripe billing and webhooks plugin for Kernia. Handles customers, checkout, subscriptions, seat-based billing, and signed webhook verification.

Part of [Kernia](https://kernia.dev), a framework-agnostic authentication library for Python.

## Installation

    pip install kernia-stripe

## Usage

```python
from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.plugins.organization import organization
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_stripe import StripeClient, StripeOptions, StripePlan, stripe

auth = init(
    KerniaOptions(
        database=memory_adapter(),
        secret="dev-secret",
        plugins=[
            email_and_password(),
            organization(),
            stripe(
                StripeOptions(
                    stripe_client=StripeClient(api_key="sk_test_..."),
                    webhook_secret="whsec_...",
                    subscription_for="organization",
                    plans={
                        "team": StripePlan(
                            name="team",
                            price_id="price_team_base",
                            seats=True,
                            seat_price_id="price_team_seat",
                        ),
                    },
                )
            ),
        ],
    )
)
```

## Documentation

Full documentation at [kernia.dev/docs](https://kernia.dev/docs). Source at [github.com/advantch/kernia](https://github.com/advantch/kernia).

## License

MIT
