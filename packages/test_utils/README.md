# kernia-test-utils

Shared test utilities for Kernia: an ASGI driver, mock OIDC/SAML identity providers, SMTP/SMS capture, a Stripe REST mock, a software WebAuthn authenticator, and lazy testcontainers fixtures.

Part of [Kernia](https://kernia.dev), a framework-agnostic authentication library for Python.

## Installation

    pip install kernia-test-utils

## Usage

```python
from kernia_test_utils import ASGIDriver, MockSMTP

# Drive an ASGI app like an HTTP client, no server needed.
driver = ASGIDriver(app=auth.router.mount())
response = await driver.post("/api/auth/sign-up/email", json={
    "email": "user@example.com",
    "password": "correct-horse",
    "name": "User",
})

# Capture outgoing email in tests.
smtp = MockSMTP()
```

Also provides `MockIdP`, `MockSAMLIdP`, `MockStripe`, `MockSMS`, `SoftAuthenticator`, and container fixtures behind `requires_docker`.

## Documentation

Full documentation at [kernia.dev/docs](https://kernia.dev/docs). Source at [github.com/advantch/kernia](https://github.com/advantch/kernia).

## License

MIT
