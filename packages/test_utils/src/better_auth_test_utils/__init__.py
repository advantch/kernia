"""Shared test fixtures.

Mirrors `reference/packages/test-utils/`. Exposes:

    * `ASGIDriver` / `ASGIResponse` — call an ASGI app like a client.
    * `MockIdP` — in-process OIDC IdP with signed id_tokens.
    * `MockSMTP` / `SentEmail` — capture outgoing emails.
    * `MockSMS` / `SentSMS` — capture outgoing SMS.
    * `MockStripe` — Stripe REST mock + signed-webhook helper.
    * `MockSAMLIdP` — minimal signed SAML 2.0 IdP fixture.
    * Container helpers — lazy testcontainers fixtures behind `requires_docker`.
    * `all_adapters_param` — pytest parametrize value covering every backend.
"""

from better_auth_test_utils.adapter_fixtures import (
    AdapterFactory,
    adapter_cleanup,
    all_adapters_param,
)
from better_auth_test_utils.asgi_driver import ASGIDriver, ASGIResponse
from better_auth_test_utils.containers import (
    docker_available,
    mongodb_container,
    mysql_container,
    postgres_container,
    redis_container,
    requires_docker,
)
from better_auth_test_utils.mock_idp import MockIdP
from better_auth_test_utils.mock_saml_idp import MockSAMLIdP
from better_auth_test_utils.mock_sms import MockSMS, SentSMS
from better_auth_test_utils.mock_smtp import MockSMTP, SentEmail
from better_auth_test_utils.mock_stripe import MockStripe

__all__ = [
    "ASGIDriver",
    "ASGIResponse",
    "AdapterFactory",
    "MockIdP",
    "MockSAMLIdP",
    "MockSMS",
    "MockSMTP",
    "MockStripe",
    "SentEmail",
    "SentSMS",
    "adapter_cleanup",
    "all_adapters_param",
    "docker_available",
    "mongodb_container",
    "mysql_container",
    "postgres_container",
    "redis_container",
    "requires_docker",
]
