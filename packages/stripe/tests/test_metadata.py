"""Ported from reference/packages/stripe/test/metadata.test.ts.

Covers the metadata prototype-pollution guard and the set/get helpers.
Python dicts don't have a JS-style prototype, so the pollution assertions are
adapted to check that the unsafe keys (`__proto__`, `constructor`, `prototype`)
are dropped and that internal fields win — the behavioral intent upstream.

@see https://github.com/advisories/GHSA-737v-mqg7-c878
"""

from __future__ import annotations

from better_auth_stripe.metadata import customer_metadata, subscription_metadata

ROOT_PROBE_KEY = "polluted"


# ----- prototype pollution guard -------------------------------------------


def test_drops_proto_from_user_metadata_on_customer_set() -> None:
    malicious = {"__proto__": {ROOT_PROBE_KEY: "yes"}, "plan": "pro"}
    result = customer_metadata.set({"customerType": "user", "userId": "u1"}, malicious)
    assert "__proto__" not in result
    assert {}.get(ROOT_PROBE_KEY) is None
    assert result["plan"] == "pro"
    assert result["userId"] == "u1"


def test_drops_constructor_and_prototype_on_customer_set() -> None:
    malicious = {
        "constructor": {"prototype": {ROOT_PROBE_KEY: "yes"}},
        "plan": "pro",
    }
    result = customer_metadata.set({"customerType": "user", "userId": "u1"}, malicious)
    assert "constructor" not in result
    assert result["plan"] == "pro"


def test_drops_proto_from_user_metadata_on_subscription_set() -> None:
    malicious = {"__proto__": {ROOT_PROBE_KEY: "yes"}, "planName": "pro"}
    result = subscription_metadata.set(
        {"userId": "u1", "subscriptionId": "s1", "referenceId": "ref1"}, malicious
    )
    assert "__proto__" not in result
    assert result["planName"] == "pro"
    assert result["subscriptionId"] == "s1"


def test_internal_fields_take_precedence_over_user_metadata() -> None:
    result = customer_metadata.set(
        {"customerType": "user", "userId": "real"},
        {"userId": "spoofed", "customerType": "organization"},
    )
    assert result["userId"] == "real"
    assert result["customerType"] == "user"


# ----- metadata helpers -----------------------------------------------------


def test_customer_set_protects_internal_fields() -> None:
    result = customer_metadata.set(
        {"userId": "real", "customerType": "user"},
        {"userId": "fake", "custom": "value"},
    )
    assert result["userId"] == "real"
    assert result["customerType"] == "user"
    assert result["custom"] == "value"


def test_customer_get_extracts_typed_fields() -> None:
    result = customer_metadata.get(
        {"userId": "u1", "customerType": "organization", "extra": "ignored"}
    )
    assert result["userId"] == "u1"
    assert result["customerType"] == "organization"
    assert "extra" not in result


def test_subscription_set_protects_internal_fields() -> None:
    result = subscription_metadata.set(
        {"userId": "u1", "subscriptionId": "s1", "referenceId": "r1"},
        {"subscriptionId": "fake"},
    )
    assert result["subscriptionId"] == "s1"


def test_subscription_get_extracts_typed_fields() -> None:
    result = subscription_metadata.get(
        {
            "userId": "u1",
            "subscriptionId": "s1",
            "referenceId": "r1",
            "extra": "ignored",
        }
    )
    assert result["userId"] == "u1"
    assert result["subscriptionId"] == "s1"
    assert result["referenceId"] == "r1"
    assert "extra" not in result
