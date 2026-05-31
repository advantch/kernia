"""Stripe metadata helpers — mirrors `reference/packages/stripe/src/metadata.ts`.

Internal fields (userId / subscriptionId / referenceId / customerType /
organizationId) always win over user-supplied metadata and reserved
prototype-mutating keys are dropped.
"""

from __future__ import annotations

from typing import Any, ClassVar

_UNSAFE_KEYS = {"__proto__", "constructor", "prototype"}


def _merge_metadata(
    internal_fields: dict[str, str],
    *user_metadata: dict[str, Any] | None,
) -> dict[str, str]:
    merged: dict[str, str] = {}
    for source in user_metadata:
        if not source:
            continue
        for key, value in source.items():
            if key in _UNSAFE_KEYS:
                continue
            merged[key] = value
    for key, value in internal_fields.items():
        merged[key] = value
    return merged


class _CustomerMetadata:
    keys: ClassVar[dict[str, str]] = {
        "userId": "userId",
        "organizationId": "organizationId",
        "customerType": "customerType",
    }

    @staticmethod
    def set(
        internal_fields: dict[str, str], *user_metadata: dict[str, Any] | None
    ) -> dict[str, str]:
        return _merge_metadata(internal_fields, *user_metadata)

    @staticmethod
    def get(metadata: dict[str, Any] | None) -> dict[str, Any]:
        metadata = metadata or {}
        return {
            "userId": metadata.get("userId"),
            "organizationId": metadata.get("organizationId"),
            "customerType": metadata.get("customerType"),
        }


class _SubscriptionMetadata:
    keys: ClassVar[dict[str, str]] = {
        "userId": "userId",
        "subscriptionId": "subscriptionId",
        "referenceId": "referenceId",
    }

    @staticmethod
    def set(
        internal_fields: dict[str, str], *user_metadata: dict[str, Any] | None
    ) -> dict[str, str]:
        return _merge_metadata(internal_fields, *user_metadata)

    @staticmethod
    def get(metadata: dict[str, Any] | None) -> dict[str, Any]:
        metadata = metadata or {}
        return {
            "userId": metadata.get("userId"),
            "subscriptionId": metadata.get("subscriptionId"),
            "referenceId": metadata.get("referenceId"),
        }


customer_metadata = _CustomerMetadata()
subscription_metadata = _SubscriptionMetadata()


__all__ = ["customer_metadata", "subscription_metadata"]
