"""Ported from reference/packages/stripe/test/utils.test.ts.

Covers `escape_stripe_search_value` and `resolve_plan_item`. Kept ~1:1 with the
upstream `escapeStripeSearchValue` / `resolvePlanItem` describe blocks.
"""

from __future__ import annotations

from better_auth_stripe.schema import StripeOptions, StripePlan
from better_auth_stripe.utils import escape_stripe_search_value, resolve_plan_item


def _options(plans: dict[str, StripePlan]) -> StripeOptions:
    return StripeOptions(stripe_client=object(), webhook_secret="s", plans=plans)


# ----- escapeStripeSearchValue ---------------------------------------------


def test_escape_double_quotes() -> None:
    assert escape_stripe_search_value('test"value') == 'test\\"value'


def test_escape_handles_strings_without_quotes() -> None:
    assert escape_stripe_search_value("simple") == "simple"


def test_escape_multiple_quotes() -> None:
    assert escape_stripe_search_value('"a" and "b"') == '\\"a\\" and \\"b\\"'


# ----- resolvePlanItem ------------------------------------------------------

_OPTIONS = _options(
    {
        "starter": StripePlan(name="starter", price_id="price_starter"),
        "premium": StripePlan(name="premium", price_id="price_premium"),
    }
)


def test_resolve_plan_item_single_item() -> None:
    items = [{"price": {"id": "price_starter", "lookup_key": None}}]
    result = resolve_plan_item(_OPTIONS, items)
    assert result is not None
    assert result["item"]["price"]["id"] == "price_starter"
    assert result["plan"].name == "starter"


def test_resolve_plan_item_empty_items() -> None:
    assert resolve_plan_item(_OPTIONS, []) is None


def test_resolve_plan_item_unmatched_single_item() -> None:
    items = [{"price": {"id": "price_unknown", "lookup_key": None}}]
    result = resolve_plan_item(_OPTIONS, items)
    assert result is not None
    assert result["item"]["price"]["id"] == "price_unknown"
    assert result["plan"] is None


def test_resolve_plan_item_matching_from_multi_item() -> None:
    items = [
        {"price": {"id": "price_seat_addon", "lookup_key": None}},
        {"price": {"id": "price_starter", "lookup_key": None}},
    ]
    result = resolve_plan_item(_OPTIONS, items)
    assert result is not None
    assert result["item"]["price"]["id"] == "price_starter"
    assert result["plan"].name == "starter"


def test_resolve_plan_item_no_match_multi_item() -> None:
    items = [
        {"price": {"id": "price_unknown_1", "lookup_key": None}},
        {"price": {"id": "price_unknown_2", "lookup_key": None}},
    ]
    assert resolve_plan_item(_OPTIONS, items) is None


def test_resolve_plan_item_match_by_lookup_key() -> None:
    options = _options(
        {
            "starter": StripePlan(name="starter", lookup_key="lookup_starter"),
            "premium": StripePlan(name="premium", lookup_key="lookup_premium"),
        }
    )
    items = [
        {"price": {"id": "price_seat", "lookup_key": None}},
        {"price": {"id": "price_foo", "lookup_key": "lookup_premium"}},
    ]
    result = resolve_plan_item(options, items)
    assert result is not None
    assert result["item"]["price"]["id"] == "price_foo"
    assert result["plan"].name == "premium"
