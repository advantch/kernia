"""Unit tests for the Where -> BSON translator.

Pure-function tests — no Docker, no I/O. Locks in the wire shape of the BSON
filters our MongoDB adapter emits.
"""

from __future__ import annotations

from kernia.types.adapter import Where
from kernia_mongo.adapter import _escape_regex, _field_name, where_to_bson


def test_empty_where_is_empty_filter() -> None:
    assert where_to_bson(()) == {}


def test_single_eq_is_bare() -> None:
    assert where_to_bson((Where("email", "a@example.com"),)) == {"email": "a@example.com"}


def test_id_field_maps_to_underscore_id() -> None:
    assert where_to_bson((Where("id", "abc"),)) == {"_id": "abc"}
    assert _field_name("id") == "_id"
    assert _field_name("userId") == "userId"


def test_ne_operator() -> None:
    assert where_to_bson((Where("name", "x", operator="ne"),)) == {"name": {"$ne": "x"}}


def test_numeric_operators() -> None:
    assert where_to_bson((Where("age", 30, operator="gt"),)) == {"age": {"$gt": 30}}
    assert where_to_bson((Where("age", 30, operator="gte"),)) == {"age": {"$gte": 30}}
    assert where_to_bson((Where("age", 30, operator="lt"),)) == {"age": {"$lt": 30}}
    assert where_to_bson((Where("age", 30, operator="lte"),)) == {"age": {"$lte": 30}}


def test_in_and_not_in() -> None:
    assert where_to_bson((Where("status", ["a", "b"], operator="in"),)) == {
        "status": {"$in": ["a", "b"]}
    }
    assert where_to_bson((Where("status", ["a"], operator="not_in"),)) == {
        "status": {"$nin": ["a"]}
    }


def test_contains_starts_with_ends_with_escape() -> None:
    f = where_to_bson((Where("email", "a.b", operator="contains"),))
    assert f == {"email": {"$regex": ".*a\\.b.*"}}
    f = where_to_bson((Where("email", "a.b", operator="starts_with"),))
    assert f == {"email": {"$regex": "^a\\.b"}}
    f = where_to_bson((Where("email", "a.b", operator="ends_with"),))
    assert f == {"email": {"$regex": "a\\.b$"}}


def test_ilike_eq_uses_case_insensitive_regex() -> None:
    assert where_to_bson((Where("email", "A@X.com", operator="ilike_eq"),)) == {
        "email": {"$regex": "^A@X\\.com$", "$options": "i"}
    }


def test_and_connector_groups_under_and() -> None:
    out = where_to_bson(
        (
            Where("name", "x"),
            Where("age", 30, operator="gt", connector="AND"),
        )
    )
    assert out == {"$and": [{"name": "x"}, {"age": {"$gt": 30}}]}


def test_or_connector_groups_under_or() -> None:
    out = where_to_bson(
        (
            Where("name", "x"),
            Where("name", "y", connector="OR"),
        )
    )
    # First clause's connector is treated as AND; second goes to $or.
    assert out == {"$and": [{"name": "x"}], "$or": [{"name": "y"}]}


def test_escape_regex_escapes_meta_chars() -> None:
    s = _escape_regex(".*+?^${}()|[]\\")
    assert s == "\\.\\*\\+\\?\\^\\$\\{\\}\\(\\)\\|\\[\\]\\\\"


def test_escape_regex_truncates_to_max_length() -> None:
    s = _escape_regex("a" * 1000, max_length=10)
    # 10 'a's, none of which are meta chars.
    assert s == "a" * 10
