"""SCIM filter parser.

Mirrors ``reference/packages/scim/src/scim-filters.ts``. Supports the upstream
subset: a single ``<attribute> <op> <value>`` expression where ``op`` is one of
``eq|ne|co|sw|ew|pr`` and only ``eq`` maps to a DB filter (on ``userName``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from better_auth_scim.schemas import SCIM_USER_RESOURCE_SCHEMA


@dataclass(frozen=True, slots=True)
class DBFilter:
    field: str
    value: Any
    operator: str | None = None


class SCIMParseError(Exception):
    """Raised when a SCIM filter expression cannot be parsed."""


_SCIM_OPERATORS: dict[str, str | None] = {"eq": "eq"}
_SCIM_USER_ATTRIBUTES: dict[str, str | None] = {"userName": "email"}

_FILTER_RE = re.compile(
    r'^\s*(?P<attribute>[^\s]+)\s+(?P<op>eq|ne|co|sw|ew|pr)\s*'
    r'(?:(?P<value>"[^"]*"|[^\s]+))?\s*$',
    re.IGNORECASE,
)


def _parse_scim_filter(filter_str: str) -> tuple[str, str, str]:
    match = _FILTER_RE.match(filter_str)
    if not match:
        raise SCIMParseError("Invalid filter expression")

    attribute = match.group("attribute")
    op = (match.group("op") or "").lower()
    value = match.group("value")

    if not attribute or not op or not value:
        raise SCIMParseError("Invalid filter expression")

    operator = _SCIM_OPERATORS.get(op)
    if not operator:
        raise SCIMParseError(f'The operator "{op}" is not supported')

    return attribute, operator, value


def parse_scim_user_filter(filter_str: str) -> list[DBFilter]:
    attribute, operator, value = _parse_scim_filter(filter_str)

    target_attribute = _SCIM_USER_ATTRIBUTES.get(attribute)
    resource_attribute = next(
        (
            attr
            for attr in SCIM_USER_RESOURCE_SCHEMA["attributes"]
            if attr["name"] == attribute
        ),
        None,
    )

    if not target_attribute or not resource_attribute:
        raise SCIMParseError(f'The attribute "{attribute}" is not supported')

    final_value = value.replace('"', "")
    if not resource_attribute.get("caseExact"):
        final_value = final_value.lower()

    return [DBFilter(field=target_attribute, value=final_value, operator=operator)]
