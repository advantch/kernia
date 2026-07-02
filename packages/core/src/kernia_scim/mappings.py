"""SCIM <-> better-auth field mappings.

Mirrors ``reference/packages/scim/src/mappings.ts`` and ``utils.ts``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urljoin


def get_account_id(user_name: str, external_id: str | None = None) -> str:
    return external_id if external_id is not None else user_name


def _formatted_name(name: Mapping[str, Any]) -> str:
    given = name.get("givenName")
    family = name.get("familyName")
    if given and family:
        return f"{given} {family}"
    if given:
        return given
    return family or ""


def get_user_full_name(email: str, name: Mapping[str, Any] | None = None) -> str:
    if name is not None:
        formatted = (name.get("formatted") or "").strip()
        if formatted:
            return formatted
        return _formatted_name(name) or email
    return email


def get_user_primary_email(user_name: str, emails: list[Mapping[str, Any]] | None = None) -> str:
    if emails:
        primary = next((e for e in emails if e.get("primary")), None)
        if primary and primary.get("value"):
            return primary["value"]
        if emails[0].get("value"):
            return emails[0]["value"]
    return user_name


def get_resource_url(path: str, base_url: str) -> str:
    normalized_base = base_url if base_url.endswith("/") else f"{base_url}/"
    normalized_path = path.lstrip("/")
    return urljoin(normalized_base, normalized_path)
