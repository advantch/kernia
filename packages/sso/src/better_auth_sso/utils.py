"""Shared SSO helpers.

1:1 port of ``reference/packages/sso/src/utils.ts``.

``getHostnameFromDomain`` mirrors ``tldts.getHostname``: a bare domain, a full
URL, a URL with port or path, and a subdomain all resolve to the host portion;
an empty string yields ``None``. We achieve the same with ``urllib.parse`` by
prefixing scheme-less inputs with ``//`` so they parse as network locations.
"""

from __future__ import annotations

import json
from typing import Any, TypeVar
from urllib.parse import urlparse

T = TypeVar("T")


def safe_json_parse(value: Any) -> Any:
    """Parse a value that may be a JSON string or an already-parsed object.

    Mirrors the TS ``safeJsonParse``: falsy -> ``None``; dict/list returned
    as-is; strings are JSON-decoded (raising on failure); anything else ``None``.
    """
    # JS falsiness: null/undefined/""/0/false -> null. Note an empty object or
    # array is *truthy* in JS, so those must be returned as-is (check first).
    if isinstance(value, dict | list):
        return value
    if not value:
        return None
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError) as error:
            raise ValueError(f"Failed to parse JSON: {error}") from error
    return None


def domain_matches(search_domain: str, domain_list: str) -> bool:
    """Return True if *search_domain* matches any domain in *domain_list*.

    ``domain_list`` is comma-separated. Matching is case-insensitive and a
    domain matches its subdomains (``hr.company.com`` matches ``company.com``).
    """
    search = search_domain.lower()
    domains = [d.strip().lower() for d in domain_list.split(",")]
    domains = [d for d in domains if d]
    return any(search == d or search.endswith(f".{d}") for d in domains)


def validate_email_domain(email: str, domain: str) -> bool:
    """Validate an email's domain against allowed domain(s).

    Supports comma-separated domains for multi-domain SSO (issue #7324).
    """
    parts = email.split("@")
    email_domain = parts[1].lower() if len(parts) > 1 and parts[1] else None
    if not email_domain or not domain:
        return False
    return domain_matches(email_domain, domain)


def get_hostname_from_domain(domain: str) -> str | None:
    """Extract the hostname from a bare domain or URL, else ``None`` (issue #8361)."""
    if not domain:
        return None
    candidate = domain if "//" in domain else f"//{domain}"
    return urlparse(candidate).hostname or None


def mask_client_id(client_id: str) -> str:
    """Mask a client id, keeping only the last 4 characters."""
    if len(client_id) <= 4:
        return "****"
    return f"****{client_id[-4:]}"


__all__ = [
    "domain_matches",
    "get_hostname_from_domain",
    "mask_client_id",
    "safe_json_parse",
    "validate_email_domain",
]
