"""OIDC Discovery pipeline.

1:1 port of ``reference/packages/sso/src/oidc/discovery.ts`` (+ the
``DiscoveryError`` class and ``REQUIRED_DISCOVERY_FIELDS`` from
``oidc/types.ts``).

Network access is funnelled through the module-level :func:`better_fetch`,
which mirrors ``@better-fetch/fetch``'s ``{ data, error }`` return contract.
Tests monkeypatch :func:`better_fetch`. URL parsing replicates the WHATWG
``new URL()`` semantics closely enough for the discovery surface: a scheme is
required, only ``http``/``https`` are accepted, and relative endpoints are
resolved against the issuer's origin + base path.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

DEFAULT_DISCOVERY_TIMEOUT = 10000

REQUIRED_DISCOVERY_FIELDS = (
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
)


class DiscoveryError(Exception):
    """Custom error for OIDC discovery failures (mirrors the TS class)."""

    def __init__(
        self,
        code: str,
        message: str,
        details: dict[str, Any] | None = None,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(message)
        self.name = "DiscoveryError"
        self.code = code
        self.message = message
        self.details = details
        if cause is not None:
            self.__cause__ = cause


@dataclass
class FetchResult:
    """Mirror of ``@better-fetch/fetch``'s ``{ data, error }`` response."""

    data: Any = None
    error: dict[str, Any] | None = None


def better_fetch(url: str, timeout: int = DEFAULT_DISCOVERY_TIMEOUT) -> FetchResult:
    """HTTP GET shim mirroring ``betterFetch``.

    Tests monkeypatch this. The default implementation performs a real request
    so the runtime pipeline works; the function returns a :class:`FetchResult`
    and raises an ``AbortError``-named exception on timeout (matching the TS
    timeout contract handled by :func:`fetch_discovery_document`).
    """
    import httpx

    try:
        response = httpx.get(url, timeout=timeout / 1000)
    except httpx.TimeoutException as exc:  # surface as AbortError-style
        err = TimeoutError("The operation was aborted")
        err.name = "AbortError"  # type: ignore[attr-defined]
        raise err from exc

    if response.status_code >= 400:
        return FetchResult(
            data=None,
            error={
                "status": response.status_code,
                "statusText": response.reason_phrase,
                "message": response.text[:200],
            },
        )
    try:
        return FetchResult(data=response.json(), error=None)
    except ValueError:
        return FetchResult(data=response.text, error=None)


# --------------------------------------------------------------------------- #
# URL helpers
# --------------------------------------------------------------------------- #
class _ParsedURL:
    __slots__ = ("scheme", "netloc", "path", "_raw")

    def __init__(self, scheme: str, netloc: str, path: str, raw: str) -> None:
        self.scheme = scheme
        self.netloc = netloc
        self.path = path
        self._raw = raw

    @property
    def hostname(self) -> str:
        host = self.netloc
        if "@" in host:
            host = host.rsplit("@", 1)[1]
        if host.startswith("["):  # IPv6 literal
            return host[: host.index("]") + 1]
        if ":" in host:
            host = host.rsplit(":", 1)[0]
        return host

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.netloc}"

    @property
    def protocol(self) -> str:
        return f"{self.scheme}:"

    def to_string(self) -> str:
        return self._raw


def _parse_url(name: str, endpoint: str, base: str | None = None) -> _ParsedURL:
    """Parse ``endpoint`` (optionally against ``base``), enforcing http(s).

    Mirrors the TS ``parseURL``: throws ``discovery_invalid_url`` for malformed
    URLs and for non-http(s) schemes.
    """
    resolved = urljoin(base, endpoint) if base else endpoint
    split = urlsplit(resolved)

    if split.scheme not in ("http", "https") or not split.netloc:
        if split.scheme in ("http", "https"):
            # Parsed but missing authority -> treat as protocol error path only
            # when scheme present; otherwise invalid URL.
            raise DiscoveryError(
                "discovery_invalid_url",
                f'The url "{name}" must be valid: {endpoint}',
                {"url": endpoint},
            )
        if split.scheme:
            raise DiscoveryError(
                "discovery_invalid_url",
                (
                    f'The url "{name}" must use the http or https supported '
                    f"protocols: {endpoint}"
                ),
                {"url": endpoint, "protocol": f"{split.scheme}:"},
            )
        raise DiscoveryError(
            "discovery_invalid_url",
            f'The url "{name}" must be valid: {endpoint}',
            {"url": endpoint},
        )

    return _ParsedURL(split.scheme, split.netloc, split.path, resolved)


def normalize_url(name: str, endpoint: str, issuer: str) -> str:
    """Normalize a single endpoint, resolving relative URLs against the issuer."""
    try:
        return _parse_url(name, endpoint).to_string()
    except DiscoveryError:
        # endpoint may be relative -> resolve against the issuer origin + base.
        issuer_url = _parse_url(name, issuer)
        base_path = re.sub(r"/+$", "", issuer_url.path)
        endpoint_path = re.sub(r"^/+", "", endpoint)
        full = f"{base_path}/{endpoint_path}"
        return _parse_url(name, full, issuer_url.origin).to_string()


def _normalize_and_validate_url(
    name: str, endpoint: str, issuer: str, is_trusted_origin: Callable[[str], bool]
) -> str:
    url = normalize_url(name, endpoint, issuer)
    if not is_trusted_origin(url):
        raise DiscoveryError(
            "discovery_untrusted_origin",
            f'The {name} "{url}" is not trusted by your trusted origins configuration.',
            {"endpoint": name, "url": url},
        )
    return url


# --------------------------------------------------------------------------- #
# Pipeline
# --------------------------------------------------------------------------- #
def compute_discovery_url(issuer: str) -> str:
    """Compute ``<issuer>/.well-known/openid-configuration`` (trailing-slash safe)."""
    base_url = issuer[:-1] if issuer.endswith("/") else issuer
    return f"{base_url}/.well-known/openid-configuration"


def validate_discovery_url(
    url: str, is_trusted_origin: Callable[[str], bool]
) -> None:
    """Validate the main discovery URL before fetching."""
    discovery_endpoint = _parse_url("discoveryEndpoint", url).to_string()
    if not is_trusted_origin(discovery_endpoint):
        raise DiscoveryError(
            "discovery_untrusted_origin",
            (
                f'The main discovery endpoint "{discovery_endpoint}" is not '
                "trusted by your trusted origins configuration."
            ),
            {"url": discovery_endpoint},
        )


def fetch_discovery_document(
    url: str, timeout: int = DEFAULT_DISCOVERY_TIMEOUT
) -> dict[str, Any]:
    """Fetch + parse the discovery document, mapping failures to DiscoveryError."""
    try:
        response = better_fetch(url, timeout=timeout)

        if response.error:
            status = response.error.get("status")

            if status == 404:
                raise DiscoveryError(
                    "discovery_not_found",
                    "Discovery endpoint not found",
                    {"url": url, "status": status},
                )

            if status == 408:
                raise DiscoveryError(
                    "discovery_timeout",
                    "Discovery request timed out",
                    {"url": url, "timeout": timeout},
                )

            status_text = response.error.get("statusText", "")
            raise DiscoveryError(
                "discovery_unexpected_error",
                f"Unexpected discovery error: {status_text}",
                {"url": url, **response.error},
            )

        if response.data is None:
            raise DiscoveryError(
                "discovery_invalid_json",
                "Discovery endpoint returned an empty response",
                {"url": url},
            )

        data = response.data
        if isinstance(data, str):
            raise DiscoveryError(
                "discovery_invalid_json",
                "Discovery endpoint returned invalid JSON",
                {"url": url, "bodyPreview": data[:200]},
            )

        return data
    except DiscoveryError:
        raise
    except BaseException as error:  # - mirror TS broad catch
        # betterFetch raises an AbortError-named error on timeout.
        if getattr(error, "name", None) == "AbortError":
            raise DiscoveryError(
                "discovery_timeout",
                "Discovery request timed out",
                {"url": url, "timeout": timeout},
            ) from error
        raise DiscoveryError(
            "discovery_unexpected_error",
            f"Unexpected error during discovery: {error}",
            {"url": url},
            cause=error,
        ) from error


def validate_discovery_document(doc: dict[str, Any], configured_issuer: str) -> None:
    """Ensure required fields present and the issuer matches (trailing-slash safe)."""
    missing_fields = [field_ for field_ in REQUIRED_DISCOVERY_FIELDS if not doc.get(field_)]

    if missing_fields:
        raise DiscoveryError(
            "discovery_incomplete",
            f"Discovery document is missing required fields: {', '.join(missing_fields)}",
            {"missingFields": missing_fields},
        )

    discovered_issuer = doc["issuer"]
    discovered_issuer = (
        discovered_issuer[:-1] if discovered_issuer.endswith("/") else discovered_issuer
    )
    expected_issuer = (
        configured_issuer[:-1]
        if configured_issuer.endswith("/")
        else configured_issuer
    )

    if discovered_issuer != expected_issuer:
        raise DiscoveryError(
            "issuer_mismatch",
            (
                f'Discovered issuer "{doc["issuer"]}" does not match configured '
                f'issuer "{configured_issuer}"'
            ),
            {"discovered": doc["issuer"], "configured": configured_issuer},
        )


def normalize_discovery_urls(
    document: dict[str, Any],
    issuer: str,
    is_trusted_origin: Callable[[str], bool],
) -> dict[str, Any]:
    """Resolve + trust-check every present endpoint URL in the document."""
    doc = dict(document)

    doc["token_endpoint"] = _normalize_and_validate_url(
        "token_endpoint", doc["token_endpoint"], issuer, is_trusted_origin
    )
    doc["authorization_endpoint"] = _normalize_and_validate_url(
        "authorization_endpoint",
        doc["authorization_endpoint"],
        issuer,
        is_trusted_origin,
    )
    doc["jwks_uri"] = _normalize_and_validate_url(
        "jwks_uri", doc["jwks_uri"], issuer, is_trusted_origin
    )

    if doc.get("userinfo_endpoint"):
        doc["userinfo_endpoint"] = _normalize_and_validate_url(
            "userinfo_endpoint", doc["userinfo_endpoint"], issuer, is_trusted_origin
        )
    if doc.get("revocation_endpoint"):
        doc["revocation_endpoint"] = _normalize_and_validate_url(
            "revocation_endpoint", doc["revocation_endpoint"], issuer, is_trusted_origin
        )
    if doc.get("end_session_endpoint"):
        doc["end_session_endpoint"] = _normalize_and_validate_url(
            "end_session_endpoint",
            doc["end_session_endpoint"],
            issuer,
            is_trusted_origin,
        )
    if doc.get("introspection_endpoint"):
        doc["introspection_endpoint"] = _normalize_and_validate_url(
            "introspection_endpoint",
            doc["introspection_endpoint"],
            issuer,
            is_trusted_origin,
        )

    return doc


def select_token_endpoint_auth_method(
    doc: dict[str, Any], existing: str | None = None
) -> str:
    """Pick the token endpoint auth method (basic preferred; basic fallback)."""
    if existing:
        return existing

    supported = doc.get("token_endpoint_auth_methods_supported")
    if not supported:
        return "client_secret_basic"
    if "client_secret_basic" in supported:
        return "client_secret_basic"
    if "client_secret_post" in supported:
        return "client_secret_post"
    return "client_secret_basic"


def needs_runtime_discovery(config: dict[str, Any] | None) -> bool:
    """True when stored config lacks token/jwks/authorization endpoints."""
    if not config:
        return True
    return (
        not config.get("tokenEndpoint")
        or not config.get("jwksEndpoint")
        or not config.get("authorizationEndpoint")
    )


@dataclass
class DiscoverOIDCConfigParams:
    issuer: str
    is_trusted_origin: Callable[[str], bool]
    existing_config: dict[str, Any] | None = None
    discovery_endpoint: str | None = None
    timeout: int = DEFAULT_DISCOVERY_TIMEOUT


def discover_oidc_config(
    params: DiscoverOIDCConfigParams | None = None,
    *,
    issuer: str | None = None,
    is_trusted_origin: Callable[[str], bool] | None = None,
    existing_config: dict[str, Any] | None = None,
    discovery_endpoint: str | None = None,
    timeout: int = DEFAULT_DISCOVERY_TIMEOUT,
) -> dict[str, Any]:
    """Discover and hydrate OIDC configuration from an issuer.

    Accepts either a :class:`DiscoverOIDCConfigParams` or keyword arguments
    (mirroring the TS single-object parameter).
    """
    if params is not None:
        issuer = params.issuer
        is_trusted_origin = params.is_trusted_origin
        existing_config = params.existing_config
        discovery_endpoint = params.discovery_endpoint
        timeout = params.timeout

    assert issuer is not None
    assert is_trusted_origin is not None
    existing = existing_config or {}

    discovery_url = (
        discovery_endpoint
        or existing.get("discoveryEndpoint")
        or compute_discovery_url(issuer)
    )

    validate_discovery_url(discovery_url, is_trusted_origin)

    discovery_doc = fetch_discovery_document(discovery_url, timeout)

    validate_discovery_document(discovery_doc, issuer)

    normalized_doc = normalize_discovery_urls(discovery_doc, issuer, is_trusted_origin)

    token_endpoint_auth = select_token_endpoint_auth_method(
        normalized_doc, existing.get("tokenEndpointAuthentication")
    )

    def pick(existing_key: str, doc_value: Any) -> Any:
        value = existing.get(existing_key)
        return value if value is not None else doc_value

    return {
        "issuer": pick("issuer", normalized_doc["issuer"]),
        "discoveryEndpoint": pick("discoveryEndpoint", discovery_url),
        "authorizationEndpoint": pick(
            "authorizationEndpoint", normalized_doc["authorization_endpoint"]
        ),
        "tokenEndpoint": pick("tokenEndpoint", normalized_doc["token_endpoint"]),
        "jwksEndpoint": pick("jwksEndpoint", normalized_doc["jwks_uri"]),
        "userInfoEndpoint": pick(
            "userInfoEndpoint", normalized_doc.get("userinfo_endpoint")
        ),
        "tokenEndpointAuthentication": pick(
            "tokenEndpointAuthentication", token_endpoint_auth
        ),
        "scopesSupported": pick(
            "scopesSupported", normalized_doc.get("scopes_supported")
        ),
    }


async def ensure_runtime_discovery(
    config: dict[str, Any],
    issuer: str,
    is_trusted_origin: Callable[[str], bool],
) -> dict[str, Any]:
    """Hydrate missing endpoints via discovery, preserving existing fields."""
    if not needs_runtime_discovery(config):
        return config
    hydrated = discover_oidc_config(
        issuer=issuer, existing_config=config, is_trusted_origin=is_trusted_origin
    )
    return {
        **config,
        "authorizationEndpoint": hydrated["authorizationEndpoint"],
        "tokenEndpoint": hydrated["tokenEndpoint"],
        "tokenEndpointAuthentication": hydrated["tokenEndpointAuthentication"],
        "userInfoEndpoint": hydrated["userInfoEndpoint"],
        "jwksEndpoint": hydrated["jwksEndpoint"],
    }


__all__ = [
    "DEFAULT_DISCOVERY_TIMEOUT",
    "REQUIRED_DISCOVERY_FIELDS",
    "DiscoverOIDCConfigParams",
    "DiscoveryError",
    "FetchResult",
    "better_fetch",
    "compute_discovery_url",
    "discover_oidc_config",
    "ensure_runtime_discovery",
    "fetch_discovery_document",
    "needs_runtime_discovery",
    "normalize_discovery_urls",
    "normalize_url",
    "select_token_endpoint_auth_method",
    "validate_discovery_document",
    "validate_discovery_url",
]
