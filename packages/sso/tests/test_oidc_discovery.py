"""1:1 port of reference/packages/sso/src/oidc/discovery.test.ts.

The TS suite mocks ``@better-fetch/fetch``'s ``betterFetch``. The Python port
monkeypatches the module-level :func:`better_fetch`, which returns a
:class:`FetchResult` (the ``{ data, error }`` contract). ``isTrustedOrigin``
predicates are passed through unchanged.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from kernia_sso import oidc_discovery as disc
from kernia_sso.oidc_discovery import (
    DiscoveryError,
    FetchResult,
    compute_discovery_url,
    discover_oidc_config,
    ensure_runtime_discovery,
    fetch_discovery_document,
    needs_runtime_discovery,
    normalize_discovery_urls,
    normalize_url,
    select_token_endpoint_auth_method,
    validate_discovery_document,
    validate_discovery_url,
)


def create_mock_discovery_document(**overrides: Any) -> dict[str, Any]:
    doc = {
        "issuer": "https://idp.example.com",
        "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
        "token_endpoint": "https://idp.example.com/oauth2/token",
        "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
        "userinfo_endpoint": "https://idp.example.com/userinfo",
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
        ],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "response_types_supported": ["code", "token", "id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "claims_supported": ["sub", "name", "email", "email_verified"],
    }
    doc.update(overrides)
    return doc


def _always_trusted(_url: str) -> bool:
    return True


class _FetchQueue:
    """Mimics vitest ``mockResolvedValueOnce`` / ``mockRejectedValueOnce``."""

    def __init__(self) -> None:
        self.results: list[Any] = []
        self.default: Any = None
        self.calls: list[tuple[str, int]] = []

    def push(self, result: Any) -> None:
        self.results.append(result)

    def __call__(self, url: str, timeout: int = disc.DEFAULT_DISCOVERY_TIMEOUT) -> FetchResult:
        self.calls.append((url, timeout))
        item = self.results.pop(0) if self.results else self.default
        if isinstance(item, BaseException):
            raise item
        if item is None:
            raise AssertionError("fetch queue exhausted")
        return item


@pytest.fixture
def fetch_queue(monkeypatch: pytest.MonkeyPatch) -> _FetchQueue:
    q = _FetchQueue()
    monkeypatch.setattr(disc, "better_fetch", q)
    return q


# --------------------------------------------------------------------------- #
# computeDiscoveryUrl
# --------------------------------------------------------------------------- #
class TestComputeDiscoveryUrl:
    def test_without_trailing_slash(self) -> None:
        assert (
            compute_discovery_url("https://idp.example.com")
            == "https://idp.example.com/.well-known/openid-configuration"
        )

    def test_with_trailing_slash(self) -> None:
        assert (
            compute_discovery_url("https://idp.example.com/")
            == "https://idp.example.com/.well-known/openid-configuration"
        )

    def test_issuer_with_path(self) -> None:
        assert (
            compute_discovery_url("https://idp.example.com/tenant/v1")
            == "https://idp.example.com/tenant/v1/.well-known/openid-configuration"
        )

    def test_issuer_with_path_and_trailing_slash(self) -> None:
        assert (
            compute_discovery_url("https://idp.example.com/tenant/v1/")
            == "https://idp.example.com/tenant/v1/.well-known/openid-configuration"
        )


# --------------------------------------------------------------------------- #
# validateDiscoveryUrl
# --------------------------------------------------------------------------- #
class TestValidateDiscoveryUrl:
    def test_accept_valid_https(self) -> None:
        validate_discovery_url(
            "https://idp.example.com/.well-known/openid-configuration",
            _always_trusted,
        )

    def test_accept_valid_http(self) -> None:
        validate_discovery_url(
            "http://localhost:8080/.well-known/openid-configuration",
            _always_trusted,
        )

    def test_reject_invalid_url(self) -> None:
        with pytest.raises(DiscoveryError):
            validate_discovery_url("not-a-url", _always_trusted)
        with pytest.raises(
            DiscoveryError, match='The url "discoveryEndpoint" must be valid'
        ):
            validate_discovery_url("not-a-url", _always_trusted)

    def test_reject_non_http_protocols(self) -> None:
        with pytest.raises(DiscoveryError):
            validate_discovery_url("ftp://example.com/config", _always_trusted)
        with pytest.raises(
            DiscoveryError, match="must use the http or https supported protocols"
        ):
            validate_discovery_url("ftp://example.com/config", _always_trusted)

    def test_invalid_url_code_and_details(self) -> None:
        with pytest.raises(DiscoveryError) as exc:
            validate_discovery_url("not-a-url", _always_trusted)
        assert exc.value.code == "discovery_invalid_url"
        assert exc.value.details["url"] == "not-a-url"

    def test_non_http_protocol_code_and_details(self) -> None:
        with pytest.raises(DiscoveryError) as exc:
            validate_discovery_url("ftp://example.com/config", _always_trusted)
        assert exc.value.code == "discovery_invalid_url"
        assert exc.value.details["protocol"] == "ftp:"

    def test_untrusted_origin(self) -> None:
        with pytest.raises(DiscoveryError) as exc:
            validate_discovery_url(
                "https://untrusted.com/.well-known/openid-configuration",
                lambda _url: False,
            )
        assert exc.value.code == "discovery_untrusted_origin"
        assert exc.value.message == (
            'The main discovery endpoint "https://untrusted.com/.well-known/'
            'openid-configuration" is not trusted by your trusted origins '
            "configuration."
        )


# --------------------------------------------------------------------------- #
# validateDiscoveryDocument
# --------------------------------------------------------------------------- #
class TestValidateDiscoveryDocument:
    issuer = "https://idp.example.com"

    def test_accept_valid_document(self) -> None:
        validate_discovery_document(create_mock_discovery_document(), self.issuer)

    def test_accept_only_required_fields(self) -> None:
        doc = {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/authorize",
            "token_endpoint": f"{self.issuer}/token",
            "jwks_uri": f"{self.issuer}/jwks",
        }
        validate_discovery_document(doc, self.issuer)

    def test_incomplete_missing_issuer(self) -> None:
        with pytest.raises(DiscoveryError) as exc:
            validate_discovery_document(
                create_mock_discovery_document(issuer=""), self.issuer
            )
        assert exc.value.code == "discovery_incomplete"
        assert "issuer" in exc.value.details["missingFields"]

    def test_incomplete_missing_authorization_endpoint(self) -> None:
        with pytest.raises(DiscoveryError) as exc:
            validate_discovery_document(
                create_mock_discovery_document(authorization_endpoint=""), self.issuer
            )
        assert exc.value.code == "discovery_incomplete"
        assert "authorization_endpoint" in exc.value.details["missingFields"]

    def test_incomplete_missing_token_endpoint(self) -> None:
        with pytest.raises(DiscoveryError) as exc:
            validate_discovery_document(
                create_mock_discovery_document(token_endpoint=""), self.issuer
            )
        assert exc.value.code == "discovery_incomplete"
        assert "token_endpoint" in exc.value.details["missingFields"]

    def test_incomplete_missing_jwks_uri(self) -> None:
        with pytest.raises(DiscoveryError) as exc:
            validate_discovery_document(
                create_mock_discovery_document(jwks_uri=""), self.issuer
            )
        assert exc.value.code == "discovery_incomplete"
        assert "jwks_uri" in exc.value.details["missingFields"]

    def test_list_all_missing_fields(self) -> None:
        doc = {
            "issuer": "",
            "authorization_endpoint": "",
            "token_endpoint": "",
            "jwks_uri": "",
        }
        with pytest.raises(DiscoveryError) as exc:
            validate_discovery_document(doc, self.issuer)
        assert exc.value.code == "discovery_incomplete"
        for f in (
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
        ):
            assert f in exc.value.details["missingFields"]

    def test_issuer_mismatch(self) -> None:
        with pytest.raises(DiscoveryError) as exc:
            validate_discovery_document(
                create_mock_discovery_document(issuer="https://evil.example.com"),
                self.issuer,
            )
        assert exc.value.code == "issuer_mismatch"
        assert exc.value.details["discovered"] == "https://evil.example.com"
        assert exc.value.details["configured"] == self.issuer

    def test_trailing_slash_normalization_in_discovered(self) -> None:
        validate_discovery_document(
            create_mock_discovery_document(issuer="https://idp.example.com/"),
            "https://idp.example.com",
        )

    def test_trailing_slash_in_configured_issuer(self) -> None:
        validate_discovery_document(
            create_mock_discovery_document(issuer="https://idp.example.com"),
            "https://idp.example.com/",
        )


# --------------------------------------------------------------------------- #
# selectTokenEndpointAuthMethod
# --------------------------------------------------------------------------- #
class TestSelectTokenEndpointAuthMethod:
    def test_return_existing_config_value(self) -> None:
        assert (
            select_token_endpoint_auth_method(
                create_mock_discovery_document(), "client_secret_post"
            )
            == "client_secret_post"
        )

    def test_prefer_basic_when_both_supported(self) -> None:
        doc = create_mock_discovery_document(
            token_endpoint_auth_methods_supported=[
                "client_secret_post",
                "client_secret_basic",
            ]
        )
        assert select_token_endpoint_auth_method(doc) == "client_secret_basic"

    def test_use_post_if_only_supported(self) -> None:
        doc = create_mock_discovery_document(
            token_endpoint_auth_methods_supported=["client_secret_post"]
        )
        assert select_token_endpoint_auth_method(doc) == "client_secret_post"

    def test_default_basic_when_only_unsupported(self) -> None:
        doc = create_mock_discovery_document(
            token_endpoint_auth_methods_supported=["private_key_jwt"]
        )
        assert select_token_endpoint_auth_method(doc) == "client_secret_basic"

    def test_default_basic_for_tls_client_auth_only(self) -> None:
        doc = create_mock_discovery_document(
            token_endpoint_auth_methods_supported=["tls_client_auth", "private_key_jwt"]
        )
        assert select_token_endpoint_auth_method(doc) == "client_secret_basic"

    def test_default_basic_if_not_specified(self) -> None:
        doc = create_mock_discovery_document(
            token_endpoint_auth_methods_supported=None
        )
        assert select_token_endpoint_auth_method(doc) == "client_secret_basic"

    def test_default_basic_for_empty_array(self) -> None:
        doc = create_mock_discovery_document(token_endpoint_auth_methods_supported=[])
        assert select_token_endpoint_auth_method(doc) == "client_secret_basic"


# --------------------------------------------------------------------------- #
# normalizeDiscoveryUrls
# --------------------------------------------------------------------------- #
class TestNormalizeDiscoveryUrls:
    def test_unchanged_if_all_absolute(self) -> None:
        doc = create_mock_discovery_document()
        result = normalize_discovery_urls(doc, "https://idp.example.com", _always_trusted)
        assert result == doc

    def test_resolve_required_urls_relative(self) -> None:
        expected = create_mock_discovery_document(
            issuer="https://idp.example.com",
            authorization_endpoint="https://idp.example.com/oauth2/authorize",
            token_endpoint="https://idp.example.com/oauth2/token",
            jwks_uri="https://idp.example.com/.well-known/jwks.json",
        )
        doc = create_mock_discovery_document(
            issuer="https://idp.example.com",
            authorization_endpoint="/oauth2/authorize",
            token_endpoint="/oauth2/token",
            jwks_uri="/.well-known/jwks.json",
        )
        result = normalize_discovery_urls(doc, "https://idp.example.com", _always_trusted)
        assert result == expected

    def test_resolve_all_urls_relative(self) -> None:
        expected = create_mock_discovery_document(
            issuer="https://idp.example.com",
            authorization_endpoint="https://idp.example.com/oauth2/authorize",
            token_endpoint="https://idp.example.com/oauth2/token",
            jwks_uri="https://idp.example.com/.well-known/jwks.json",
            userinfo_endpoint="https://idp.example.com/userinfo",
            revocation_endpoint="https://idp.example.com/revoke",
        )
        doc = create_mock_discovery_document(
            issuer="https://idp.example.com",
            authorization_endpoint="/oauth2/authorize",
            token_endpoint="/oauth2/token",
            jwks_uri="/.well-known/jwks.json",
            userinfo_endpoint="/userinfo",
            revocation_endpoint="/revoke",
        )
        result = normalize_discovery_urls(doc, "https://idp.example.com", _always_trusted)
        assert result == expected

    def test_reject_invalid_discovery_urls(self) -> None:
        doc = create_mock_discovery_document(authorization_endpoint="/oauth2/authorize")
        with pytest.raises(
            DiscoveryError, match='The url "authorization_endpoint" must be valid'
        ):
            normalize_discovery_urls(doc, "not-url", _always_trusted)

    def test_reject_untrusted_discovery_urls(self) -> None:
        doc = create_mock_discovery_document(
            authorization_endpoint="/oauth2/authorize",
            token_endpoint="/oauth2/token",
            jwks_uri="/.well-known/jwks.json",
            userinfo_endpoint="/userinfo",
            revocation_endpoint="/revoke",
            end_session_endpoint="/endsession",
            introspection_endpoint="/introspection",
        )
        issuer = "https://idp.example.com"

        cases: list[tuple[Callable[[str], bool], str, str, str]] = [
            (
                lambda url: not url.endswith("/oauth2/token"),
                "token_endpoint",
                f"{issuer}/oauth2/token",
                'The token_endpoint "https://idp.example.com/oauth2/token" is not '
                "trusted by your trusted origins configuration.",
            ),
            (
                lambda url: not url.endswith("/oauth2/authorize"),
                "authorization_endpoint",
                f"{issuer}/oauth2/authorize",
                'The authorization_endpoint "https://idp.example.com/oauth2/authorize"'
                " is not trusted by your trusted origins configuration.",
            ),
            (
                lambda url: not url.endswith("/.well-known/jwks.json"),
                "jwks_uri",
                f"{issuer}/.well-known/jwks.json",
                'The jwks_uri "https://idp.example.com/.well-known/jwks.json" is not '
                "trusted by your trusted origins configuration.",
            ),
            (
                lambda url: not url.endswith("/userinfo"),
                "userinfo_endpoint",
                f"{issuer}/userinfo",
                'The userinfo_endpoint "https://idp.example.com/userinfo" is not '
                "trusted by your trusted origins configuration.",
            ),
            (
                lambda url: not url.endswith("/revoke"),
                "revocation_endpoint",
                f"{issuer}/revoke",
                'The revocation_endpoint "https://idp.example.com/revoke" is not '
                "trusted by your trusted origins configuration.",
            ),
            (
                lambda url: not url.endswith("/endsession"),
                "end_session_endpoint",
                f"{issuer}/endsession",
                'The end_session_endpoint "https://idp.example.com/endsession" is not '
                "trusted by your trusted origins configuration.",
            ),
            (
                lambda url: not url.endswith("/introspection"),
                "introspection_endpoint",
                f"{issuer}/introspection",
                'The introspection_endpoint "https://idp.example.com/introspection" is'
                " not trusted by your trusted origins configuration.",
            ),
        ]

        for predicate, endpoint_name, url, message in cases:
            with pytest.raises(DiscoveryError) as exc:
                normalize_discovery_urls(doc, issuer, predicate)
            assert exc.value.code == "discovery_untrusted_origin"
            assert exc.value.message == message
            assert exc.value.details == {"endpoint": endpoint_name, "url": url}


# --------------------------------------------------------------------------- #
# normalizeUrl
# --------------------------------------------------------------------------- #
class TestNormalizeUrl:
    def test_unchanged_if_already_absolute(self) -> None:
        endpoint = "https://idp.example.com/oauth2/token"
        assert normalize_url("url", endpoint, "https://idp.example.com") == endpoint

    def test_return_endpoint_as_absolute(self) -> None:
        assert (
            normalize_url("url", "/oauth2/token", "https://idp.example.com")
            == "https://idp.example.com/oauth2/token"
        )

    @pytest.mark.parametrize(
        ("endpoint", "issuer"),
        [
            ("/oauth2/token", "https://idp.example.com/base"),
            ("oauth2/token", "https://idp.example.com/base"),
            ("/oauth2/token", "https://idp.example.com/base/"),
            ("//oauth2/token", "https://idp.example.com/base//"),
        ],
    )
    def test_resolve_relative_preserving_base_path(
        self, endpoint: str, issuer: str
    ) -> None:
        assert (
            normalize_url("url", endpoint, issuer)
            == "https://idp.example.com/base/oauth2/token"
        )

    def test_reject_invalid_endpoint_urls(self) -> None:
        with pytest.raises(DiscoveryError, match='The url "url" must be valid'):
            normalize_url("url", "oauth2/token", "not-a-url")

    def test_reject_unsupported_protocols(self) -> None:
        with pytest.raises(
            DiscoveryError,
            match='The url "url" must use the http or https supported protocols',
        ):
            normalize_url("url", "not-a-url", "ftp://idp.example.com")


# --------------------------------------------------------------------------- #
# needsRuntimeDiscovery
# --------------------------------------------------------------------------- #
class TestNeedsRuntimeDiscovery:
    def test_undefined_config(self) -> None:
        assert needs_runtime_discovery(None) is True

    def test_empty_config(self) -> None:
        assert needs_runtime_discovery({}) is True

    def test_missing_token_endpoint(self) -> None:
        assert (
            needs_runtime_discovery(
                {"jwksEndpoint": "https://idp.example.com/.well-known/jwks.json"}
            )
            is True
        )

    def test_missing_jwks_endpoint(self) -> None:
        assert (
            needs_runtime_discovery(
                {"tokenEndpoint": "https://idp.example.com/oauth2/token"}
            )
            is True
        )

    def test_all_present_returns_false(self) -> None:
        assert (
            needs_runtime_discovery(
                {
                    "tokenEndpoint": "https://idp.example.com/oauth2/token",
                    "jwksEndpoint": "https://idp.example.com/.well-known/jwks.json",
                    "authorizationEndpoint": "https://idp.example.com/oauth2/authorize",
                }
            )
            is False
        )

    def test_missing_authorization_endpoint(self) -> None:
        assert (
            needs_runtime_discovery(
                {
                    "tokenEndpoint": "https://idp.example.com/oauth2/token",
                    "jwksEndpoint": "https://idp.example.com/.well-known/jwks.json",
                }
            )
            is True
        )


# --------------------------------------------------------------------------- #
# fetchDiscoveryDocument
# --------------------------------------------------------------------------- #
DISC_URL = "https://idp.example.com/.well-known/openid-configuration"


class TestFetchDiscoveryDocument:
    def test_fetch_and_parse_valid(self, fetch_queue: _FetchQueue) -> None:
        expected = create_mock_discovery_document()
        fetch_queue.push(FetchResult(data=expected, error=None))
        result = fetch_discovery_document(DISC_URL)
        assert result["issuer"] == expected["issuer"]
        assert result["authorization_endpoint"] == expected["authorization_endpoint"]
        assert result["token_endpoint"] == expected["token_endpoint"]
        assert result["jwks_uri"] == expected["jwks_uri"]
        assert fetch_queue.calls[0][0] == DISC_URL

    def test_not_found_404(self, fetch_queue: _FetchQueue) -> None:
        fetch_queue.push(
            FetchResult(data=None, error={"status": 404, "message": "Not Found"})
        )
        with pytest.raises(DiscoveryError) as exc:
            fetch_discovery_document(DISC_URL)
        assert exc.value.code == "discovery_not_found"

    def test_timeout_on_abort_error(self, fetch_queue: _FetchQueue) -> None:
        abort_error = TimeoutError("The operation was aborted")
        abort_error.name = "AbortError"  # type: ignore[attr-defined]
        fetch_queue.push(abort_error)
        with pytest.raises(DiscoveryError) as exc:
            fetch_discovery_document(DISC_URL, 100)
        assert exc.value.code == "discovery_timeout"

    def test_timeout_on_http_408(self, fetch_queue: _FetchQueue) -> None:
        fetch_queue.push(
            FetchResult(
                data=None,
                error={"status": 408, "statusText": "Request Timeout", "message": ""},
            )
        )
        with pytest.raises(DiscoveryError) as exc:
            fetch_discovery_document(DISC_URL, 100)
        assert exc.value.code == "discovery_timeout"

    def test_unexpected_error_for_server_errors(self, fetch_queue: _FetchQueue) -> None:
        fetch_queue.push(
            FetchResult(
                data=None,
                error={"status": 500, "message": "Internal Server Error"},
            )
        )
        with pytest.raises(DiscoveryError) as exc:
            fetch_discovery_document(DISC_URL)
        assert exc.value.code == "discovery_unexpected_error"

    def test_invalid_json_for_empty_response(self, fetch_queue: _FetchQueue) -> None:
        fetch_queue.push(FetchResult(data=None, error=None))
        with pytest.raises(DiscoveryError) as exc:
            fetch_discovery_document(DISC_URL)
        assert exc.value.code == "discovery_invalid_json"

    def test_invalid_json_for_parse_errors(self, fetch_queue: _FetchQueue) -> None:
        fetch_queue.push(
            FetchResult(data="<!DOCTYPE html><html>Not JSON</html>", error=None)
        )
        with pytest.raises(DiscoveryError) as exc:
            fetch_discovery_document(DISC_URL)
        assert exc.value.code == "discovery_invalid_json"
        assert exc.value.details["bodyPreview"] == "<!DOCTYPE html><html>Not JSON</html>"

    def test_unexpected_error_for_unknown_errors(self, fetch_queue: _FetchQueue) -> None:
        fetch_queue.push(RuntimeError("Network failure"))
        with pytest.raises(DiscoveryError) as exc:
            fetch_discovery_document(DISC_URL)
        assert exc.value.code == "discovery_unexpected_error"


# --------------------------------------------------------------------------- #
# discoverOIDCConfig (integration)
# --------------------------------------------------------------------------- #
class TestDiscoverOIDCConfigIntegration:
    issuer = "https://idp.example.com"

    def test_return_hydrated_config(self, fetch_queue: _FetchQueue) -> None:
        issuer = self.issuer
        fetch_queue.push(
            FetchResult(
                data=create_mock_discovery_document(
                    issuer=issuer,
                    authorization_endpoint=f"{issuer}/oauth2/authorize",
                    token_endpoint=f"{issuer}/oauth2/token",
                    jwks_uri=f"{issuer}/.well-known/jwks.json",
                    userinfo_endpoint=f"{issuer}/userinfo",
                ),
                error=None,
            )
        )
        result = discover_oidc_config(issuer=issuer, is_trusted_origin=_always_trusted)
        assert result["issuer"] == issuer
        assert result["authorizationEndpoint"] == f"{issuer}/oauth2/authorize"
        assert result["tokenEndpoint"] == f"{issuer}/oauth2/token"
        assert result["jwksEndpoint"] == f"{issuer}/.well-known/jwks.json"
        assert result["userInfoEndpoint"] == f"{issuer}/userinfo"
        assert (
            result["discoveryEndpoint"]
            == f"{issuer}/.well-known/openid-configuration"
        )
        assert result["tokenEndpointAuthentication"] == "client_secret_basic"

    def test_merge_existing_config_precedence(self, fetch_queue: _FetchQueue) -> None:
        issuer = self.issuer
        fetch_queue.push(
            FetchResult(
                data=create_mock_discovery_document(
                    issuer=issuer,
                    authorization_endpoint=f"{issuer}/oauth2/authorize",
                    token_endpoint=f"{issuer}/oauth2/token",
                    jwks_uri=f"{issuer}/.well-known/jwks.json",
                ),
                error=None,
            )
        )
        result = discover_oidc_config(
            issuer=issuer,
            existing_config={
                "tokenEndpoint": "https://custom.example.com/token",
                "tokenEndpointAuthentication": "client_secret_post",
            },
            is_trusted_origin=_always_trusted,
        )
        assert result["tokenEndpoint"] == "https://custom.example.com/token"
        assert result["tokenEndpointAuthentication"] == "client_secret_post"
        assert result["authorizationEndpoint"] == f"{issuer}/oauth2/authorize"
        assert result["jwksEndpoint"] == f"{issuer}/.well-known/jwks.json"

    def test_use_custom_discovery_endpoint(self, fetch_queue: _FetchQueue) -> None:
        issuer = self.issuer
        custom_endpoint = f"{issuer}/custom/.well-known/openid-configuration"
        fetch_queue.push(
            FetchResult(data=create_mock_discovery_document(issuer=issuer), error=None)
        )
        result = discover_oidc_config(
            issuer=issuer,
            discovery_endpoint=custom_endpoint,
            is_trusted_origin=_always_trusted,
        )
        assert result["discoveryEndpoint"] == custom_endpoint
        assert fetch_queue.calls[0][0] == custom_endpoint

    def test_use_discovery_endpoint_from_existing_config(
        self, fetch_queue: _FetchQueue
    ) -> None:
        issuer = self.issuer
        existing_endpoint = f"{issuer}/tenant/.well-known/openid-configuration"
        fetch_queue.push(
            FetchResult(data=create_mock_discovery_document(issuer=issuer), error=None)
        )
        result = discover_oidc_config(
            issuer=issuer,
            existing_config={"discoveryEndpoint": existing_endpoint},
            is_trusted_origin=_always_trusted,
        )
        assert result["discoveryEndpoint"] == existing_endpoint
        assert fetch_queue.calls[0][0] == existing_endpoint

    def test_throw_on_issuer_mismatch(self, fetch_queue: _FetchQueue) -> None:
        fetch_queue.push(
            FetchResult(
                data=create_mock_discovery_document(issuer="https://evil.example.com"),
                error=None,
            )
        )
        with pytest.raises(DiscoveryError) as exc:
            discover_oidc_config(issuer=self.issuer, is_trusted_origin=_always_trusted)
        assert exc.value.code == "issuer_mismatch"

    def test_throw_on_missing_required_fields(self, fetch_queue: _FetchQueue) -> None:
        issuer = self.issuer
        fetch_queue.push(
            FetchResult(
                data={
                    "issuer": issuer,
                    "authorization_endpoint": f"{issuer}/authorize",
                },
                error=None,
            )
        )
        with pytest.raises(DiscoveryError) as exc:
            discover_oidc_config(issuer=issuer, is_trusted_origin=_always_trusted)
        assert exc.value.code == "discovery_incomplete"

    def test_throw_not_found_when_endpoint_missing(
        self, fetch_queue: _FetchQueue
    ) -> None:
        fetch_queue.push(
            FetchResult(data=None, error={"status": 404, "message": "Not Found"})
        )
        with pytest.raises(DiscoveryError) as exc:
            discover_oidc_config(issuer=self.issuer, is_trusted_origin=_always_trusted)
        assert exc.value.code == "discovery_not_found"

    def test_include_scopes_supported(self, fetch_queue: _FetchQueue) -> None:
        issuer = self.issuer
        scopes = ["openid", "profile", "email", "offline_access", "custom"]
        fetch_queue.push(
            FetchResult(
                data=create_mock_discovery_document(issuer=issuer, scopes_supported=scopes),
                error=None,
            )
        )
        result = discover_oidc_config(issuer=issuer, is_trusted_origin=_always_trusted)
        assert result["scopesSupported"] == scopes

    def test_document_without_optional_fields(self, fetch_queue: _FetchQueue) -> None:
        issuer = self.issuer
        fetch_queue.push(
            FetchResult(
                data={
                    "issuer": issuer,
                    "authorization_endpoint": f"{issuer}/authorize",
                    "token_endpoint": f"{issuer}/token",
                    "jwks_uri": f"{issuer}/jwks",
                },
                error=None,
            )
        )
        result = discover_oidc_config(issuer=issuer, is_trusted_origin=_always_trusted)
        assert result["issuer"] == issuer
        assert result["authorizationEndpoint"] == f"{issuer}/authorize"
        assert result["tokenEndpoint"] == f"{issuer}/token"
        assert result["jwksEndpoint"] == f"{issuer}/jwks"
        assert result["userInfoEndpoint"] is None
        assert result["scopesSupported"] is None
        assert result["tokenEndpointAuthentication"] == "client_secret_basic"

    def test_keep_all_existing_config_fields(self, fetch_queue: _FetchQueue) -> None:
        issuer = self.issuer
        fetch_queue.push(
            FetchResult(data=create_mock_discovery_document(issuer=issuer), error=None)
        )
        result = discover_oidc_config(
            issuer=issuer,
            existing_config={
                "issuer": issuer,
                "discoveryEndpoint": "https://custom.example.com/.well-known/openid-configuration",
                "authorizationEndpoint": "https://custom.example.com/auth",
                "tokenEndpoint": "https://custom.example.com/token",
                "jwksEndpoint": "https://custom.example.com/jwks",
                "userInfoEndpoint": "https://custom.example.com/userinfo",
                "tokenEndpointAuthentication": "client_secret_post",
                "scopesSupported": ["openid", "profile"],
            },
            is_trusted_origin=_always_trusted,
        )
        assert result["issuer"] == issuer
        assert (
            result["discoveryEndpoint"]
            == "https://custom.example.com/.well-known/openid-configuration"
        )
        assert result["authorizationEndpoint"] == "https://custom.example.com/auth"
        assert result["tokenEndpoint"] == "https://custom.example.com/token"
        assert result["jwksEndpoint"] == "https://custom.example.com/jwks"
        assert result["userInfoEndpoint"] == "https://custom.example.com/userinfo"
        assert result["tokenEndpointAuthentication"] == "client_secret_post"
        assert result["scopesSupported"] == ["openid", "profile"]

    def test_default_basic_when_only_unsupported_methods(
        self, fetch_queue: _FetchQueue
    ) -> None:
        issuer = self.issuer
        fetch_queue.push(
            FetchResult(
                data={
                    "issuer": issuer,
                    "authorization_endpoint": f"{issuer}/authorize",
                    "token_endpoint": f"{issuer}/token",
                    "jwks_uri": f"{issuer}/jwks",
                    "token_endpoint_auth_methods_supported": ["private_key_jwt"],
                },
                error=None,
            )
        )
        result = discover_oidc_config(issuer=issuer, is_trusted_origin=_always_trusted)
        assert result["tokenEndpointAuthentication"] == "client_secret_basic"

    def test_fill_missing_fields_when_partial(self, fetch_queue: _FetchQueue) -> None:
        issuer = self.issuer
        fetch_queue.push(
            FetchResult(
                data=create_mock_discovery_document(
                    issuer=issuer,
                    authorization_endpoint=f"{issuer}/oauth2/authorize",
                    token_endpoint=f"{issuer}/oauth2/token",
                    jwks_uri=f"{issuer}/.well-known/jwks.json",
                    userinfo_endpoint=f"{issuer}/userinfo",
                ),
                error=None,
            )
        )
        result = discover_oidc_config(
            issuer=issuer,
            existing_config={"jwksEndpoint": "https://custom.example.com/jwks"},
            is_trusted_origin=_always_trusted,
        )
        assert result["jwksEndpoint"] == "https://custom.example.com/jwks"
        assert result["issuer"] == issuer
        assert result["authorizationEndpoint"] == f"{issuer}/oauth2/authorize"
        assert result["tokenEndpoint"] == f"{issuer}/oauth2/token"
        assert result["userInfoEndpoint"] == f"{issuer}/userinfo"
        assert result["tokenEndpointAuthentication"] == "client_secret_basic"

    def test_extra_unknown_fields_and_missing_optional(
        self, fetch_queue: _FetchQueue
    ) -> None:
        issuer = self.issuer
        fetch_queue.push(
            FetchResult(
                data={
                    "issuer": issuer,
                    "authorization_endpoint": f"{issuer}/authorize",
                    "token_endpoint": f"{issuer}/token",
                    "jwks_uri": f"{issuer}/jwks",
                    "x-vendor-feature": True,
                    "custom_logout_endpoint": f"{issuer}/logout",
                    "experimental_flags": {"feature_a": True, "feature_b": False},
                },
                error=None,
            )
        )
        result = discover_oidc_config(issuer=issuer, is_trusted_origin=_always_trusted)
        assert result["issuer"] == issuer
        assert result["authorizationEndpoint"] == f"{issuer}/authorize"
        assert result["tokenEndpoint"] == f"{issuer}/token"
        assert result["jwksEndpoint"] == f"{issuer}/jwks"
        assert result["userInfoEndpoint"] is None
        assert result["scopesSupported"] is None
        assert result["tokenEndpointAuthentication"] == "client_secret_basic"

    def test_untrusted_main_discovery_url(self, fetch_queue: _FetchQueue) -> None:
        with pytest.raises(DiscoveryError) as exc:
            discover_oidc_config(issuer=self.issuer, is_trusted_origin=lambda _u: False)
        assert exc.value.name == "DiscoveryError"
        assert exc.value.code == "discovery_untrusted_origin"
        assert exc.value.message == (
            'The main discovery endpoint "https://idp.example.com/.well-known/'
            'openid-configuration" is not trusted by your trusted origins '
            "configuration."
        )
        assert exc.value.details == {
            "url": "https://idp.example.com/.well-known/openid-configuration"
        }

    def test_untrusted_discovered_urls(self, fetch_queue: _FetchQueue) -> None:
        issuer = self.issuer

        def is_trusted(url: str) -> bool:
            return url.endswith(".well-known/openid-configuration")

        fetch_queue.push(
            FetchResult(
                data=create_mock_discovery_document(
                    issuer=issuer,
                    authorization_endpoint=f"{issuer}/oauth2/authorize",
                    token_endpoint=f"{issuer}/oauth2/token",
                    jwks_uri=f"{issuer}/.well-known/jwks.json",
                    userinfo_endpoint=f"{issuer}/userinfo",
                ),
                error=None,
            )
        )
        with pytest.raises(DiscoveryError) as exc:
            discover_oidc_config(issuer=issuer, is_trusted_origin=is_trusted)
        assert exc.value.name == "DiscoveryError"
        assert exc.value.code == "discovery_untrusted_origin"
        assert exc.value.message == (
            'The token_endpoint "https://idp.example.com/oauth2/token" is not '
            "trusted by your trusted origins configuration."
        )
        assert exc.value.details == {
            "endpoint": "token_endpoint",
            "url": "https://idp.example.com/oauth2/token",
        }


# --------------------------------------------------------------------------- #
# ensureRuntimeDiscovery
# --------------------------------------------------------------------------- #
class TestEnsureRuntimeDiscovery:
    issuer = "https://idp.example.com"

    @property
    def base_config(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "clientId": "client-id",
            "clientSecret": "client-secret",
            "pkce": True,
            "discoveryEndpoint": f"{self.issuer}/.well-known/openid-configuration",
        }

    @pytest.fixture
    def queue_default_doc(self, fetch_queue: _FetchQueue) -> _FetchQueue:
        fetch_queue.default = FetchResult(
            data=create_mock_discovery_document(), error=None
        )
        return fetch_queue

    @pytest.mark.anyio
    async def test_unchanged_when_not_needed(
        self, queue_default_doc: _FetchQueue
    ) -> None:
        complete = {
            **self.base_config,
            "authorizationEndpoint": f"{self.issuer}/oauth2/authorize",
            "tokenEndpoint": f"{self.issuer}/oauth2/token",
            "jwksEndpoint": f"{self.issuer}/.well-known/jwks.json",
        }
        result = await ensure_runtime_discovery(complete, self.issuer, _always_trusted)
        assert result is complete
        assert queue_default_doc.calls == []

    @pytest.mark.anyio
    async def test_hydrates_missing_endpoints(
        self, queue_default_doc: _FetchQueue
    ) -> None:
        doc = create_mock_discovery_document()
        result = await ensure_runtime_discovery(
            self.base_config, self.issuer, _always_trusted
        )
        assert result["authorizationEndpoint"] == doc["authorization_endpoint"]
        assert result["tokenEndpoint"] == doc["token_endpoint"]
        assert result["jwksEndpoint"] == doc["jwks_uri"]
        assert result["userInfoEndpoint"] == doc["userinfo_endpoint"]

    @pytest.mark.anyio
    async def test_preserves_existing_fields(
        self, queue_default_doc: _FetchQueue
    ) -> None:
        result = await ensure_runtime_discovery(
            self.base_config, self.issuer, _always_trusted
        )
        assert result["clientId"] == "client-id"
        assert result["clientSecret"] == "client-secret"
        assert result["pkce"] is True

    @pytest.mark.anyio
    async def test_throws_when_discovery_fails(self, fetch_queue: _FetchQueue) -> None:
        fetch_queue.default = FetchResult(
            data=None, error={"message": "Network error"}
        )
        with pytest.raises(DiscoveryError):
            await ensure_runtime_discovery(
                self.base_config, self.issuer, _always_trusted
            )

    @pytest.mark.anyio
    async def test_throws_for_untrusted_origin(
        self, queue_default_doc: _FetchQueue
    ) -> None:
        with pytest.raises(DiscoveryError) as exc:
            await ensure_runtime_discovery(
                self.base_config, self.issuer, lambda _u: False
            )
        assert exc.value.code == "discovery_untrusted_origin"
