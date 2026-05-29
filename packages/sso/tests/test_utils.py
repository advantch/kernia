"""1:1 port of reference/packages/sso/src/utils.test.ts plus the
``safeJsonParse`` describe block from saml.test.ts.
"""

from __future__ import annotations

import pytest
from better_auth_sso.utils import (
    get_hostname_from_domain,
    safe_json_parse,
    validate_email_domain,
)


# --------------------------------------------------------------------------- #
# validateEmailDomain - https://github.com/better-auth/better-auth/issues/7324
# --------------------------------------------------------------------------- #
class TestValidateEmailDomainSingle:
    def test_matches_domain_exactly(self) -> None:
        assert validate_email_domain("user@company.com", "company.com") is True

    def test_matches_subdomain(self) -> None:
        assert validate_email_domain("user@hr.company.com", "company.com") is True
        assert validate_email_domain("user@dept.hr.company.com", "company.com") is True

    def test_reject_different_domain(self) -> None:
        assert validate_email_domain("user@other.com", "company.com") is False

    def test_reject_suffix_but_not_subdomain(self) -> None:
        assert validate_email_domain("user@notcompany.com", "company.com") is False

    def test_case_insensitive(self) -> None:
        assert validate_email_domain("USER@COMPANY.COM", "company.com") is True
        assert validate_email_domain("user@company.com", "COMPANY.COM") is True


class TestValidateEmailDomainMultiple:
    def test_match_any_domain_in_list(self) -> None:
        domains = "company.com,subsidiary.com,acquired-company.com"
        assert validate_email_domain("user@company.com", domains) is True
        assert validate_email_domain("user@subsidiary.com", domains) is True
        assert validate_email_domain("user@acquired-company.com", domains) is True

    def test_subdomains_for_any_domain_in_list(self) -> None:
        domains = "company.com,subsidiary.com"
        assert validate_email_domain("user@hr.company.com", domains) is True
        assert validate_email_domain("user@dept.subsidiary.com", domains) is True

    def test_reject_not_matching_any_domain(self) -> None:
        domains = "company.com,subsidiary.com,acquired-company.com"
        assert validate_email_domain("user@other.com", domains) is False
        assert validate_email_domain("user@notcompany.com", domains) is False

    def test_handle_whitespace_in_domain_list(self) -> None:
        domains = "company.com, subsidiary.com , acquired-company.com"
        assert validate_email_domain("user@company.com", domains) is True
        assert validate_email_domain("user@subsidiary.com", domains) is True
        assert validate_email_domain("user@acquired-company.com", domains) is True

    def test_handle_empty_domains_in_list(self) -> None:
        domains = "company.com,,subsidiary.com"
        assert validate_email_domain("user@company.com", domains) is True
        assert validate_email_domain("user@subsidiary.com", domains) is True

    def test_case_insensitive_for_multiple_domains(self) -> None:
        domains = "Company.COM,SUBSIDIARY.com"
        assert validate_email_domain("user@company.com", domains) is True
        assert validate_email_domain("USER@SUBSIDIARY.COM", domains) is True


class TestValidateEmailDomainEdgeCases:
    def test_empty_email(self) -> None:
        assert validate_email_domain("", "company.com") is False

    def test_empty_domain(self) -> None:
        assert validate_email_domain("user@company.com", "") is False

    def test_email_without_at(self) -> None:
        assert validate_email_domain("usercompany.com", "company.com") is False

    def test_domain_list_only_whitespace_commas(self) -> None:
        assert validate_email_domain("user@company.com", ", ,") is False


# --------------------------------------------------------------------------- #
# getHostnameFromDomain - https://github.com/better-auth/better-auth/issues/8361
# --------------------------------------------------------------------------- #
class TestGetHostnameFromDomain:
    def test_bare_domain(self) -> None:
        assert get_hostname_from_domain("github.com") == "github.com"

    def test_full_url(self) -> None:
        assert get_hostname_from_domain("https://github.com") == "github.com"

    def test_url_with_port(self) -> None:
        assert get_hostname_from_domain("https://github.com:8081") == "github.com"

    def test_subdomain(self) -> None:
        assert get_hostname_from_domain("auth.github.com") == "auth.github.com"

    def test_url_with_path(self) -> None:
        assert (
            get_hostname_from_domain("https://github.com/path/to/resource")
            == "github.com"
        )

    def test_empty_string_returns_none(self) -> None:
        assert get_hostname_from_domain("") is None


# --------------------------------------------------------------------------- #
# safeJsonParse - from saml.test.ts
# --------------------------------------------------------------------------- #
class TestSafeJsonParse:
    def test_returns_object_as_is(self) -> None:
        obj = {"a": 1, "nested": {"b": 2}}
        result = safe_json_parse(obj)
        assert result is obj
        assert result == {"a": 1, "nested": {"b": 2}}

    def test_parses_stringified_json(self) -> None:
        result = safe_json_parse('{"a":1,"nested":{"b":2}}')
        assert result == {"a": 1, "nested": {"b": 2}}

    def test_returns_none_for_null_input(self) -> None:
        assert safe_json_parse(None) is None

    def test_throws_for_invalid_json_string(self) -> None:
        with pytest.raises(ValueError, match="Failed to parse JSON"):
            safe_json_parse("not valid json")

    def test_handles_empty_object(self) -> None:
        obj: dict = {}
        result = safe_json_parse(obj)
        assert result is obj

    def test_handles_empty_string_json(self) -> None:
        assert safe_json_parse("{}") == {}
