"""Unit tests for kernia.plugins.open_api."""

from __future__ import annotations

import pytest

from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.plugins.open_api import build_openapi_document, open_api, scalar_html
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter


@pytest.fixture
def auth_instance():
    return init(
        KerniaOptions(
            database=memory_adapter(),
            secret="x" * 32,
            plugins=[email_and_password(), open_api()],
        )
    )


def test_document_is_valid_openapi_31(auth_instance) -> None:
    from openapi_spec_validator import validate

    doc = build_openapi_document(
        router=auth_instance.router, plugins=list(auth_instance.context.plugins)
    )
    validate(doc)
    assert doc["openapi"] == "3.1.0"
    assert doc["info"]["title"] == "better-auth"
    assert "version" in doc["info"]


def test_every_registered_route_appears_in_paths(auth_instance) -> None:
    doc = build_openapi_document(
        router=auth_instance.router, plugins=list(auth_instance.context.plugins)
    )
    for (method, path) in auth_instance.router._endpoints:
        assert path in doc["paths"], f"missing path {path}"
        assert method.lower() in doc["paths"][path], (
            f"missing method {method} for {path}"
        )


def test_request_body_schemas_present_for_body_endpoints(auth_instance) -> None:
    doc = build_openapi_document(
        router=auth_instance.router, plugins=list(auth_instance.context.plugins)
    )
    # /revoke-session uses a Pydantic BaseModel for its body.
    op = doc["paths"]["/revoke-session"]["post"]
    assert "requestBody" in op
    ref = op["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    assert ref.startswith("#/components/schemas/")
    schema_name = ref.rsplit("/", 1)[-1]
    assert schema_name in doc["components"]["schemas"]


def test_requires_session_endpoints_have_security_block(auth_instance) -> None:
    doc = build_openapi_document(
        router=auth_instance.router, plugins=list(auth_instance.context.plugins)
    )
    op = doc["paths"]["/list-sessions"]["get"]
    assert op.get("security") == [{"sessionCookie": []}]
    assert "401" in op["responses"]


def test_plugin_error_codes_surface_in_responses(auth_instance) -> None:
    doc = build_openapi_document(
        router=auth_instance.router, plugins=list(auth_instance.context.plugins)
    )
    op = doc["paths"]["/sign-in/email"]["post"]
    # email_and_password contributes error codes; 400 should be present.
    assert "400" in op["responses"]


def test_tags_default_to_owner_plugin_id(auth_instance) -> None:
    doc = build_openapi_document(
        router=auth_instance.router, plugins=list(auth_instance.context.plugins)
    )
    op = doc["paths"]["/sign-up/email"]["post"]
    assert "email-password" in op["tags"]


def test_scalar_html_embeds_openapi_url() -> None:
    html = scalar_html(openapi_url="openapi.json")
    assert "<script" in html
    assert "openapi.json" in html
    assert "scalar/api-reference" in html


def test_open_api_plugin_registers_two_endpoints() -> None:
    plugin = open_api()
    paths = {ep.path for ep in plugin.endpoints}
    assert paths == {"/openapi.json", "/scalar"}
