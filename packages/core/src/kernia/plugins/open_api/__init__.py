"""OpenAPI 3.1 plugin — exposes `/openapi.json` and `/scalar` for the auth surface.

Mirrors `reference/packages/better-auth/src/plugins/open-api/`.

The plugin walks the router's registered endpoints (made available via
`ctx.router` after `init()` builds the route table) and emits an OpenAPI 3.1
document on demand. Pydantic v2 body and query models are converted to JSON
Schema via `model_json_schema()`; referenced component schemas are deduplicated
under `components.schemas` and reused via `$ref`.

Usage::

    from kernia.plugins.open_api import open_api
    init(KerniaOptions(..., plugins=[open_api()]))

Endpoints (mounted under the auth base path, e.g. `/api/auth/openapi.json`):

    GET /openapi.json   → the OpenAPI document
    GET /scalar         → an HTML page rendering Scalar UI from /openapi.json
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, TypeGuard

from kernia.api.endpoint import create_auth_endpoint
from kernia.api.request import HTMLResponse
from kernia.types.endpoint import AuthEndpoint, EndpointOptions

# --------------------------------------------------------------------------- helpers

_DEFAULT_INFO_DESCRIPTION = (
    "Auto-generated OpenAPI document for the better-auth Python instance. "
    "Includes every endpoint registered by core + active plugins."
)


def _safe_doc_summary(handler: Any) -> str | None:
    doc = getattr(handler, "__doc__", None)
    if not doc:
        return None
    first = doc.strip().splitlines()[0].strip()
    return first or None


def _pkg_version() -> str:
    try:
        from kernia import __version__

        return __version__
    except Exception:  # pragma: no cover
        return "0.0.0"


def _is_pydantic_model(t: Any) -> TypeGuard[type]:
    return t is not None and hasattr(t, "model_json_schema")


def _extract_schema_and_defs(model: type) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return `(root_schema, defs)` for a Pydantic model.

    Refs are emitted as `#/components/schemas/<Name>` so they slot directly into
    the OpenAPI document's `components.schemas` map.
    """
    raw = model.model_json_schema(ref_template="#/components/schemas/{model}")  # type: ignore[attr-defined]
    defs = raw.pop("$defs", {}) or {}
    return raw, defs


def _query_params_from_model(model: type) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Expand a Pydantic model's fields into OpenAPI parameter entries."""
    schema, defs = _extract_schema_and_defs(model)
    props: dict[str, Any] = schema.get("properties", {}) or {}
    required = set(schema.get("required", []) or [])
    params: list[dict[str, Any]] = []
    for name, prop in props.items():
        params.append(
            {
                "name": name,
                "in": "query",
                "required": name in required,
                "schema": prop,
            }
        )
    return params, defs


# --------------------------------------------------------------------------- builder


def build_openapi_document(
    *,
    router: Any,
    plugins: list[Any],
    info_title: str = "better-auth",
    info_version: str | None = None,
    info_description: str = _DEFAULT_INFO_DESCRIPTION,
) -> dict[str, Any]:
    """Build an OpenAPI 3.1 document from a Router and the registered plugin list."""
    info_version = info_version or _pkg_version()

    plugin_error_codes: dict[str, Mapping[str, str]] = {}
    for p in plugins:
        codes = getattr(p, "error_codes", None)
        if codes:
            plugin_error_codes[p.id] = codes

    components_schemas: dict[str, Any] = {}
    paths: dict[str, dict[str, Any]] = {}

    endpoints: dict[tuple[str, str], AuthEndpoint] = router._endpoints

    for (method, path), ep in endpoints.items():
        op: dict[str, Any] = {}

        summary = _safe_doc_summary(ep.handler)
        if summary:
            op["summary"] = summary

        # Tags: explicit metadata > owner plugin id > "core".
        meta = dict(ep.options.metadata or {})
        tags = meta.get("tags")
        if not tags:
            tags = [ep.owner] if ep.owner else ["core"]
        op["tags"] = list(tags)

        # Query parameters
        if _is_pydantic_model(ep.options.query):
            params, defs = _query_params_from_model(ep.options.query)
            if params:
                op["parameters"] = params
            components_schemas.update(defs)

        # Request body
        if _is_pydantic_model(ep.options.body):
            root, defs = _extract_schema_and_defs(ep.options.body)
            title = root.get("title") or ep.options.body.__name__
            components_schemas[title] = root
            components_schemas.update(defs)
            op["requestBody"] = {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {"$ref": f"#/components/schemas/{title}"},
                    },
                },
            }

        # Responses
        responses: dict[str, Any] = {
            "200": {
                "description": "Successful response",
                "content": {
                    "application/json": {"schema": {"type": "object"}},
                },
            },
        }
        err_schema = {
            "type": "object",
            "properties": {
                "code": {"type": "string"},
                "message": {"type": "string"},
            },
            "required": ["code", "message"],
        }
        if ep.options.requires_session:
            responses["401"] = {
                "description": "Unauthorized",
                "content": {"application/json": {"schema": err_schema}},
            }
        codes_for_owner = plugin_error_codes.get(ep.owner or "", {})
        if codes_for_owner:
            responses["400"] = {
                "description": "Plugin error codes: " + ", ".join(sorted(codes_for_owner.keys())),
                "content": {"application/json": {"schema": err_schema}},
            }
        op["responses"] = responses

        if ep.options.requires_session:
            op["security"] = [{"sessionCookie": []}]

        paths.setdefault(path, {})[method.lower()] = op

    doc: dict[str, Any] = {
        "openapi": "3.1.0",
        "info": {
            "title": info_title,
            "version": info_version,
            "description": info_description,
        },
        "paths": paths,
        "components": {
            "schemas": components_schemas,
            "securitySchemes": {
                "sessionCookie": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": "better-auth.session_token",
                },
            },
        },
    }
    return doc


# --------------------------------------------------------------------------- HTML


_SCALAR_HTML_TEMPLATE = """<!doctype html>
<html>
  <head>
    <title>Better Auth API Reference</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <script
      id="api-reference"
      data-url="__OPENAPI_URL__"
    ></script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </body>
</html>
"""


def scalar_html(openapi_url: str = "openapi.json") -> str:
    """Render the Scalar reference HTML pointing at the given openapi URL."""
    return _SCALAR_HTML_TEMPLATE.replace("__OPENAPI_URL__", openapi_url)


# --------------------------------------------------------------------------- plugin


async def _openapi_json(ctx: Any) -> dict[str, Any]:
    """Return the auto-generated OpenAPI 3.1 document for this auth instance."""
    router = ctx.auth.router
    return build_openapi_document(router=router, plugins=list(ctx.auth.plugins))


async def _scalar_page(ctx: Any) -> HTMLResponse:
    """Render the Scalar API reference HTML page."""
    return HTMLResponse(body=scalar_html(openapi_url="openapi.json"), status=200)


_OPENAPI_ENDPOINT = create_auth_endpoint(
    "/openapi.json",
    EndpointOptions(method="GET", metadata={"tags": ["open-api"]}),
    _openapi_json,
)

_SCALAR_ENDPOINT = create_auth_endpoint(
    "/scalar",
    EndpointOptions(method="GET", metadata={"tags": ["open-api"]}),
    _scalar_page,
)


@dataclass(frozen=True, slots=True)
class _OpenAPIPlugin:
    id: str = "open-api"
    version: str | None = None
    schema: None = None
    middlewares: None = None
    hooks: None = None
    on_request: None = None
    on_response: None = None
    rate_limit: None = None
    error_codes: None = None
    init: None = None
    endpoints: tuple[AuthEndpoint, ...] = field(
        default_factory=lambda: (_OPENAPI_ENDPOINT, _SCALAR_ENDPOINT)
    )


def open_api() -> Any:
    """Construct the OpenAPI plugin.

    Adds two routes to the auth surface:
      - GET /openapi.json
      - GET /scalar
    """
    return _OpenAPIPlugin()


__all__ = [
    "build_openapi_document",
    "open_api",
    "scalar_html",
]
