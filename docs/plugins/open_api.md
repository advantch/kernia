# Open Api

> Module: `kernia.plugins.open_api`
> Constructor: `build_openapi_document`

OpenAPI 3.1 plugin — exposes `/openapi.json` and `/scalar` for the auth surface.

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

## Endpoints

_(no HTTP endpoints — this plugin contributes hooks/schema only)_

## Schema contributions

_(no schema contributions)_

## Usage

```python
from kernia.plugins.open_api import build_openapi_document
from kernia import KerniaOptions
from kernia.auth import init

auth = init(
    KerniaOptions(
        database=...,
        secret=...,
        plugins=[
            build_openapi_document(),
        ],
    )
)
```
