# OpenAPI

The [`open_api`](plugins/open_api.md) plugin auto-generates an OpenAPI 3 document
for every registered better-auth route — core endpoints plus everything each
plugin contributes.

## Usage

```python
from better_auth import BetterAuthOptions
from better_auth.auth import init
from better_auth.plugins.open_api import open_api
from better_auth.plugins.email_password import email_and_password
from better_auth_memory_adapter import memory_adapter

auth = init(
    BetterAuthOptions(
        database=memory_adapter(),
        secret="change-me",
        plugins=[
            email_and_password(),
            open_api(),
        ],
    )
)
```

Once mounted, the document is served at `/api/auth/openapi.json` and a Scalar UI is
served at `/api/auth/reference`.

## Live reference (Scalar embed)

When you're running locally, you can browse the generated API reference via the
embedded Scalar UI:

<iframe
  src="http://localhost:3000/api/auth/reference"
  width="100%"
  height="800"
  style="border:1px solid #ddd; border-radius: 6px;"
></iframe>

> The iframe points at `http://localhost:3000` — adjust to match your `base_url`
> when serving these docs from somewhere else.

## Static rendering

For published docs, fetch the JSON once and check it in:

```bash
curl http://localhost:3000/api/auth/openapi.json > docs/openapi.json
```

Then render it with [Scalar](https://github.com/scalar/scalar) or any OpenAPI
viewer of your choice.
