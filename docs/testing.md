# Testing

Run the backend suite:

```bash
uv run pytest e2e/ packages/ -q
```

Run the layout parity audit:

```bash
python scripts/audit_layout.py
```

Run the demo frontend build:

```bash
cd examples/frontend
pnpm build
```

Run the JS-client wire check against a live backend:

```bash
uv run uvicorn examples.backend.app:app --host 127.0.0.1 --port 8000
cd examples/frontend
node scripts/wire-check.mjs
```

Build the docs:

```bash
uv run --with mkdocs --with mkdocs-material mkdocs build -f docs/mkdocs.yml
```

The Docker-gated Mongo tests skip automatically when Docker is unavailable.
