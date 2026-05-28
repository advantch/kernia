# FastAPI SaaS demo

The example app is a real Kernia-backed SaaS shell: FastAPI on the backend,
Vite + React on the frontend, and the official `better-auth@1.6.11` browser
client for auth flows.

## Run the backend

```bash
uv run uvicorn examples.backend.app:app --host 127.0.0.1 --port 8000 --reload
```

The demo wires email/password, magic link, email OTP, organizations, admin,
API keys, Stripe billing, OpenAPI, and database-backed admin config. External
providers are environment driven; without credentials the UI shows them as not
configured instead of pretending they work.

## Run the frontend

```bash
cd examples/frontend
pnpm install
pnpm dev
```

Open `http://localhost:5173`. The Vite proxy keeps `/api/auth/*` same-origin so
Kernia session cookies behave the same way they do in production.

## What the UI covers

- Login and logout with configured auth methods surfaced.
- Dashboard with workspace context, billing state, active organization, and
  account health.
- Settings tabs for profile, linked accounts, sessions, API keys, security,
  and billing.
- Admin tabs for users/auth methods, email clients, Stripe setup, imported
  products/prices, entitlements, usage, and webhook readiness.

## Wire check

```bash
cd examples/frontend
node scripts/wire-check.mjs
```

This drives the official Better Auth JS client against Kernia and checks
sign-up, session, sign-out, sign-in, organization create/list, and a negative
credentials case.
