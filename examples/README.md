# Examples — full-stack walkthrough

A working FastAPI server + React SPA, demonstrating that the Python port of
better-auth is wire-compatible with the official JavaScript client.

## What's here

```
examples/
├── backend/
│   ├── app.py          # FastAPI app: email/password + organization + open_api
│   └── run.sh          # boot helper
└── frontend/
    ├── package.json
    ├── vite.config.ts  # /api → :5050 proxy (same-origin cookies)
    ├── src/
    │   ├── App.tsx     # sign-up / sign-in / org list / org create UI
    │   └── auth-client.ts  # the official `better-auth` JS client
    └── scripts/
        └── wire-check.mjs  # headless protocol check driven by the JS client
```

## Run it

In one terminal:

```bash
cd <repo>
.venv/bin/python -m uvicorn examples.backend.app:app --port 5050 --reload
```

In another:

```bash
cd examples/frontend
pnpm install   # only first time
pnpm dev       # serves http://localhost:5173
```

Open <http://localhost:5173> in a browser. You can sign up, sign in, sign out,
create organizations, see them listed. All cookies flow correctly because the
vite dev proxy makes `/api/*` same-origin.

## Headless wire-protocol check

The same JS client the SPA uses is driven from Node against the running
backend. It exercises sign-up, get-session, sign-out, sign-in, organization
create + list, and a negative case (wrong password):

```bash
cd examples/frontend
node scripts/wire-check.mjs
```

Expected output:

```
=== Wire check against http://localhost:5050/api/auth ===
✓ signUp.email
✓ getSession (after sign-up)
✓ signOut
✓ getSession (after sign-out → null)
✓ signIn.email
✓ organization.create
✓ organization.list contains created org
✓ signIn.email rejects wrong password  INVALID_CREDENTIALS

OK — wire protocol matches better-auth client expectations
```

This is the test that subsumes the "containerized Node oracle" idea from the
plan: instead of comparing bytes between two implementations, we drive the
official JS client and assert every contract method works against the Python
server. If you set `WIRE_DEBUG=1`, every HTTP call is logged.

## What this proved

A real wire-protocol bug surfaced during this exercise: the Python
`organization` plugin's `create` and `update` routes returned
`{"organization": {...}}`, but the JS client (and the TS reference) returns the
organization at the top level. The unit + integration tests had been written
around the wrapped shape and didn't catch this — only an actual better-auth
client did. The wire-check (and one-line fixes to the routes) are the visible
result.

## Optional: Google OAuth

To enable Google sign-in in the demo, export real credentials before booting
the backend:

```bash
export GOOGLE_CLIENT_ID="..."
export GOOGLE_CLIENT_SECRET="..."
```

The backend auto-registers `google` as a social provider whenever both vars
are set. The `/api/auth/sign-in/social` route then accepts `provider: "google"`.

## Visual click-through

If you want to actually click through the flow rather than run the headless
check, just open <http://localhost:5173> after both servers are up. The minimal
demo UI ships sign-up, sign-in, sign-out, and an organization create+list flow.
