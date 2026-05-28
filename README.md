# kernia

Kernia is an independent Python implementation compatible with [Better Auth](https://github.com/better-auth/better-auth) (TS, v1.6.11). It preserves the Better Auth wire protocol where clients depend on it, while exposing a Python-native `kernia` package family. No upstream source is vendored in this repository.

## Status

**Full feature parity target: Better Auth 1.6.11. The suite is maintained as a
green gate, with Docker / external-dep tests skipped when unavailable.**

### Plugins (27 built-in + 7 in standalone packages = 34)

Built-in (under `packages/core/src/kernia/plugins/`):
`access`, `additional_fields`, `admin`, `anonymous`, `bearer`, `captcha`, `custom_session`, `device_authorization`, `email_otp`, `email_password`, `generic_oauth`, `haveibeenpwned`, `jwt`, `last_login_method`, `magic_link`, `mcp`, `multi_session`, `oauth_proxy`, `oidc_provider`, `one_tap`, `one_time_token`, `open_api`, `organization`, `phone_number`, `siwe`, `two_factor`, `username`.

Standalone packages: `api_key`, `passkey`, `sso` (SAML + OIDC), `oauth_provider` (full OIDC issuer), `scim`, `stripe`, `redis_storage`.

### Adapters
`memory`, `sqlalchemy` (Postgres/MySQL/SQLite + transactions/joins/ilike_eq/UUID PK), `mongo` (motor). Cross-adapter conformance suite: 64 cases run against each.

### Social providers (35 built-in + 9 generic-oauth helpers)
apple, atlassian, cognito, discord, dropbox, facebook, figma, github, gitlab, google, huggingface, kakao, kick, line, linear, linkedin, microsoft, naver, notion, paybin, paypal, polar, railway, reddit, roblox, salesforce, slack, spotify, tiktok, twitch, twitter, vercel, vk, wechat, zoom. Plus generic-oauth constructors for auth0, okta, keycloak, microsoft-entra-id, slack, patreon, line, gumroad, hubspot.

### Server integrations
`fastapi`, `starlette`, `django` (async-to-sync via asgiref).

### Frontend SDK story
**OpenAPI 3.1.** The `open_api` plugin serves `GET /api/auth/openapi.json` (validated against `openapi-spec-validator`) and `GET /api/auth/scalar` (Scalar UI). Frontends generate their own typed clients from this spec.

### SaaS reference app
`examples/backend` and `examples/frontend` are a FastAPI + Vite SaaS demo, not a
mock-only login form. The app includes login/logout, workspace context, settings
for profile/accounts/sessions/API keys/billing, admin config for auth methods
and email clients, Stripe setup, Stripe product/price import, billing checks,
and usage display. External providers without credentials are shown as not
configured.

### CLI
`kernia init | generate | migrate | secret | info` — Click-based, scaffolds an app, emits Alembic migrations, applies them, generates secrets, dumps diagnostics.

### Crypto + security
- Argon2id (argon2-cffi) default password hash; scrypt verify fallback with `needs_rehash()` for lazy upgrade.
- AES-GCM OAuth-token-at-rest encryption (`oauth2/encryption.py`).
- HMAC-SHA256 cookie signing, wire-compatible with the Better Auth JS client.
- Signed OAuth `state` tokens with PKCE-verifier binding.
- Pure-stdlib RS256 id_token verifier; authlib for outbound ES256/RS256/EdDSA issuance.
- Trusted-origins CSRF check, on by default for state-changing requests.
- Cookie-secret rotation: multi-secret verify so old sessions don't break.
- Rate-limit with InMemory + Redis stores (atomic Lua INCR+EXPIRE).
- haveibeenpwned k-anonymity gate during sign-up + reset.
- Captcha middleware for reCAPTCHA v2/v3, Turnstile, hCaptcha, CaptchaFox.

### Test discipline (per the no-shortcuts mandate)

- **Unit tests** at `packages/<pkg>/tests/` — pure-function tests only.
- **Integration tests** at `e2e/plugins/test_<plugin>.py` — full ASGI flow per plugin, parametrized over memory + sqlalchemy + mongo (mongo skips when no Docker).
- **Cross-cutting integration** at `e2e/integration/` — flows that span plugins.
- **Adapter conformance** at `e2e/adapter/` — same suite green against every adapter.
- **No smoke tests anywhere.**

## Repository layout

```
.
├── spec/                                       # 7 extracted contract docs (~2300 lines)
├── packages/
│   ├── core/                                   # 28 plugins + 35 social providers + i18n + telemetry
│   ├── memory_adapter/  sqlalchemy_adapter/  mongo_adapter/  redis_storage/
│   ├── api_key/  passkey/  sso/  oauth_provider/  scim/  stripe/
│   ├── fastapi_integration/  starlette_integration/  django_integration/
│   ├── cli/  test_utils/
├── e2e/
│   ├── adapter/   # 64 cases × 3 adapters
│   ├── plugins/   # one file per plugin
│   ├── integration/   # cross-plugin flows
├── docs/   # mkdocs site, plugin pages auto-built
├── scripts/audit_layout.py   # CI gate: every upstream dir implemented or waived
└── .github/workflows/ci.yml  # 4 adapters × py3.11/3.12
```

## Quickstart

```bash
git clone <repo>
cd kernia
uv sync
uv run pytest e2e/ packages/ -v
python scripts/audit_layout.py
```

## Parity gates

- `python scripts/audit_layout.py` fetches Better Auth 1.6.11 into a temporary directory and verifies every upstream layout area is implemented or explicitly waived.
- `uv run pytest e2e/ packages/ -q` is green: 649 passed, 108 skipped.
- `examples/frontend/scripts/wire-check.mjs` drives the official Better Auth JS client against the Kernia FastAPI example and validates sign-up, session, sign-out, sign-in, organization create/list, and a negative credentials case.

Previously deferred work now landed:
- ~~**WebAuthn full attestation trust chain**~~ — `SoftAuthenticator` in `test_utils` produces real CBOR attestations + ES256 signatures. Full register → authenticate round-trip green, with negative tests for forged signatures and tampered challenges.
- ~~**SAML strict-mode validation against `MockSAMLIdP`**~~ — `MockSAMLIdP` now uses lxml's exc-c14n. python3-saml in strict mode accepts the mock; SSO plugin defaults to strict validation.
- ~~**SIWE ENS reverse-lookup**~~ — wired. Pass `siwe(enable_ens=True, ens_rpc_url=...)` or supply a custom `ENSResolver`; `web3_ens_resolver()` is the stock implementation with forward-resolve confirmation.
- ~~**Stripe seat-sync hook on org membership change**~~ — wired via `kernia.events`. The org plugin emits `organization.member.{added,removed,updated}`; the Stripe plugin subscribes on init when configured for org+seat billing and pushes `quantity` updates.

## Upstream parity target

The parity audit targets Better Auth commit `f41514ef07cfafc5dbf463bd1500aee6575d88a7` (`1.6.11`). Bumping the target is an explicit code review step that re-runs `scripts/audit_layout.py` and updates the extracted contract docs when needed.
