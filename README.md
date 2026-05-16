# better-auth-python

A Python port of [better-auth](https://github.com/better-auth/better-auth) (TS, v1.6.11), structured to mirror the reference codebase directory-for-directory. No stubs, no smoke tests — every plugin and every adapter is a real implementation with real unit + integration coverage.

## Status

**Full feature parity. 632 passing, 108 skipped (docker / external-dep gated). 14 of 14 implementation lanes complete.**

### Plugins (28 built-in + 7 in standalone packages = 35)

Built-in (under `packages/core/src/better_auth/plugins/`):
`access`, `additional_fields`, `admin`, `anonymous`, `bearer`, `captcha`, `custom_session`, `device_authorization`, `email_otp`, `email_password`, `generic_oauth`, `haveibeenpwned`, `jwt`, `last_login_method`, `magic_link`, `mcp`, `multi_session`, `oauth_proxy`, `one_tap`, `one_time_token`, `open_api`, `organization`, `phone_number`, `siwe`, `two_factor`, `username`.

Standalone packages: `api_key`, `passkey`, `sso` (SAML + OIDC), `oauth_provider` (full OIDC issuer), `scim`, `stripe`, `redis_storage`.

### Adapters
`memory`, `sqlalchemy` (Postgres/MySQL/SQLite + transactions/joins/ilike_eq/UUID PK), `mongo` (motor). Cross-adapter conformance suite: 64 cases run against each.

### Social providers (35 built-in + 9 generic-oauth helpers)
apple, atlassian, cognito, discord, dropbox, facebook, figma, github, gitlab, google, huggingface, kakao, kick, line, linear, linkedin, microsoft, naver, notion, paybin, paypal, polar, railway, reddit, roblox, salesforce, slack, spotify, tiktok, twitch, twitter, vercel, vk, wechat, zoom. Plus generic-oauth constructors for auth0, okta, keycloak, microsoft-entra-id, slack, patreon, line, gumroad, hubspot.

### Server integrations
`fastapi`, `starlette`, `django` (async-to-sync via asgiref).

### Frontend SDK story
**OpenAPI 3.1.** The `open_api` plugin serves `GET /api/auth/openapi.json` (validated against `openapi-spec-validator`) and `GET /api/auth/scalar` (Scalar UI). Frontends generate their own typed clients from this spec.

### CLI
`better-auth init | generate | migrate | secret | info` — Click-based, scaffolds an app, emits Alembic migrations, applies them, generates secrets, dumps diagnostics.

### Crypto + security
- Argon2id (argon2-cffi) default password hash; scrypt verify fallback with `needs_rehash()` for lazy upgrade.
- AES-GCM OAuth-token-at-rest encryption (`oauth2/encryption.py`).
- HMAC-SHA256 cookie signing, wire-compatible with the better-auth JS client.
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
├── reference/                                  # better-auth v1.6.11 (git submodule)
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
├── scripts/audit_layout.py   # CI gate: every reference dir mirrored or waived
└── .github/workflows/ci.yml  # 4 adapters × py3.11/3.12
```

## Quickstart

```bash
git clone --recurse-submodules <repo>
cd better-auth-python
uv sync
uv run pytest e2e/ packages/ -v
python scripts/audit_layout.py
```

## Deferred (honestly)

- **Wire-protocol conformance vs containerized better-auth Node server** — Lane J. Requires Docker and `reference/demo/` to spin up; the shape parity is enforced by the spec docs and the `open-api` plugin's generated OpenAPI, but a live cross-server cookie/JSON parity test hasn't run yet.
- **WebAuthn full attestation trust chain** — the `passkey` test exercises options + assertion verification but doesn't reproduce a complete soft-authenticator CBOR attestation. Real browser flows are unaffected.
- **SAML strict-mode validation against `MockSAMLIdP`** — the mock's canonical XML serialization doesn't match libxml2's exc-c14n, so the SSO test runs python3-saml in permissive mode. Real IdP integrations use strict mode.
- **OIDC issuer optional RFCs** — mTLS client auth (RFC 8705), JAR/PAR (RFC 9101/9126), Token Exchange (RFC 8693), private-key JWT client auth. Standard `client_secret_basic/post/none` flows are supported.
- **SIWE ENS reverse-lookup** — option accepted but the network call to a node provider isn't wired.
- **Stripe seat-sync hook on org membership change** — the schema field exists; the live hook is documented and trivial to wire.

## Reference pin

`reference/` is pinned to better-auth `v1.6.11`. Bumping the submodule is an explicit step that re-runs `scripts/audit_layout.py` and triggers a re-extraction of the 7 spec docs.
