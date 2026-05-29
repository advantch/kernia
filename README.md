# better-auth-python

A Python port of [better-auth](https://github.com/better-auth/better-auth) (TS, v1.6.11), structured to mirror the reference codebase directory-for-directory. Every plugin and adapter listed below is a real implementation (no empty stubs), but **this is a work in progress, not a finished 1:1 port.**

## Status — honest parity ledger

> **Not full parity yet. Not released.** A previous revision of this README claimed "full feature parity, 632 passing." That claim was wrong and has been removed. The definition of *done* in this project is **better-auth's own test suite, translated vitest→pytest, passing against the Python implementation** — not lines of code, and not "the endpoint exists."
>
> By that gate we are **partial**: ~**687** ported/passing Python tests against ~**3,507** upstream test cases (≈ **20 %** by test-case count). We will only flip the headline to "full parity" when the ledger below reads 100 %, and we will not publish to PyPI before then.

Test counts are *passing Python tests* (e2e + unit + package) vs *upstream `it()`/`test()` cases* for the same area. A high ratio means the behavior is well-exercised; a low ratio means the surface exists but upstream covers far more edge cases than we've ported yet.

| Area | Python tests | Upstream cases | Notes |
|---|---:|---:|---|
| **At / near parity** | | | |
| one_tap | 4 | 4 | ✅ |
| haveibeenpwned | 5 | 4 | ✅ |
| open_api | 11 | 10 | ✅ |
| access (AC DSL) | 11 | 9 | ✅ |
| multi_session | 12 | 9 | ✅ |
| magic_link | 21 | 18 | ✅ |
| one_time_token | 20 | 13 | ✅ |
| bearer | 10 | 7 | ✅ |
| captcha | 13 | 17 | strong |
| phone_number | 21 | 32 | strong |
| **Partial — surface built, coverage behind** | | | |
| device_authorization | 11 | 36 | |
| last_login_method | 12 | 21 | |
| siwe | 11 | 18 | |
| custom_session | 5 | 11 | |
| anonymous | 9 | 13 | |
| jwt | 11 | 38 | /jwks, /sign, /verify present |
| username | 9 | 37 | |
| email_otp | 26 | 73 | |
| organization | 142 | 200 | 35 endpoints, teams, dynamic AC |
| db / adapters | 57 | 67 | with_hooks, transactions, conformance |
| **Large gaps — do not assume parity** | | | |
| two_factor | 9 | 55 | |
| generic_oauth | 8 | 60 | |
| oauth_proxy | 3 | 18 | |
| mcp (FastMCP) | 12 | 45 | OAuth-protected, RFC 9728 |
| admin | 3 | 72 | RBAC/ban/impersonation thin |
| stripe | 15 | 158 | metered + upgrade landed; lifecycle hooks thin |
| passkey | 6 | 20 | |
| scim | 10 | 78 | |
| oauth_provider | 11 | 279 | issuer works; many RFC paths unported |
| api_key | 6 | 178 | |
| sso (SAML+OIDC) | 21 | 359 | |
| oidc_provider | shim | 47 | deprecated shim → oauth_provider |

**Bottom line:** the architecture and the Phase-0 core foundations (field model, schema resolution, `with_hooks`, transactions, plugin lifecycle) are in place and the highest-traffic plugins are well covered, but the standalone packages (sso, api_key, oauth_provider, scim, stripe) and a few core plugins (admin, two_factor, generic_oauth) need substantially more ported tests before any "full parity" claim is truthful.

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

The parity ledger above is the authoritative picture of what's covered. The
"Large gaps" tier there is the real backlog — those packages need many more
ported upstream tests before parity is truthful. Beyond test coverage, these
specific capabilities are known-incomplete:

Remaining real deferrals:
- **Wire-protocol conformance vs containerized better-auth Node server** — Lane J. Requires Docker and `reference/demo/` to spin up; the shape parity is enforced by the spec docs and the `open-api` plugin's generated OpenAPI, but a live cross-server cookie/JSON parity test hasn't run yet.
- **OIDC issuer optional RFCs** — mTLS client auth (RFC 8705), JAR/PAR (RFC 9101/9126), Token Exchange (RFC 8693), private-key JWT client auth. Standard `client_secret_basic/post/none` flows are supported.

Previously deferred, now landed:
- ~~**WebAuthn full attestation trust chain**~~ — `SoftAuthenticator` in `test_utils` produces real CBOR attestations + ES256 signatures. Full register → authenticate round-trip green, with negative tests for forged signatures and tampered challenges.
- ~~**SAML strict-mode validation against `MockSAMLIdP`**~~ — `MockSAMLIdP` now uses lxml's exc-c14n. python3-saml in strict mode accepts the mock; SSO plugin defaults to strict validation.
- ~~**SIWE ENS reverse-lookup**~~ — wired. Pass `siwe(enable_ens=True, ens_rpc_url=...)` or supply a custom `ENSResolver`; `web3_ens_resolver()` is the stock implementation with forward-resolve confirmation.
- ~~**Stripe seat-sync hook on org membership change**~~ — wired via `better_auth.events`. The org plugin emits `organization.member.{added,removed,updated}`; the Stripe plugin subscribes on init when configured for org+seat billing and pushes `quantity` updates.

## Reference pin

`reference/` is pinned to better-auth `v1.6.11`. Bumping the submodule is an explicit step that re-runs `scripts/audit_layout.py` and triggers a re-extraction of the 7 spec docs.
