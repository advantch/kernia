# better-auth-python

A Python port of [better-auth](https://github.com/better-auth/better-auth) (TS, v1.6.11), structured to mirror the reference codebase directory-for-directory. Every plugin and adapter listed below is a real implementation (no empty stubs), but **this is a work in progress, not a finished 1:1 port.**

## Status — honest parity ledger

> **Not full parity yet. Not released.** A previous revision of this README claimed "full feature parity, 632 passing." That claim was wrong and was removed. The definition of *done* in this project is **better-auth's own test suite, translated vitest→pytest, passing against the Python implementation** — not lines of code, and not "the endpoint exists."
>
> By that gate we are **substantially advanced but not yet complete**: **1,740** passing Python tests against **3,468** upstream `it()`/`test()` cases across the whole reference repo (≈ **46 %** by raw test-case count). Note the upstream denominator includes the frontend SDKs (`expo`, `electron`, the React/Vue/Svelte clients) that are **explicitly out of scope** here — measured against backend areas only, coverage is much higher and many areas now meet or exceed upstream. We will only flip the headline to "full parity" when every row below reads ✅, and we will not publish to PyPI before then.

Counts are *passing Python tests* (e2e + unit + package) vs *upstream `it()`/`test()` cases* for the same area, both measured directly (`uv run pytest --co` vs `grep` over `reference/**/*.test.ts`). A ratio ≥ 1.0 means we exercise the behavior at least as thoroughly as upstream; a low ratio means the surface exists but upstream covers far more edge cases than we've ported yet.

| Area | Python tests | Upstream cases | Notes |
|---|---:|---:|---|
| **At or above upstream coverage** | | | |
| one_tap | 9 | 4 | ✅ |
| haveibeenpwned | 5 | 4 | ✅ |
| open_api | 11 | 10 | ✅ |
| access (AC DSL) | 11 | 9 | ✅ |
| multi_session | 12 | 9 | ✅ |
| magic_link | 28 | 18 | ✅ |
| one_time_token | 21 | 13 | ✅ |
| bearer | 21 | 7 | ✅ |
| anonymous | 15 | 13 | ✅ |
| last_login_method | 22 | 21 | ✅ |
| siwe | 28 | 18 | ✅ |
| device_authorization | 45 | 36 | ✅ |
| passkey | 21 | 20 | ✅ |
| scim | 89 | 78 | ✅ |
| db / adapters | 97 | 67 | ✅ with_hooks, transactions, conformance |
| admin | 71 | 72 | ✅ ban-expiry, impersonation, RBAC |
| jwt | 45 | 38 | ✅ /jwks, /sign, /verify, EdDSA, rotation |
| **Strong — most of upstream ported** | | | |
| phone_number | 31 | 32 | 97 % — + expired-code, last-code-wins, reset-password (create-account / too-many-attempts / no-leak); remaining: custom `verifyOTP` + `updatePhoneNumber`/`updateUser` immutability |
| captcha | 17 | 17 | ✅ non-protected passthrough, missing-secret + siteverify-failure → 500, v3 low-score → 403 |
| oauth_proxy | 14 | 18 | 78 % |
| generic_oauth | 45 | 60 | 75 % — + async `mapProfileToUser` awaited |
| organization | 142 | 200 | 71 % — 35 endpoints, teams, dynamic AC |
| sso (SAML+OIDC) | 236 | 359 | 66 % — provider ownership, sanitized read endpoints |
| two_factor | 56 | 55 | ✅ raw count — + twoFactorMethods combos (totp/otp/both), magic-link enforcement scope, storeBackupCodes (plain/encrypted/custom); one upstream option (custom twoFactorTable name) still unimplemented |
| email_otp | 55 | 73 | 75 % — attempts, resend, change-email, custom store, race delete |
| mcp (FastMCP) | 25 | 44 | 57 % — RFC 9728 resource server; issuer + refresh_token client-auth cases ported in oauth_provider |
| username | 28 | 35 | 80 % — + empty-username, default displayUsername-not-normalized; remaining: form-mode + a few displayUsername edge cases |
| api_key | 109 | 178 | 61 % — multi-config, scopes, org-owned, legacy metadata migration, deferUpdates via backgroundTasks, list pagination + sorting |
| stripe | 142 | 157 | 90 % — metered/upgrade/customer/webhook + checkout hook + schedule + auto-managed seats + org member-change seat-sync + seat-swap upgrades + multiset line-item diff (immediate + scheduled: in-place base swap, deletes for removed prices, adds for introduced prices, no duplicates) + trial-abuse prevention + trial-data propagation + cancel/schedule webhook lifecycle + org customer creation/reuse/billing-portal + org dashboard webhook + cross-org isolation + org subscription update/cancel/delete webhook lifecycle + org customer-lookup customerType isolation + signup customer dedup/email-sync + getCustomerCreateParams defu-merge + search→list fallback |
| **Behind — surface built, coverage lagging** | | | |
| custom_session | 10 | 11 | 91 % — + cookie-cache `session_data` refresh + `advanced.defaultCookieAttributes` (partitioned cookies) |
| oauth_provider | 152 | 278 | 55 % — JWT + opaque-token models + pairwise PPID subjects + configurable per-endpoint rate limits + refresh_token client-auth (Basic/body, mismatch, disabled-client → invalid_client) + OIDC RP-initiated logout (end-session, `sid` claim, admin-only `enable_end_session`, post-logout redirect) + DCR validation (empty-body → 400, `skip_consent` rejected as privileged) + session-linked introspection (`sid` claim on access/refresh tokens, validated against a live session and dropped after logout); remaining DB-token-table + unauthenticated-DCR-override cases unported |
| oidc_provider | shim | 47 | deprecated shim → oauth_provider |

**Bottom line:** the Phase-0 core foundations (field model, schema resolution, `with_hooks`, transactions, plugin lifecycle) are in place, and the majority of plugins now meet or closely approach upstream test coverage — 17 areas are at or above upstream, 10 more are 45–87 %. The one remaining structural gap is **oauth_provider (52 %)**: it now supports *both* the self-contained-JWT and the opaque DB-backed `oauthAccessToken` models (`jwt_access_token=False` selects upstream's opaque tokens, with prefix/introspection/userinfo/revocation parity) plus pairwise (PPID) subject identifiers (per-sector unlinkable id_token `sub`, sector isolation by redirect-URI host, DCR + metadata validation), configurable per-endpoint rate limits (six upstream defaults, `{window, max}` overrides, `False` to disable, live 429 enforcement), full refresh_token-grant client authentication (confidential clients must present a valid secret via body or `Authorization: Basic`, body/Basic `client_id` mismatch and administratively `disabled` clients are rejected with `invalid_client`), and OIDC RP-initiated logout (`end_session_endpoint`: validates the `id_token_hint`, terminates the session named by the token's `sid` claim — emitted only for clients granted the admin-only `enable_end_session` flag, never via dynamic registration — and honours whitelisted `post_logout_redirect_uri` + `state`), but many upstream cases still exercise that table's edge behaviour we haven't ported. **stripe (90 %)** wires the `getCheckoutSessionParams` hook, `scheduleAtPeriodEnd` deferred plan changes (Subscription Schedules), auto-managed seat line items at checkout, org member-change seat-sync (seat line-item quantity tracks membership, honouring per-plan proration), seat-aware plan upgrades via the full multiset line-item diff (in-place base/seat swap with preserved item ids, `deleted` flags for removed prices, adds for introduced prices, duplicate-free — applied to both the immediate `subscriptions.update` and the deferred schedule phase), the full org customer + subscription-lifecycle webhook surface, and signup customer dedup / email-sync / `getCustomerCreateParams` defu-merge / search→list fallback — leaving only metered-usage-reporting and checkout-success edge cases to port. These remain genuinely incomplete; no blanket "full parity" claim until they close.

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
