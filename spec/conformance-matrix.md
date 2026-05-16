# Conformance Matrix

Every test under
`reference/packages/better-auth/src/**/*.test.ts` and
`reference/e2e/**` is listed below, with a one-line summary and an
**MVP / future / skip** tag.

Tagging policy:
- **mvp** — must pass for first Python release: smoke tests,
  email/password auth, session basics, adapter CRUD, Google OAuth.
- **future** — port later once the relevant subsystem/plugin is in
  scope.
- **skip** — TS-only (type-level tests, framework integrations,
  reactivity, snapshot tests we won't re-snapshot).

## Top-level package tests

| Path (relative to `reference/`)                                  | Summary                                              | Tag    |
| ---------------------------------------------------------------- | ---------------------------------------------------- | ------ |
| `packages/better-auth/src/social.test.ts`                        | Google/GitHub/Apple OAuth sign-in end-to-end.        | mvp    |
| `packages/better-auth/src/call.test.ts`                          | Direct `auth.api.X(...)` server-side invocation.     | mvp    |
| `packages/better-auth/src/instrumentation.db.test.ts`            | OTel spans wrap adapter operations.                  | future |
| `packages/better-auth/src/instrumentation.endpoint.test.ts`      | OTel spans wrap endpoint dispatch.                   | future |

## `auth/`

| Path                                                             | Summary                                              | Tag    |
| ---------------------------------------------------------------- | ---------------------------------------------------- | ------ |
| `packages/better-auth/src/auth/minimal.test.ts`                  | `minimalAuth()` boots with sign-up/sign-in only.     | mvp    |
| `packages/better-auth/src/auth/full.test.ts`                     | Full `auth()` boots with default plugin set.         | mvp    |
| `packages/better-auth/src/auth/trusted-origins.test.ts`          | Trusted-origins / wildcard host matching.            | mvp    |

## `api/`

| Path                                                                | Summary                                                       | Tag    |
| ------------------------------------------------------------------- | ------------------------------------------------------------- | ------ |
| `packages/better-auth/src/api/index.test.ts`                        | Endpoint registration aggregator.                             | mvp    |
| `packages/better-auth/src/api/check-endpoint-conflicts.test.ts`     | Plugin endpoint path conflict detection.                      | mvp    |
| `packages/better-auth/src/api/to-auth-endpoints.test.ts`            | Hook chain (before/after) and onRequest/onResponse ordering.  | mvp    |
| `packages/better-auth/src/api/rate-limiter/rate-limiter.test.ts`    | Rate-limit storage memory/db/secondary-storage.               | future |
| `packages/better-auth/src/api/middlewares/origin-check.test.ts`     | `originCheck` + `formCsrfMiddleware`.                         | mvp    |
| `packages/better-auth/src/api/middlewares/authorization.test.ts`    | Authorization header / API key middleware.                    | future |

## `api/routes/`

| Path                                                                | Summary                                                        | Tag    |
| ------------------------------------------------------------------- | -------------------------------------------------------------- | ------ |
| `packages/better-auth/src/api/routes/sign-up.test.ts`               | `/sign-up/email` happy + error paths.                          | mvp    |
| `packages/better-auth/src/api/routes/sign-in.test.ts`               | `/sign-in/email` and `/sign-in/social` (Google).               | mvp    |
| `packages/better-auth/src/api/routes/sign-out.test.ts`              | `/sign-out` deletes session + clears cookies.                  | mvp    |
| `packages/better-auth/src/api/routes/session-api.test.ts`           | `/get-session`, list/revoke endpoints, freshness middleware.   | mvp    |
| `packages/better-auth/src/api/routes/password.test.ts`              | Reset password flow.                                           | mvp    |
| `packages/better-auth/src/api/routes/email-verification.test.ts`    | Send + verify email JWT flow.                                  | mvp    |
| `packages/better-auth/src/api/routes/account.test.ts`               | `/list-accounts`, link/unlink, `/get-access-token`.            | mvp    |
| `packages/better-auth/src/api/routes/update-user.test.ts`           | Update user, change password/email, delete user.               | mvp    |
| `packages/better-auth/src/api/routes/error.test.ts`                 | `/error` HTML page rendering / redirect.                       | future |

## `context/`

| Path                                                       | Summary                                              | Tag    |
| ---------------------------------------------------------- | ---------------------------------------------------- | ------ |
| `packages/better-auth/src/context/init.test.ts`            | Full init: plugins, secrets, schema merge.           | mvp    |
| `packages/better-auth/src/context/init-minimal.test.ts`    | Minimal init.                                        | mvp    |
| `packages/better-auth/src/context/create-context.test.ts`  | Per-request context construction.                    | mvp    |

## `cookies/`

| Path                                                       | Summary                                              | Tag    |
| ---------------------------------------------------------- | ---------------------------------------------------- | ------ |
| `packages/better-auth/src/cookies/cookies.test.ts`         | `getCookies`, set/delete, signing, chunking.         | mvp    |

## `crypto/`

| Path                                                       | Summary                                              | Tag    |
| ---------------------------------------------------------- | ---------------------------------------------------- | ------ |
| `packages/better-auth/src/crypto/password.test.ts`         | Password hash/verify (scrypt).                       | mvp    |
| `packages/better-auth/src/crypto/secret-rotation.test.ts`  | Secret rotation (primary + fallbacks).               | future |

## `db/`

| Path                                                       | Summary                                              | Tag    |
| ---------------------------------------------------------- | ---------------------------------------------------- | ------ |
| `packages/better-auth/src/db/db.test.ts`                   | Adapter create/find/update/delete via factory.       | mvp    |
| `packages/better-auth/src/db/internal-adapter.test.ts`     | High-level adapter helpers (users/sessions/accounts).| mvp    |
| `packages/better-auth/src/db/secondary-storage.test.ts`    | `SecondaryStorage` get/set/delete/getAndDelete.      | future |
| `packages/better-auth/src/db/to-zod.test.ts`               | Convert DB schema to Zod (port: Pydantic).           | future |
| `packages/better-auth/src/db/get-migration-schema.test.ts` | Schema migration generation (Kysely).                | future |

## `oauth2/`

| Path                                                       | Summary                                              | Tag    |
| ---------------------------------------------------------- | ---------------------------------------------------- | ------ |
| `packages/better-auth/src/oauth2/utils.test.ts`            | PKCE, state, token encryption helpers.               | mvp    |
| `packages/better-auth/src/oauth2/link-account.test.ts`     | Account linking decision tree.                       | mvp    |

## `integrations/`

| Path                                                       | Summary                                              | Tag    |
| ---------------------------------------------------------- | ---------------------------------------------------- | ------ |
| `packages/better-auth/src/integrations/next-js.test.ts`    | Next.js Route Handler integration.                   | skip   |

## `utils/`

| Path                                                       | Summary                                              | Tag    |
| ---------------------------------------------------------- | ---------------------------------------------------- | ------ |
| `packages/better-auth/src/utils/url.test.ts`               | URL helpers.                                         | mvp    |

## `types/`

| Path                                                       | Summary                                              | Tag    |
| ---------------------------------------------------------- | ---------------------------------------------------- | ------ |
| `packages/better-auth/src/types/types.test.ts`             | Type-level inference assertions.                     | skip   |

## `client/`

| Path                                                              | Summary                                                | Tag    |
| ----------------------------------------------------------------- | ------------------------------------------------------ | ------ |
| `packages/better-auth/src/client/client.test.ts`                  | Client SDK round-trip.                                 | future |
| `packages/better-auth/src/client/client-ssr.test.ts`              | SSR client behavior.                                   | skip   |
| `packages/better-auth/src/client/proxy.test.ts`                   | `.api.<endpoint>` proxy.                               | future |
| `packages/better-auth/src/client/query.test.ts`                   | Reactive query helpers.                                | skip   |
| `packages/better-auth/src/client/session-refresh.test.ts`         | Client-side session refresh.                           | future |
| `packages/better-auth/src/client/url.test.ts`                     | URL building.                                          | future |

## `plugins/`

| Path                                                                                 | Summary                                                | Tag    |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------ | ------ |
| `packages/better-auth/src/plugins/access/access.test.ts`                             | RBAC primitives.                                       | future |
| `packages/better-auth/src/plugins/additional-fields/additional-fields.test.ts`       | Adds fields to user/session/account.                   | future |
| `packages/better-auth/src/plugins/admin/admin.test.ts`                                | Admin plugin (impersonation, user mgmt).               | future |
| `packages/better-auth/src/plugins/anonymous/anon.test.ts`                            | Anonymous sign-in.                                     | future |
| `packages/better-auth/src/plugins/bearer/bearer.test.ts`                             | Bearer token → cookie shim.                            | future |
| `packages/better-auth/src/plugins/captcha/captcha.test.ts`                           | hCaptcha/reCAPTCHA/Turnstile.                          | future |
| `packages/better-auth/src/plugins/custom-session/custom-session.test.ts`             | Override session payload.                              | future |
| `packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts` | RFC 8628 device flow.                                  | future |
| `packages/better-auth/src/plugins/email-otp/email-otp.test.ts`                       | Email OTP sign-in.                                     | future |
| `packages/better-auth/src/plugins/generic-oauth/generic-oauth.test.ts`               | Generic OAuth provider.                                | future |
| `packages/better-auth/src/plugins/haveibeenpwned/haveibeenpwned.test.ts`             | HIBP password check.                                   | future |
| `packages/better-auth/src/plugins/jwt/jwt.test.ts`                                   | JWT issuance + JWKS.                                   | future |
| `packages/better-auth/src/plugins/jwt/rotation.test.ts`                              | JWT key rotation.                                      | future |
| `packages/better-auth/src/plugins/last-login-method/last-login-method.test.ts`       | Track last login method per user.                      | future |
| `packages/better-auth/src/plugins/last-login-method/custom-prefix.test.ts`           | Custom prefix for the field.                           | future |
| `packages/better-auth/src/plugins/magic-link/magic-link.test.ts`                     | Magic link sign-in.                                    | future |
| `packages/better-auth/src/plugins/mcp/mcp.test.ts`                                   | MCP plugin (Anthropic Model Context Protocol).         | future |
| `packages/better-auth/src/plugins/mcp/client/mcp-client.test.ts`                     | MCP client.                                            | future |
| `packages/better-auth/src/plugins/multi-session/multi-session.test.ts`               | Multiple concurrent sessions per browser.              | future |
| `packages/better-auth/src/plugins/oauth-proxy/oauth-proxy.test.ts`                   | Proxy OAuth through a fixed origin.                    | future |
| `packages/better-auth/src/plugins/oidc-provider/oidc.test.ts`                        | OIDC provider mode.                                    | future |
| `packages/better-auth/src/plugins/oidc-provider/utils/prompt.test.ts`                | OIDC `prompt` param handling.                          | future |
| `packages/better-auth/src/plugins/one-tap/one-tap.test.ts`                           | Google One Tap.                                        | future |
| `packages/better-auth/src/plugins/one-time-token/one-time-token.test.ts`             | Generic one-time tokens.                               | future |
| `packages/better-auth/src/plugins/open-api/open-api.test.ts`                         | OpenAPI document generation; snapshot.                 | skip   |
| `packages/better-auth/src/plugins/organization/organization.test.ts`                 | Organization CRUD.                                     | future |
| `packages/better-auth/src/plugins/organization/organization-hook.test.ts`            | Organization hooks.                                    | future |
| `packages/better-auth/src/plugins/organization/organization-client-declaration.test.ts` | Client typing.                                      | skip   |
| `packages/better-auth/src/plugins/organization/team.test.ts`                         | Teams (nested under orgs).                             | future |
| `packages/better-auth/src/plugins/organization/client.test.ts`                       | Client SDK for org plugin.                             | skip   |
| `packages/better-auth/src/plugins/organization/routes/crud-org.test.ts`              | Org CRUD endpoints.                                    | future |
| `packages/better-auth/src/plugins/organization/routes/crud-access-control.test.ts`   | Org RBAC routes.                                       | future |
| `packages/better-auth/src/plugins/organization/routes/crud-invites.test.ts`          | Org invite routes.                                     | future |
| `packages/better-auth/src/plugins/organization/routes/crud-members.test.ts`          | Org member routes.                                     | future |
| `packages/better-auth/src/plugins/phone-number/phone-number.test.ts`                 | Phone-number sign-in.                                  | future |
| `packages/better-auth/src/plugins/siwe/siwe.test.ts`                                 | Sign-In With Ethereum.                                 | future |
| `packages/better-auth/src/plugins/test-utils/test-utils.test.ts`                     | Test harness self-test.                                | mvp    |
| `packages/better-auth/src/plugins/two-factor/two-factor.test.ts`                     | TOTP/Backup-codes/OTP.                                 | future |
| `packages/better-auth/src/plugins/username/username.test.ts`                         | Username sign-in.                                      | future |

## `e2e/adapter/test/`

| Path                                                                             | Summary                                          | Tag    |
| -------------------------------------------------------------------------------- | ------------------------------------------------ | ------ |
| `e2e/adapter/test/adapter-factory/adapter-factory.test.ts`                       | Adapter factory contract.                        | mvp    |
| `e2e/adapter/test/memory-adapter/adapter.memory.test.ts`                         | Memory adapter CRUD + consumeOne.                | mvp    |
| `e2e/adapter/test/kysely-adapter/adapter.kysely.sqlite.test.ts`                  | Kysely + SQLite full CRUD.                       | mvp    |
| `e2e/adapter/test/kysely-adapter/adapter.kysely.pg.test.ts`                      | Kysely + Postgres full CRUD.                     | mvp    |
| `e2e/adapter/test/kysely-adapter/adapter.kysely.mysql.test.ts`                   | Kysely + MySQL full CRUD.                        | future |
| `e2e/adapter/test/kysely-adapter/adapter.kysely.mssql.test.ts`                   | Kysely + MSSQL full CRUD.                        | future |
| `e2e/adapter/test/kysely-adapter/adapter.kysely.custom-schema-pg.test.ts`        | Custom schema names on Postgres.                 | future |
| `e2e/adapter/test/kysely-adapter/node-sqlite-dialect.test.ts`                    | Node sqlite dialect.                             | future |
| `e2e/adapter/test/drizzle-adapter/adapter.drizzle.sqlite.test.ts`                | Drizzle adapter.                                 | skip   |
| `e2e/adapter/test/drizzle-adapter/adapter.drizzle.pg.test.ts`                    | Drizzle adapter.                                 | skip   |
| `e2e/adapter/test/drizzle-adapter/adapter.drizzle.mysql.test.ts`                 | Drizzle adapter.                                 | skip   |
| `e2e/adapter/test/drizzle-adapter/adapter.drizzle.plural-joins.test.ts`          | Drizzle joins.                                   | skip   |
| `e2e/adapter/test/prisma-adapter/prisma.sqlite.test.ts`                          | Prisma adapter.                                  | future |
| `e2e/adapter/test/prisma-adapter/prisma.pg.test.ts`                              | Prisma adapter.                                  | future |
| `e2e/adapter/test/prisma-adapter/prisma.mysql.test.ts`                           | Prisma adapter.                                  | future |
| `e2e/adapter/test/mongo-adapter/adapter.mongo-db.test.ts`                        | MongoDB adapter.                                 | future |

## `e2e/integration/`

| Path                                                                             | Summary                                          | Tag    |
| -------------------------------------------------------------------------------- | ------------------------------------------------ | ------ |
| `e2e/integration/vanilla-node/e2e/test.spec.ts`                                  | Playwright smoke: sign-in flow in browser.       | mvp    |
| `e2e/integration/vanilla-node/e2e/cookie-cache-signout.spec.ts`                  | Cookie-cache cleared on sign-out.                | mvp    |
| `e2e/integration/vanilla-node/e2e/domain.spec.ts`                                | Cross-subdomain cookies.                         | future |
| `e2e/integration/vanilla-node/e2e/dynamic-base-url.spec.ts`                      | Dynamic baseURL resolution.                      | future |
| `e2e/integration/vanilla-node/e2e/postgres-js.spec.ts`                           | Live postgres integration.                       | future |
| `e2e/integration/solid-vinxi/e2e/test.spec.ts`                                   | Solid-Vinxi integration.                         | skip   |

## `e2e/smoke/`

| Path                                                       | Summary                                              | Tag    |
| ---------------------------------------------------------- | ---------------------------------------------------- | ------ |
| `e2e/smoke/test/bun.spec.ts`                               | Bun runtime smoke.                                   | skip   |
| `e2e/smoke/test/cloudflare.spec.ts`                        | Cloudflare Workers smoke.                            | skip   |
| `e2e/smoke/test/deno.spec.ts`                              | Deno runtime smoke.                                  | skip   |
| `e2e/smoke/test/esbuild.spec.ts`                           | esbuild bundling smoke.                              | skip   |
| `e2e/smoke/test/vite.spec.ts`                              | Vite bundling smoke.                                 | skip   |
| `e2e/smoke/test/ipv6.spec.ts`                              | IPv6 host smoke.                                     | future |
| `e2e/smoke/test/redis.spec.ts`                             | Redis secondary storage smoke.                       | future |
| `e2e/smoke/test/passkey-preauth.spec.ts`                   | Passkey pre-auth smoke.                              | future |
| `e2e/smoke/test/saml.spec.ts`                              | SAML smoke.                                          | future |
| `e2e/smoke/test/session-token-refresh.spec.ts`             | Token refresh smoke.                                 | mvp    |
| `e2e/smoke/test/typecheck.spec.ts`                         | TS typecheck.                                        | skip   |
| `e2e/smoke/test/fixtures/cloudflare/test/index.test.ts`    | CF fixture smoke.                                    | skip   |

## MVP scoreboard

- `mvp` tests cover: sign-up/sign-in/sign-out (email+password),
  get-session and revocation, password reset, email verification,
  Google OAuth start/callback, account list/link/unlink, basic adapter
  CRUD (memory + Kysely SQLite/Postgres), origin/CSRF, full vs minimal
  bootstrap, cookies (incl. chunking), and a Playwright browser
  smoke.
- `future` tests cover every non-MVP plugin, secondary storage,
  multi-tenant orgs, JWT/OIDC, MFA, telemetry, and the additional
  databases (MySQL/MSSQL/Mongo/Prisma).
- `skip` tests cover front-end framework integrations, TS-only typing
  tests, OpenAPI snapshots, and JS runtime smokes.
