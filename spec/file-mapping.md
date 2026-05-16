# File Mapping: TypeScript → Python

Maps every directory under
`reference/packages/better-auth/src/` to its planned Python counterpart
under `packages/core/src/better_auth/`. Naming rules:

- Kebab-case directory names → snake_case (`social-providers` → `social_providers`).
- Camel-case file basenames → snake_case (`internal-adapter.ts` →
  `internal_adapter.py`).
- TypeScript dotted basenames are flattened (`get-migration-schema.test.ts`
  → `test_get_migration_schema.py`).
- Subdirectories become Python packages (`__init__.py`).

The columns:

- **TS source dir** — relative to `reference/packages/better-auth/src/`.
- **Python target** — relative to `packages/core/src/better_auth/`.
- **Notes** — special considerations.

## Top-level: `better-auth/src/`

| TS source                       | Python target                          | Notes                                                              |
| ------------------------------- | -------------------------------------- | ------------------------------------------------------------------ |
| `index.ts`                      | `__init__.py`                          | Public re-exports.                                                 |
| `version.ts`                    | `version.py`                           | `PACKAGE_VERSION` constant.                                        |
| `state.ts`                      | `state.py`                             | Module-level mutable state holders.                                |
| `social.test.ts`                | `tests/test_social.py`                 | Smoke test for social-provider end-to-end.                         |
| `call.test.ts`                  | `tests/test_call.py`                   | Endpoint-call regression tests.                                    |
| `instrumentation.db.test.ts`    | `tests/test_instrumentation_db.py`     | OTel span coverage for DB.                                         |
| `instrumentation.endpoint.test.ts` | `tests/test_instrumentation_endpoint.py` | OTel span coverage for endpoints.                              |

## `auth/`

| TS source                          | Python target                              | Notes                                            |
| ---------------------------------- | ------------------------------------------ | ------------------------------------------------ |
| `auth/base.ts`                     | `auth/base.py`                             | Shared `Auth` base.                              |
| `auth/full.ts`                     | `auth/full.py`                             | `auth()` factory (all routes + plugins).         |
| `auth/full.test.ts`                | `tests/auth/test_full.py`                  |                                                  |
| `auth/minimal.ts`                  | `auth/minimal.py`                          | `minimalAuth()` (sign-up/sign-in only).          |
| `auth/minimal.test.ts`             | `tests/auth/test_minimal.py`               |                                                  |
| `auth/trusted-origins.ts`          | `auth/trusted_origins.py`                  |                                                  |
| `auth/trusted-origins.test.ts`     | `tests/auth/test_trusted_origins.py`       |                                                  |

## `api/`

| TS source                                | Python target                                | Notes                                                                 |
| ---------------------------------------- | -------------------------------------------- | --------------------------------------------------------------------- |
| `api/index.ts`                           | `api/__init__.py`                            |                                                                       |
| `api/index.test.ts`                      | `tests/api/test_index.py`                    |                                                                       |
| `api/to-auth-endpoints.ts`               | `api/to_auth_endpoints.py`                   | Hook collection + endpoint pipeline.                                  |
| `api/to-auth-endpoints.test.ts`          | `tests/api/test_to_auth_endpoints.py`        |                                                                       |
| `api/check-endpoint-conflicts.test.ts`   | `tests/api/test_check_endpoint_conflicts.py` |                                                                       |
| `api/middlewares/`                       | `api/middlewares/`                           |                                                                       |
| `api/middlewares/index.ts`               | `api/middlewares/__init__.py`                |                                                                       |
| `api/middlewares/origin-check.ts`        | `api/middlewares/origin_check.py`            | `originCheck`, `formCsrfMiddleware`.                                  |
| `api/middlewares/origin-check.test.ts`   | `tests/api/middlewares/test_origin_check.py` |                                                                       |
| `api/middlewares/authorization.ts`       | `api/middlewares/authorization.py`           |                                                                       |
| `api/middlewares/authorization.test.ts`  | `tests/api/middlewares/test_authorization.py`|                                                                       |
| `api/rate-limiter/`                      | `api/rate_limiter/`                          |                                                                       |
| `api/routes/`                            | `api/routes/`                                |                                                                       |
| `api/routes/index.ts`                    | `api/routes/__init__.py`                     |                                                                       |
| `api/routes/account.ts`                  | `api/routes/account.py`                      | `listUserAccounts`, `linkSocialAccount`, `unlinkAccount`, `getAccessToken`, `refreshToken`, `accountInfo`. |
| `api/routes/callback.ts`                 | `api/routes/callback.py`                     | OAuth callback (`/callback/:id`).                                     |
| `api/routes/email-verification.ts`       | `api/routes/email_verification.py`           | `sendVerificationEmail`, `verifyEmail`, `createEmailVerificationToken`.|
| `api/routes/error.ts`                    | `api/routes/error.py`                        | HTML error page.                                                      |
| `api/routes/ok.ts`                       | `api/routes/ok.py`                           | `GET /ok`.                                                            |
| `api/routes/password.ts`                 | `api/routes/password.py`                     | request/reset/verify password.                                        |
| `api/routes/session.ts`                  | `api/routes/session.py`                      | `getSession`, session middlewares, revoke endpoints.                  |
| `api/routes/sign-in.ts`                  | `api/routes/sign_in.py`                      | `signInEmail`, `signInSocial`.                                        |
| `api/routes/sign-out.ts`                 | `api/routes/sign_out.py`                     |                                                                       |
| `api/routes/sign-up.ts`                  | `api/routes/sign_up.py`                      |                                                                       |
| `api/routes/update-session.ts`           | `api/routes/update_session.py`               |                                                                       |
| `api/routes/update-user.ts`              | `api/routes/update_user.py`                  | `updateUser`, `changePassword`, `setPassword`, `deleteUser`, `changeEmail`. |
| `api/routes/*.test.ts`                   | `tests/api/routes/test_<name>.py`            | Per-route tests.                                                      |
| `api/state/`                             | `api/state/`                                 |                                                                       |
| `api/state/oauth.ts`                     | `api/state/oauth.py`                         | OAuth state persistence.                                              |
| `api/state/should-session-refresh.ts`    | `api/state/should_session_refresh.py`        |                                                                       |

## `adapters/`

| TS source                                 | Python target                            | Notes                                                                 |
| ----------------------------------------- | ---------------------------------------- | --------------------------------------------------------------------- |
| `adapters/index.ts`                       | `adapters/__init__.py`                   | Factory re-exports.                                                   |
| `adapters/memory-adapter/`                | `adapters/memory_adapter/`               | In-memory adapter (tests).                                            |
| `adapters/kysely-adapter/`                | `adapters/sqlalchemy_adapter/` or `adapters/sql_adapter/` | TS uses Kysely; Python port uses SQLAlchemy (or asyncpg/raw SQL).     |
| `adapters/drizzle-adapter/`               | n/a (TS-only)                             | Drizzle is a TS ORM; no Python analog. Skip.                          |
| `adapters/prisma-adapter/`                | `adapters/prisma_adapter/` (optional)    | Prisma has a Python client; defer to a future release.                |
| `adapters/mongodb-adapter/`               | `adapters/mongodb_adapter/`              | Use `motor` / `pymongo`.                                              |

## `client/`

| TS source                | Python target                                          | Notes                                              |
| ------------------------ | ------------------------------------------------------ | -------------------------------------------------- |
| `client/`                | `client/`                                              | A typed Python HTTP client (httpx-based).          |
| `client/react/`, `client/svelte/`, `client/vue/`, `client/solid/`, `client/lynx/` | n/a | Front-end framework integrations; not ported. |
| `client/plugins/`        | `client/plugins/`                                      | Client-side plugin extensions (kept lean).         |
| `client/vanilla.ts`      | `client/__init__.py` (top-level `BetterAuthClient`)    |                                                    |
| `client/query.ts`        | `client/query.py`                                      |                                                    |
| `client/session-atom.ts` | n/a                                                    | Reactivity primitive; not relevant in Python.      |
| `client/session-refresh.ts` | `client/session_refresh.py`                         |                                                    |
| `client/proxy.ts`        | `client/proxy.py`                                      | The `.api.<endpoint>` chained-attr proxy.          |
| `client/parser.ts`       | `client/parser.py`                                     |                                                    |
| `client/path-to-object.ts` | `client/path_to_object.py`                           |                                                    |
| `client/url.test.ts`     | `tests/client/test_url.py`                             |                                                    |
| `client/test-plugin.ts`  | `client/test_plugin.py`                                |                                                    |
| `client/types.ts`        | `client/types.py`                                      | Pydantic models or `TypedDict`s.                   |
| `client/focus-manager.ts`, `client/online-manager.ts`, `client/broadcast-channel.ts`, `client/fetch-plugins.ts` | n/a / optional | Browser-specific. |

## `context/`

| TS source                          | Python target                          | Notes                                                |
| ---------------------------------- | -------------------------------------- | ---------------------------------------------------- |
| `context/create-context.ts`        | `context/create_context.py`            | Per-request context builder.                         |
| `context/create-context.test.ts`   | `tests/context/test_create_context.py` |                                                      |
| `context/init.ts`                  | `context/init.py`                      | Auth init (plugins, schemas, secrets).               |
| `context/init.test.ts`             | `tests/context/test_init.py`           |                                                      |
| `context/init-minimal.ts`          | `context/init_minimal.py`              |                                                      |
| `context/init-minimal.test.ts`     | `tests/context/test_init_minimal.py`   |                                                      |
| `context/helpers.ts`               | `context/helpers.py`                   | `getAwaitableValue`, `pickSource`, etc.              |
| `context/secret-utils.ts`          | `context/secret_utils.py`              | Secret rotation helpers.                             |

## `cookies/`

| TS source                          | Python target                          | Notes                                                |
| ---------------------------------- | -------------------------------------- | ---------------------------------------------------- |
| `cookies/index.ts`                 | `cookies/__init__.py`                  |                                                      |
| `cookies/cookie-utils.ts`          | `cookies/cookie_utils.py`              | Parse / serialize helpers.                           |
| `cookies/session-store.ts`         | `cookies/session_store.py`             | Chunking + account cookie helpers.                   |
| `cookies/cookies.test.ts`          | `tests/cookies/test_cookies.py`        |                                                      |

## `crypto/`

| TS source                          | Python target                          | Notes                                                |
| ---------------------------------- | -------------------------------------- | ---------------------------------------------------- |
| `crypto/index.ts`                  | `crypto/__init__.py`                   |                                                      |
| `crypto/buffer.ts`                 | `crypto/buffer.py`                     | `Uint8Array` helpers → `bytes` utilities.            |
| `crypto/jwt.ts`                    | `crypto/jwt.py`                        | HS256 sign/verify + JWE encode/decode.               |
| `crypto/password.ts`               | `crypto/password.py`                   | Scrypt by default; needs `bcrypt`/`argon2` fallback. |
| `crypto/password.test.ts`          | `tests/crypto/test_password.py`        |                                                      |
| `crypto/random.ts`                 | `crypto/random.py`                     | `secrets.token_urlsafe` wrappers.                    |
| `crypto/secret-rotation.test.ts`   | `tests/crypto/test_secret_rotation.py` |                                                      |

## `db/`

| TS source                              | Python target                                | Notes                                                                |
| -------------------------------------- | -------------------------------------------- | -------------------------------------------------------------------- |
| `db/index.ts`                          | `db/__init__.py`                             |                                                                      |
| `db/adapter-base.ts`                   | `db/adapter_base.py`                         |                                                                      |
| `db/adapter-kysely.ts`                 | `db/adapter_sqlalchemy.py` (rename)          | Kysely wrapper → SQLAlchemy core wrapper.                            |
| `db/db.test.ts`                        | `tests/db/test_db.py`                        |                                                                      |
| `db/field-converter.ts`                | `db/field_converter.py`                      |                                                                      |
| `db/field.ts`                          | `db/field.py`                                |                                                                      |
| `db/get-migration.ts`                  | `db/get_migration.py`                        |                                                                      |
| `db/get-migration-schema.test.ts`      | `tests/db/test_get_migration_schema.py`      |                                                                      |
| `db/get-schema.ts`                     | `db/get_schema.py`                           |                                                                      |
| `db/internal-adapter.ts`               | `db/internal_adapter.py`                     | The big one — wraps `DBAdapter`.                                     |
| `db/internal-adapter.test.ts`          | `tests/db/test_internal_adapter.py`          |                                                                      |
| `db/schema.ts`                         | `db/schema.py`                               | User/Session/Account/Verification field maps + parse helpers.        |
| `db/secondary-storage.test.ts`         | `tests/db/test_secondary_storage.py`         |                                                                      |
| `db/to-zod.ts`                         | `db/to_pydantic.py` (rename)                 | Zod schema → Pydantic model.                                         |
| `db/to-zod.test.ts`                    | `tests/db/test_to_pydantic.py`               |                                                                      |
| `db/verification-token-storage.ts`     | `db/verification_token_storage.py`           |                                                                      |
| `db/with-hooks.ts`                     | `db/with_hooks.py`                           | Database operation hooks (create/update/delete pre/post).            |

## `integrations/`

| TS source                              | Python target                                | Notes                                                                |
| -------------------------------------- | -------------------------------------------- | -------------------------------------------------------------------- |
| `integrations/cookie-plugin-guard.ts`  | `integrations/cookie_plugin_guard.py`        |                                                                      |
| `integrations/next-js.ts`              | n/a                                          | Next.js-specific.                                                    |
| `integrations/next-js.test.ts`         | n/a                                          |                                                                      |
| `integrations/node.ts`                 | `integrations/asgi.py` (rename)              | Node-style integration → ASGI middleware.                            |
| `integrations/solid-start.ts`          | n/a                                          | Solid-specific.                                                      |
| `integrations/svelte-kit.ts`           | n/a                                          | SvelteKit-specific.                                                  |
| `integrations/tanstack-start.ts`       | n/a                                          | Tanstack-specific.                                                   |
| `integrations/tanstack-start-solid.ts` | n/a                                          | Tanstack/Solid.                                                      |
| —                                      | `integrations/fastapi.py` (new)              | New: FastAPI integration.                                            |
| —                                      | `integrations/django.py` (new)               | New: Django integration.                                             |
| —                                      | `integrations/flask.py` (new)                | New: Flask/WSGI integration.                                         |

## `oauth2/`

| TS source                       | Python target                           | Notes                                                |
| ------------------------------- | --------------------------------------- | ---------------------------------------------------- |
| `oauth2/index.ts`               | `oauth2/__init__.py`                    |                                                      |
| `oauth2/errors.ts`              | `oauth2/errors.py`                      |                                                      |
| `oauth2/link-account.ts`        | `oauth2/link_account.py`                |                                                      |
| `oauth2/link-account.test.ts`   | `tests/oauth2/test_link_account.py`     |                                                      |
| `oauth2/state.ts`               | `oauth2/state.py`                       | OAuth state cookie / DB storage.                     |
| `oauth2/utils.ts`               | `oauth2/utils.py`                       | Token encryption, etc.                               |
| `oauth2/utils.test.ts`          | `tests/oauth2/test_utils.py`            |                                                      |

## `social-providers/`

| TS source                       | Python target                           | Notes                                                |
| ------------------------------- | --------------------------------------- | ---------------------------------------------------- |
| `social-providers/index.ts`     | `social_providers/__init__.py`          | Re-exports each provider plus the enum.              |
| (per provider in `core/src/social-providers/`) | `social_providers/<name>.py` | One module per provider: google, github, apple, facebook, discord, microsoft_entra_id, twitch, gitlab, dropbox, linkedin, reddit, spotify, twitter, kakao, kick, line, linear, naver, notion, paybin, paypal, polar, railway, roblox, salesforce, slack, tiktok, vercel, vk, wechat, zoom, atlassian, cognito, figma, huggingface. |

## `plugins/`

| TS source                                            | Python target                                        | Notes                                            |
| ---------------------------------------------------- | ---------------------------------------------------- | ------------------------------------------------ |
| `plugins/access/`                                    | `plugins/access/`                                    | RBAC primitives.                                 |
| `plugins/additional-fields/`                         | `plugins/additional_fields/`                         |                                                  |
| `plugins/admin/`                                     | `plugins/admin/`                                     |                                                  |
| `plugins/admin/access/`                              | `plugins/admin/access/`                              |                                                  |
| `plugins/anonymous/`                                 | `plugins/anonymous/`                                 |                                                  |
| `plugins/bearer/`                                    | `plugins/bearer/`                                    |                                                  |
| `plugins/captcha/`                                   | `plugins/captcha/`                                   |                                                  |
| `plugins/captcha/verify-handlers/`                   | `plugins/captcha/verify_handlers/`                   |                                                  |
| `plugins/custom-session/`                            | `plugins/custom_session/`                            |                                                  |
| `plugins/device-authorization/`                      | `plugins/device_authorization/`                      |                                                  |
| `plugins/email-otp/`                                 | `plugins/email_otp/`                                 |                                                  |
| `plugins/generic-oauth/`                             | `plugins/generic_oauth/`                             |                                                  |
| `plugins/generic-oauth/providers/`                   | `plugins/generic_oauth/providers/`                   |                                                  |
| `plugins/haveibeenpwned/`                            | `plugins/haveibeenpwned/`                            |                                                  |
| `plugins/jwt/`                                       | `plugins/jwt/`                                       |                                                  |
| `plugins/last-login-method/`                         | `plugins/last_login_method/`                         |                                                  |
| `plugins/magic-link/`                                | `plugins/magic_link/`                                |                                                  |
| `plugins/mcp/`                                       | `plugins/mcp/`                                       |                                                  |
| `plugins/mcp/client/`                                | `plugins/mcp/client/`                                |                                                  |
| `plugins/multi-session/`                             | `plugins/multi_session/`                             |                                                  |
| `plugins/oauth-proxy/`                               | `plugins/oauth_proxy/`                               |                                                  |
| `plugins/oidc-provider/`                             | `plugins/oidc_provider/`                             |                                                  |
| `plugins/oidc-provider/utils/`                       | `plugins/oidc_provider/utils/`                       |                                                  |
| `plugins/one-tap/`                                   | `plugins/one_tap/`                                   |                                                  |
| `plugins/one-time-token/`                            | `plugins/one_time_token/`                            |                                                  |
| `plugins/open-api/`                                  | `plugins/open_api/`                                  |                                                  |
| `plugins/open-api/__snapshots__/`                    | `tests/plugins/open_api/snapshots/`                  | Move snapshots under tests.                      |
| `plugins/organization/`                              | `plugins/organization/`                              |                                                  |
| `plugins/organization/access/`                       | `plugins/organization/access/`                       |                                                  |
| `plugins/organization/routes/`                       | `plugins/organization/routes/`                       |                                                  |
| `plugins/phone-number/`                              | `plugins/phone_number/`                              |                                                  |
| `plugins/siwe/`                                      | `plugins/siwe/`                                      | Sign-In With Ethereum.                           |
| `plugins/test-utils/`                                | `plugins/test_utils/`                                |                                                  |
| `plugins/two-factor/`                                | `plugins/two_factor/`                                |                                                  |
| `plugins/two-factor/backup-codes/`                   | `plugins/two_factor/backup_codes/`                   |                                                  |
| `plugins/two-factor/otp/`                            | `plugins/two_factor/otp/`                            |                                                  |
| `plugins/two-factor/totp/`                           | `plugins/two_factor/totp/`                           |                                                  |
| `plugins/username/`                                  | `plugins/username/`                                  |                                                  |

## `test-utils/`

| TS source                  | Python target                  | Notes                              |
| -------------------------- | ------------------------------ | ---------------------------------- |
| `test-utils/`              | `test_utils/`                  | `get_test_instance()` and friends. |

## `types/`

| TS source                  | Python target                  | Notes                              |
| -------------------------- | ------------------------------ | ---------------------------------- |
| `types/index.ts`           | `types/__init__.py`            |                                    |
| `types/adapter.ts`         | `types/adapter.py`             | Re-exports from `core/db/adapter`. |
| `types/api.ts`             | `types/api.py`                 |                                    |
| `types/auth.ts`            | `types/auth.py`                |                                    |
| `types/helper.ts`          | `types/helper.py`              | Mostly TS type-level helpers; many drop in Python. |
| `types/models.ts`          | `types/models.py`              | Pydantic / dataclass User/Session/Account/Verification. |
| `types/plugins.ts`         | `types/plugins.py`             | Plugin inference helpers.          |
| `types/types.test.ts`      | n/a                            | Type-only tests; not portable.     |

## `utils/`

| TS source                          | Python target                          | Notes                                                     |
| ---------------------------------- | -------------------------------------- | --------------------------------------------------------- |
| `utils/index.ts`                   | `utils/__init__.py`                    |                                                           |
| `utils/boolean.ts`                 | `utils/boolean.py`                     |                                                           |
| `utils/constants.ts`               | `utils/constants.py`                   |                                                           |
| `utils/date.ts`                    | `utils/date.py`                        | `getDate(seconds, unit)` etc.                             |
| `utils/get-request-ip.ts`          | `utils/get_request_ip.py`              | X-Forwarded-For parsing.                                  |
| `utils/hashing.ts`                 | `utils/hashing.py`                     |                                                           |
| `utils/hide-metadata.ts`           | `utils/hide_metadata.py`               | `HIDE_METADATA`.                                          |
| `utils/is-api-error.ts`            | `utils/is_api_error.py`                |                                                           |
| `utils/is-atom.ts`                 | n/a                                    | Reactivity helper; not relevant.                          |
| `utils/is-promise.ts`              | `utils/is_awaitable.py`                | Inspect `inspect.isawaitable`.                            |
| `utils/middleware-response.ts`     | `utils/middleware_response.py`         |                                                           |
| `utils/password.ts`                | `utils/password.py`                    |                                                           |
| `utils/plugin-helper.ts`           | `utils/plugin_helper.py`               |                                                           |
| `utils/shim.ts`                    | n/a                                    | Browser/runtime shim; usually unnecessary.                |
| `utils/time.ts`                    | `utils/time.py`                        | `sec("7d")` etc.                                          |
| `utils/url.ts`                     | `utils/url.py`                         |                                                           |
| `utils/url.test.ts`                | `tests/utils/test_url.py`              |                                                           |
| `utils/wildcard.ts`                | `utils/wildcard.py`                    | Glob-style host matcher for trusted origins.              |

## Cross-package: shared core types

The TS monorepo also includes `reference/packages/core/`, which most of
`better-auth` imports from. The Python port should merge the two into a
single namespace package (`better_auth.core` or just under
`better_auth`) since Python has no equivalent type-only sub-package
need.

| TS source (in `reference/packages/core/src/`)             | Python target (under `packages/core/src/better_auth/core/`) |
| --------------------------------------------------------- | ----------------------------------------------------------- |
| `api/`                                                    | `core/api/`                                                 |
| `async_hooks/`                                            | `core/async_hooks/`                                         |
| `context/`                                                | `core/context/`                                             |
| `db/` (incl. `adapter/`, `schema/`, `plugin.ts`)          | `core/db/`                                                  |
| `env/`                                                    | `core/env/`                                                 |
| `error/`                                                  | `core/error/`                                               |
| `instrumentation/`                                        | `core/instrumentation/`                                     |
| `oauth2/`                                                 | `core/oauth2/`                                              |
| `social-providers/`                                       | `core/social_providers/`                                    |
| `types/`                                                  | `core/types/`                                               |
| `utils/`                                                  | `core/utils/`                                               |
