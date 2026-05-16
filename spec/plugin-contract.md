# Plugin Contract Specification

The plugin interface is defined in
`reference/packages/core/src/types/plugin.ts`
(re-exported from `@better-auth/core`).

Note: a thin extension type is also declared in
`reference/packages/better-auth/src/types/plugins.ts`, but the canonical
`BetterAuthPlugin` lives in core.

## `BetterAuthPlugin` (verbatim)

From `reference/packages/core/src/types/plugin.ts`:

```ts
import type {
  Endpoint,
  EndpointContext,
  InputContext,
  Middleware,
} from "better-call";
import type { Migration } from "kysely";
import type { AuthMiddleware } from "../api";
import type { BetterAuthPluginDBSchema } from "../db";
import type { RawError } from "../utils/error-codes";
import type { AuthContext } from "./context";
import type { Awaitable, LiteralString } from "./helper";
import type { BetterAuthOptions } from "./init-options";

type DeepPartial<T> = T extends Function
  ? T
  : T extends object
    ? { [K in keyof T]?: DeepPartial<T[K]> }
    : T;

export type HookEndpointContext = Partial<
  EndpointContext<string, any> & Omit<InputContext<string, any>, "method">
> & {
  path?: string;
  context: AuthContext & {
    returned?: unknown | undefined;
    responseHeaders?: Headers | undefined;
  };
  headers?: Headers | undefined;
};

export type BetterAuthPluginErrorCodePart = {
  /**
   * The error codes returned by the plugin
   */
  $ERROR_CODES?: Record<string, RawError>;
};

export type BetterAuthPlugin = BetterAuthPluginErrorCodePart & {
  id: LiteralString;
  version?: string | undefined;
  /**
   * The init function is called when the plugin is initialized.
   * You can return a new context or modify the existing context.
   */
  init?:
    | ((ctx: AuthContext) =>
        | Awaitable<{
            context?: DeepPartial<Omit<AuthContext, "options">> &
              Record<string, unknown>;
            options?: Partial<BetterAuthOptions>;
          }>
        | void
        | Promise<void>)
    | undefined;
  endpoints?:
    | {
        [key: string]: Endpoint;
      }
    | undefined;
  middlewares?:
    | {
        path: string;
        middleware: Middleware;
      }[]
    | undefined;
  onRequest?:
    | ((
        request: Request,
        ctx: AuthContext,
      ) => Promise<
        | { response: Response }
        | { request: Request }
        | void
      >)
    | undefined;
  onResponse?:
    | ((
        response: Response,
        ctx: AuthContext,
      ) => Promise<{ response: Response } | void>)
    | undefined;
  hooks?:
    | {
        before?: {
          matcher: (context: HookEndpointContext) => boolean;
          handler: AuthMiddleware;
        }[];
        after?: {
          matcher: (context: HookEndpointContext) => boolean;
          handler: AuthMiddleware;
        }[];
      }
    | undefined;
  /**
   * Schema the plugin needs
   *
   * This will also be used to migrate the database. If the fields are dynamic from the plugins
   * configuration each time the configuration is changed a new migration will be created.
   *
   * NOTE: If you want to create migrations manually using
   * migrations option or any other way you
   * can disable migration per table basis.
   *
   * @example
   * schema: {
   *   user: { fields: { email: { type: "string" }, emailVerified: { type: "boolean", defaultValue: false } } }
   * } as AuthPluginSchema
   */
  schema?: BetterAuthPluginDBSchema | undefined;
  /**
   * The migrations of the plugin. If you define schema that will automatically create
   * migrations for you.
   *
   * Only use this if you don't want to use the schema option and you disabled migrations for
   * the tables.
   */
  migrations?: Record<string, Migration> | undefined;
  /**
   * The options of the plugin
   */
  options?: Record<string, any> | undefined;
  /**
   * types to be inferred
   */
  $Infer?: Record<string, any> | undefined;
  /**
   * The rate limit rules to apply to specific paths.
   */
  rateLimit?:
    | {
        window: number;
        max: number;
        pathMatcher: (path: string) => boolean;
      }[]
    | undefined;
  /**
   * All database operations that are performed by the plugin
   *
   * This will override the default database operations
   */
  adapter?: {
    [key: string]: (...args: any[]) => Awaitable<any>;
  };
};
```

## Field-by-field semantics

### `id: LiteralString` (required)
- Globally unique identifier. Used by `ctx.context.hasPlugin(id)` and to
  de-duplicate plugin registration. Must be a literal string to participate
  in TypeScript inference (`InferPluginIDs`).

### `version?: string`
- Free-form. Plugins inside this repo set it to `PACKAGE_VERSION` from
  `better-auth/src/version.ts`. Surfaced in telemetry.

### `$ERROR_CODES?: Record<string, RawError>`
- Plugin-scoped error codes, merged into the global `$ERROR_CODES` map
  exposed on the `auth` instance. Each value is a string message or a
  `{ message: string; description?: string }` tuple (`RawError`).
- See `reference/packages/core/src/utils/error-codes.ts` and
  `reference/packages/better-auth/src/plugins/username/error-codes.ts` for examples.

### `init?(ctx: AuthContext) => Awaitable<{ context?; options? } | void>`
- Runs once during `auth()` initialization.
- Returning `{ context }` deeply merges into the live `AuthContext`. Plugins
  use this to inject helpers (e.g. token issuers, JWKS providers, mailer
  wrappers) under arbitrary keys.
- Returning `{ options }` replaces or augments `BetterAuthOptions` before
  the rest of init runs (used by the JWT plugin to register secondary
  secrets, by the organization plugin to extend `user.additionalFields`,
  etc.).

### `endpoints?: { [key: string]: Endpoint }`
- Each entry is created via `createAuthEndpoint(path, options, handler)`.
- The key is the plugin's local export name; the `path` inside the endpoint
  is what's mounted on the router. Endpoints are merged in
  `api/to-auth-endpoints.ts` and surfaced on the typed `auth.api`.

### `middlewares?: { path: string; middleware: Middleware }[]`
- Path-scoped middleware. The `path` is a `better-call` route pattern.
  Middlewares run before the endpoint handler.
- Example: `bearer` plugin attaches a middleware that rewrites the
  `Authorization: Bearer …` header into a `Cookie` header so downstream
  endpoints see a session cookie.

### `onRequest?(request, ctx)`
- Runs once per request, before any endpoint dispatch.
- Return `{ response }` to short-circuit and return that response.
- Return `{ request }` to replace the incoming request (e.g. cookie rewrite).
- Return nothing/undefined to continue.

### `onResponse?(response, ctx)`
- Runs once per request, after the endpoint handler.
- Return `{ response }` to replace the outgoing response.

### `hooks?: { before?; after? }`
- Each hook is `{ matcher(ctx) => boolean; handler: AuthMiddleware }`.
- `before` hooks run before the endpoint handler and can:
  - throw an `APIError` to abort,
  - return `{ context: { … } }` to merge fields into the endpoint context.
- `after` hooks run after the handler and receive `context.returned` (the
  handler's return value, before serialization) and `context.responseHeaders`.
  They may mutate response headers, e.g. set additional cookies.

### `schema?: BetterAuthPluginDBSchema`
- Adds tables / fields. Field attributes (`type`, `required`, `defaultValue`,
  `references`, `unique`, `input`, `transform`, `bigint`, etc.) are merged
  with core schema. Field types are defined in
  `reference/packages/core/src/db/schema/` and `reference/packages/core/src/db/type.ts`.
- The `getMigrations` runner in `reference/packages/better-auth/src/db/get-migration.ts`
  uses the merged schema to generate ALTER/CREATE statements for the Kysely
  adapter.

### `migrations?: Record<string, Migration>`
- Escape hatch for plugins that prefer hand-written Kysely migrations.

### `options?: Record<string, any>`
- A pass-through bag for plugin-level config; available at
  `ctx.context.plugins[id].options` (and via the plugin's own closure).

### `$Infer?: Record<string, any>`
- Phantom types used to surface plugin shapes (e.g. extra body keys) into
  the inferred client. No runtime behavior.

### `rateLimit?: { window; max; pathMatcher }[]`
- Per-plugin rate-limit rules, merged with global rate-limit config in
  `reference/packages/better-auth/src/api/rate-limiter/`.

### `adapter?: { [key: string]: (...args) => Awaitable<any> }`
- Used to override internal-adapter calls (rare).

## Plugin lifecycle (executive summary)

1. `auth(options)` calls `init` (`context/init.ts`) which:
   - builds the base `AuthContext`,
   - iterates `options.plugins` and invokes each plugin's `init`,
   - merges returned `context` / `options` deep-partial style,
   - then collects `endpoints`, `middlewares`, `hooks`, `onRequest`,
     `onResponse`, `schema`, `rateLimit`, `$ERROR_CODES`, `migrations`,
     `adapter` into the auth instance.
2. Endpoints are run through `to-auth-endpoints.ts` to attach the standard
   `optionsMiddleware` and to wire `before/after` hook matchers.
3. Requests flow: `onRequest` → `middlewares` → `before` hooks → endpoint
   handler → `after` hooks → `onResponse`.

## Example plugins

### 1) `bearer` — Authorization header → session cookie

File: `reference/packages/better-auth/src/plugins/bearer/index.ts`

Shape (excerpt):
```ts
export const bearer = (options?: BearerOptions) => ({
  id: "bearer",
  version: PACKAGE_VERSION,
  hooks: {
    before: [{ matcher(ctx) { /* has Authorization: Bearer */ }, handler }],
  },
} satisfies BetterAuthPlugin);
```

This plugin uses only `hooks.before` to rewrite the request — no DB schema,
no endpoints. Test file: `bearer.test.ts`.

### 2) `username` — additional sign-in identifier

Files: `reference/packages/better-auth/src/plugins/username/`
- `index.ts` — endpoint + hooks declaration.
- `schema.ts` — adds `username` field to the `user` table.
- `error-codes.ts` — plugin-scoped `$ERROR_CODES`.
- `client.ts` — typed client extension.

Demonstrates the full surface: `id`, `schema`, `endpoints`, `hooks`,
`$ERROR_CODES`, `$Infer`.

### 3) `jwt` — JWT issuance

Files: `reference/packages/better-auth/src/plugins/jwt/`
- `index.ts`
- `rotation.ts` / `rotation.test.ts`
- Uses `init` to register secret rotation; exposes `/token` and `/jwks`
  endpoints; uses `schema` to add a `jwks` table.

## Python port guidance

A `BetterAuthPlugin` becomes a Python `Protocol` / dataclass with the same
field names converted to snake_case where appropriate (`$ERROR_CODES` →
`error_codes`, etc.). Each callback receives an `AuthContext` analog and is
expected to be a normal `async def` returning the documented shape. The
core invariants to preserve:

- `id` uniqueness and literal typing.
- Deep-merge semantics for `init` returns.
- Hook matchers run with the same `HookEndpointContext` (path, body, query,
  headers, context).
- Endpoint ordering: plugin endpoints overlay last and may shadow core
  endpoints (checked by `api/check-endpoint-conflicts.ts`).
