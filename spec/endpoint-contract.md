# Endpoint Contract Specification

## Where is `createAuthEndpoint`?

The factory lives in
`reference/packages/core/src/api/index.ts` (re-exported from
`@better-auth/core/api`). It wraps `createEndpoint` from the
`better-call` library so that every endpoint is augmented with the
`optionsMiddleware` (which injects the `AuthContext` into the call
context) and an APIError header-attachment shim.

The wrapper is exported from the user-facing package via
`reference/packages/better-auth/src/api/index.ts`.

## Signature (verbatim)

```ts
export const optionsMiddleware = createMiddleware(async () => {
  // empty body; this exists solely to participate in better-call's `use` chain
  // so that the AuthContext type can be inferred into handlers.
  return {} as AuthContext;
});

export const createAuthMiddleware = createMiddleware.create({
  use: [
    optionsMiddleware,
    /** Only for post hooks */
    createMiddleware(async () => {
      return {} as {
        returned?: unknown | undefined;
        responseHeaders?: Headers | undefined;
      };
    }),
  ],
});

export function createAuthEndpoint<Path, Options, R>(
  path: Path,
  options: Options,
  handler: (ctx: EndpointContext<Path, Options, AuthContext>) => Promise<R>,
): StrictEndpoint<Path, Options, R>;

export function createAuthEndpoint<Path, Options, R>(
  options: Options,
  handler: (ctx: EndpointContext<Path, Options, AuthContext>) => Promise<R>,
): StrictEndpoint<Path, Options, R>;
```

The two-argument overload omits `path`; used by plugins that mount a
single endpoint by name and let the plugin loader assign the path.

Internally the wrapper:

1. Prepends `optionsMiddleware` to `options.use` (so every endpoint
   resolves `AuthContext`).
2. Wraps `handler` in `runWithEndpointContext` so AsyncLocalStorage can
   recover the context (`@better-auth/core/context`).
3. On thrown `APIError`, attaches `ctx.responseHeaders` to the error via
   `kAPIErrorHeaderSymbol` so the outer pipeline still emits any
   `Set-Cookie` headers staged before the throw.

## `EndpointOptions`

From `better-call`, with conventions used by core:

```
method:    "GET" | "POST" | ("GET" | "POST")[];
operationId?: string;
body?:     ZodSchema;
query?:    ZodSchema;
params?:   ZodSchema;
requireHeaders?: boolean;
requireRequest?: boolean;
use?:      Middleware[];
metadata?: {
  allowedMediaTypes?: ("application/json" | "application/x-www-form-urlencoded" | ...)[];
  scope?: "server";       // hides from client SDK
  isAction?: boolean;
  $Infer?: { body?: any; query?: any; returned?: any };
  openapi?: OpenAPISchemaObject;
  ...HIDE_METADATA;
};
```

`HIDE_METADATA` (from `utils/hide-metadata.ts`) marks the endpoint as
internal — it's omitted from the generated OpenAPI document and from
the typed client.

## `EndpointContext` — what handlers receive

`ctx: EndpointContext<Path, Options, AuthContext>` exposes:

```
ctx.path:       Path
ctx.method:     "GET" | "POST" | ...
ctx.body:       z.infer<Options["body"]>
ctx.query:      z.infer<Options["query"]>
ctx.params:     z.infer<Options["params"]>     // path parameters
ctx.request:    Request | undefined            // node/web Request
ctx.headers:    Headers
ctx.context:    AuthContext                    // the auth-wide context
ctx.responseHeaders: Headers                   // mutated by setCookie, setHeader

// Better-call accessors:
ctx.setHeader(name, value)
ctx.setCookie(name, value, options)
ctx.setSignedCookie(name, value, secret, options)
ctx.getCookie(name)
ctx.getSignedCookie(name, secret)
ctx.json(body, init?)                          // return JSON response
ctx.redirect(url, status?)                     // throws a redirect response
ctx.error(httpStatus, body?)
```

`ctx.context` (the `AuthContext`) is the union of init-time fields plus
plugin-injected fields. Key entries (see `core/src/types/context.ts`):

```
appName, baseURL, version,
options, trustedOrigins, trustedProviders, isTrustedOrigin,
oauthConfig: { storeStateStrategy, skipStateCookieCheck? },
newSession, session, setNewSession,
socialProviders, authCookies, logger, rateLimit,
adapter, internalAdapter,
createAuthCookie, secret, secretConfig,
sessionConfig: { updateAge, expiresIn, freshAge, cookieRefreshCache },
generateId, secondaryStorage,
password: { hash, verify, config, checkPassword },
tables, runMigrations, publishTelemetry,
hasPlugin,
```

## Middleware chain order

For each request:

1. **`onRequest` plugin hooks** (`onRequest(request, ctx)` from every
   plugin) — may return `{ response }` to short-circuit or
   `{ request }` to replace the incoming request.
2. **Path lookup + path-scoped middlewares** registered via
   `plugin.middlewares: [{ path, middleware }]` (better-call applies
   them by route match).
3. **Endpoint `use:` chain** — declared on the endpoint itself.
   `optionsMiddleware` is auto-prepended. For routes that need a
   session: `sessionMiddleware`, `sensitiveSessionMiddleware`,
   `freshSessionMiddleware`, `requestOnlySessionMiddleware` (from
   `api/routes/session.ts`).
4. **`before` plugin hooks** — collected by `to-auth-endpoints.ts`. Each
   hook has `{ matcher(ctx) => boolean; handler: AuthMiddleware }`. The
   first hook whose matcher returns true runs; if it returns
   `{ context: { … } }` the keys are merged into `ctx` (excluding
   `headers`, which is merged into `ctx.headers` separately). If it
   returns a response, that response short-circuits.
5. **Endpoint handler.** Runs inside `runWithEndpointContext` so
   AsyncLocalStorage can recover `ctx` from inside helpers.
6. **`after` plugin hooks** — receive `ctx.returned` (handler's return
   value pre-serialization) and may mutate `ctx.responseHeaders` or
   replace the response.
7. **`onResponse` plugin hooks** — final chance to rewrite the
   `Response`.

Hooks are sourced both from `options.hooks?.{before,after}` (user-level)
and from each plugin's `hooks` field. The implementation in
`reference/packages/better-auth/src/api/to-auth-endpoints.ts` (around
lines 170-330) shows the full collection order: user hooks first, then
plugins in registration order.

## Error handling

- Inside a handler, throw `APIError.from(status, { code, message })` or
  `APIError.fromStatus(status, { message })`. Both come from
  `@better-auth/core/error`.
- `ctx.redirect(url)` throws a redirect response.
- `ctx.error(status, body?)` is a sugar for throwing an `APIError` with
  no `code`.
- Any `Set-Cookie` headers staged before the throw are preserved because
  `createAuthEndpoint` attaches them to the error via
  `kAPIErrorHeaderSymbol`.

## Hook-context shape

```
HookEndpointContext = Partial<
  EndpointContext<string, any> & Omit<InputContext<string, any>, "method">
> & {
  path?: string;
  context: AuthContext & { returned?: unknown; responseHeaders?: Headers };
  headers?: Headers;
}
```

Matchers receive this shape — i.e. they can inspect `ctx.path`,
`ctx.body`, `ctx.query`, `ctx.headers`. After-hook handlers additionally
see `ctx.context.returned` and `ctx.context.responseHeaders`.

## Built-in middlewares

Located under `reference/packages/better-auth/src/api/middlewares/`:

- `origin-check.ts` — `originCheck(getURL)` and `formCsrfMiddleware`.
  Validates `Origin` header and any caller-supplied callback URLs
  against `trustedOrigins`.
- `authorization.ts` — admin-only routes' API-key check (for plugins
  that opt in).

Session middlewares from `api/routes/session.ts`:

- `sessionMiddleware` — `getSessionFromCtx(ctx)` and throws `UNAUTHORIZED`
  if no session.
- `sensitiveSessionMiddleware` — same, but disables cookie cache so
  revoked sessions cannot pass.
- `freshSessionMiddleware` — also requires `now - session.createdAt < freshAge`.
- `requestOnlySessionMiddleware` — only requires a session when called
  from an HTTP request (server-side calls can bypass).

## Operation ID & OpenAPI

`getOperationId(endpoint, key)` in `to-auth-endpoints.ts`:

```
return opts.operationId
    ?? opts.metadata?.openapi?.operationId
    ?? key;
```

`metadata.openapi` is consumed by
`reference/packages/better-auth/src/plugins/open-api/` to build the OAS document.

## Python port notes

- `createAuthEndpoint` becomes a decorator (or builder function) that
  returns an endpoint descriptor: `{path, method, body_schema, query_schema, handler, middlewares, metadata}`.
- `EndpointContext` becomes a small dataclass / Pydantic model. Cookie
  helpers belong on the context too (`set_cookie`, `set_signed_cookie`,
  `get_cookie`, `get_signed_cookie`, `json`, `redirect`, `error`).
- Hooks should use a `Protocol` for the matcher + an async handler. The
  matcher receives a `HookEndpointContext` analog.
- `runWithEndpointContext` maps to a `contextvars.ContextVar` so helpers
  can recover the context without threading it through every call.
- `kAPIErrorHeaderSymbol` is solved differently in Python: attach the
  staged headers to the raised `APIError` directly (e.g. as
  `error.response_headers`) and have the response-wrapper merge them
  in.
