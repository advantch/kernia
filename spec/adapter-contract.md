# Adapter Contract Specification

The database adapter interface lives in
`reference/packages/core/src/db/adapter/index.ts` (also exported via
`@better-auth/core/db/adapter`). The `better-auth` package re-exports it
from `reference/packages/better-auth/src/adapters/index.ts`.

## Overview

There are two distinct contracts:

- `DBAdapter<Options>` — the **public** adapter used by `auth.context.adapter`
  and `internalAdapter`. Methods accept *user-facing* `Where[]` (operators
  optional, etc.) and return rows in the user's model shape.
- `CustomAdapter` — the **factory-internal** adapter implemented by adapter
  authors. Methods accept *cleaned* `CleanedWhere[]` (`Required<Where>`) and
  are wrapped by `createAdapterFactory()` which applies model/field name
  transforms, input/output normalization, and ID generation.

Adapter authors implement `CustomAdapter` plus a `DBAdapterFactoryConfig`,
then return a `DBAdapter` via `createAdapterFactory()` (alias
`createAdapter`).

## Source-file map

- `reference/packages/core/src/db/adapter/index.ts` — exports everything.
- `reference/packages/core/src/db/adapter/factory.ts` — the factory.
- `reference/packages/core/src/db/adapter/types.ts` — `AdapterFactoryConfig`,
  `AdapterFactoryCustomizeAdapterCreator`.
- `reference/packages/core/src/db/adapter/get-default-model-name.ts`
- `reference/packages/core/src/db/adapter/get-default-field-name.ts`
- `reference/packages/core/src/db/adapter/get-field-attributes.ts`
- `reference/packages/core/src/db/adapter/get-field-name.ts`
- `reference/packages/core/src/db/adapter/get-model-name.ts`
- `reference/packages/core/src/db/adapter/get-id-field.ts`
- `reference/packages/core/src/db/adapter/utils.ts`
- Concrete adapters:
  - `reference/packages/memory-adapter/src/memory-adapter.ts`
  - `reference/packages/better-auth/src/adapters/kysely-adapter/`
  - `reference/packages/better-auth/src/adapters/drizzle-adapter/`
  - `reference/packages/better-auth/src/adapters/prisma-adapter/`
  - `reference/packages/better-auth/src/adapters/mongodb-adapter/`

## `Where` clause shape (verbatim)

```ts
export const whereOperators = [
  "eq", "ne", "lt", "lte", "gt", "gte",
  "in", "not_in",
  "contains", "starts_with", "ends_with",
] as const;
export type WhereOperator = (typeof whereOperators)[number];

export type Where = {
  /** @default eq */
  operator?: WhereOperator | undefined;
  value: string | number | boolean | string[] | number[] | Date | null;
  field: string;
  /** @default AND */
  connector?: ("AND" | "OR") | undefined;
  /**
   * Case sensitivity for string comparisons.
   * When "insensitive", string equality and pattern matching (contains, starts_with, ends_with)
   * will be case-insensitive. Only applies to string values.
   * @default "sensitive"
   */
  mode?: "sensitive" | "insensitive" | undefined;
};

export type CleanedWhere = Required<Where>;
```

`CleanedWhere[]` is produced by `transformWhereClause(...)` inside the
factory. The factory fills missing `operator` with `"eq"`, missing
`connector` with `"AND"`, missing `mode` with `"sensitive"`, and rewrites
`field` from the schema-default name to the user-configured `fieldName`.

## `JoinOption` and `JoinConfig`

```ts
export type JoinOption = {
  [model: string]: boolean | { limit?: number };
};

export type JoinConfig = {
  [model: string]: {
    on: { from: string; to: string };
    limit?: number;
    relation?: "one-to-one" | "one-to-many" | "many-to-many";
  };
};
```

`JoinOption` is the user-facing input; the factory transforms it into
`JoinConfig` by reading `schema[model].fields[*].references` to derive
`on` columns and the `relation` cardinality.

## `DBAdapter<Options>` (public adapter)

```ts
export type DBAdapter<Options extends BetterAuthOptions = BetterAuthOptions> = {
  id: string;

  create: <T extends Record<string, any>, R = T>(data: {
    model: string;
    data: Omit<T, "id">;
    select?: string[] | undefined;
    /** If true, do not strip `id` from `data`. */
    forceAllowId?: boolean | undefined;
  }) => Promise<R>;

  findOne: <T>(data: {
    model: string;
    where: Where[];
    select?: string[] | undefined;
    join?: JoinOption | undefined;
  }) => Promise<T | null>;

  findMany: <T>(data: {
    model: string;
    where?: Where[] | undefined;
    limit?: number | undefined;
    select?: string[] | undefined;
    sortBy?: { field: string; direction: "asc" | "desc" } | undefined;
    offset?: number | undefined;
    join?: JoinOption | undefined;
  }) => Promise<T[]>;

  count: (data: {
    model: string;
    where?: Where[] | undefined;
  }) => Promise<number>;

  /**
   * ⚠ Update may not return the updated data if multiple where clauses are provided.
   */
  update: <T>(data: {
    model: string;
    where: Where[];
    update: Record<string, any>;
  }) => Promise<T | null>;

  updateMany: (data: {
    model: string;
    where: Where[];
    update: Record<string, any>;
  }) => Promise<number>;

  delete: <_T>(data: { model: string; where: Where[] }) => Promise<void>;
  deleteMany: (data: { model: string; where: Where[] }) => Promise<number>;

  /**
   * Atomically consume a single row: delete it and return it, or return null.
   * Must delete at most one row, even when the where matches several.
   * Race-safe: under concurrent invocation, exactly one caller receives the row.
   */
  consumeOne: <T>(data: { model: string; where: Where[] }) => Promise<T | null>;

  /**
   * Execute multiple operations in a transaction.
   * If the adapter doesn't support transactions, operations execute sequentially.
   */
  transaction: <R>(
    callback: (trx: DBTransactionAdapter<Options>) => Promise<R>,
  ) => Promise<R>;

  /**
   * Generate schema definitions (Drizzle/Prisma DSL) for the user's tables.
   */
  createSchema?:
    | ((options: Options, file?: string) => Promise<DBAdapterSchemaCreation>)
    | undefined;

  options?:
    | ({ adapterConfig: DBAdapterFactoryConfig<Options> } & CustomAdapter["options"])
    | undefined;
};
```

`DBTransactionAdapter<Options> = Omit<DBAdapter<Options>, "transaction">`.

### `consumeOne` semantics (verbatim from source)

> Atomically consume a single row matching the where clause: delete it and
> return the deleted row, or return null if no row matched.
> Implementations MUST NOT delete any additional rows that also match a
> non-unique predicate.
>
> Under concurrent invocation against the same row, exactly one caller
> receives the row; subsequent racers receive null. This is the race-safe
> primitive for consuming single-use credentials (verification tokens,
> authorization codes, one-time tokens).
>
> Always defined on the factory-wrapped adapter. When the underlying
> CustomAdapter does not implement consumeOne, the factory provides a
> fallback that wraps `findMany + deleteMany` in `transaction(...)` and
> returns the row only when the delete reports an affected row.

## `CustomAdapter` (factory-internal contract)

```ts
export interface CustomAdapter {
  create: <T extends Record<string, any>>(data: {
    model: string;
    data: T;
    select?: string[] | undefined;
  }) => Promise<T>;

  update: <T>(data: {
    model: string;
    where: CleanedWhere[];
    update: T;
  }) => Promise<T | null>;

  updateMany: (data: {
    model: string;
    where: CleanedWhere[];
    update: Record<string, any>;
  }) => Promise<number>;

  findOne: <T>(data: {
    model: string;
    where: CleanedWhere[];
    select?: string[] | undefined;
    join?: JoinConfig | undefined;
  }) => Promise<T | null>;

  findMany: <T>(data: {
    model: string;
    where?: CleanedWhere[] | undefined;
    limit: number;                           // factory always supplies a value
    select?: string[] | undefined;
    sortBy?: { field: string; direction: "asc" | "desc" } | undefined;
    offset?: number | undefined;
    join?: JoinConfig | undefined;
  }) => Promise<T[]>;

  delete: (data: { model: string; where: CleanedWhere[] }) => Promise<void>;
  deleteMany: (data: { model: string; where: CleanedWhere[] }) => Promise<number>;

  /**
   * Optional native atomic single-row consume. When omitted, the adapter
   * factory falls back to `transaction(findMany + deleteMany)`.
   * Implementing this natively (DELETE … RETURNING *, findOneAndDelete,
   * OUTPUT deleted.*) gives one round-trip and the strongest race-safety
   * guarantee. Must delete at most one matching row.
   */
  consumeOne?: <T>(data: {
    model: string;
    where: CleanedWhere[];
  }) => Promise<T | null>;

  count: (data: {
    model: string;
    where?: CleanedWhere[] | undefined;
  }) => Promise<number>;

  createSchema?:
    | ((props: { file?: string; tables: BetterAuthDBSchema })
        => Promise<DBAdapterSchemaCreation>)
    | undefined;

  options?: Record<string, any> | undefined;
}
```

## `DBAdapterFactoryConfig`

Key fields (from `core/src/db/adapter/index.ts`):

```
adapterId: string;                       // required
adapterName?: string;                    // defaults to adapterId
usePlural?: boolean;                     // append "s" to table names; default false
debugLogs?: DBAdapterDebugLogOption;
supportsNumericIds?: boolean;            // default true
supportsUUIDs?: boolean;                 // default false
supportsJSON?: boolean;                  // default false (else stringified)
supportsDates?: boolean;                 // default true
supportsBooleans?: boolean;              // default true
supportsArrays?: boolean;                // default false
transaction?: false | (<R>(cb: (trx: DBTransactionAdapter<Options>) => Promise<R>) => Promise<R>);
disableIdGeneration?: boolean;           // default false
mapKeysTransformInput?: Record<string, string>;   // e.g. { id: "_id" } for Mongo
mapKeysTransformOutput?: Record<string, string>;  // e.g. { _id: "id" }
customTransformInput?:  (props: { … }) => any;
customTransformOutput?: (props: { … }) => any;
customIdGenerator?:    (props: { model: string }) => string;
disableTransformOutput?: boolean;
disableTransformInput?:  boolean;
disableTransformJoin?:   boolean;
```

## `AdapterFactoryCustomizeAdapterCreator`

The factory invokes the adapter creator with helpers:

```
options: BetterAuthOptions;
schema: BetterAuthDBSchema;
debugLog: (...args: unknown[]) => void;
getModelName: (model: string) => string;
getFieldName: ({ model, field }) => string;
getDefaultModelName: (model: string) => string;
getDefaultFieldName: ({ model, field }) => string;
getFieldAttributes: ({ model, field }) => DBFieldAttribute;
transformInput:  (data, defaultModelName, action, forceAllowId?) => Promise<Record<string, unknown>>;
transformOutput: (data, defaultModelName, select?, joinConfig?) => Promise<Record<string, unknown>>;
transformWhereClause: <W>({ model, where, action }) => CleanedWhere[] | undefined;
```

`action` is one of:
`"create" | "update" | "findOne" | "findMany" | "updateMany" | "delete" | "deleteMany" | "consumeOne" | "count"`.

## Model and field name conventions

Default models (`schema.ts` in `better-auth/src/db/`):
- `user`
- `account`
- `session`
- `verification`
Plus any plugin-contributed models (e.g. `organization`, `jwks`,
`twoFactor`, `passkey`, `apiKey`, …).

Users can rename a model via `options.<model>.modelName` and individual
fields via `options.<model>.fields.<key>`. The factory translates:

- `getModelName("user") → "auth_users"` (if configured)
- `getFieldName({ model: "user", field: "emailVerified" }) → "email_verified"`
- `getDefaultModelName(actualName) → "user"` to look up
  `schema["user"].fields[*]`.

Plugins extend the schema with `additionalFields` (see
`reference/packages/core/src/db/plugin.ts`).

## Built-in field attributes

From `core/src/db/type.ts`:

```
type DBFieldAttribute = {
  type: "string" | "number" | "boolean" | "date" | "string[]" | "number[]" | …;
  required?: boolean;
  unique?: boolean;
  defaultValue?: unknown | (() => unknown);
  references?: { model: string; field: string; onDelete?: "cascade" | … };
  input?: boolean;        // accept user input
  returned?: boolean;     // include in output
  bigint?: boolean;
  fieldName?: string;
  transform?: { input?: (v) => v; output?: (v) => v };
  sortable?: boolean;
};
```

## `createSchema` (optional)

Adapters may implement `createSchema` to emit a DSL file. Signature on
`DBAdapter`:
```ts
createSchema?: (options: Options, file?: string) => Promise<DBAdapterSchemaCreation>;
```
Returned shape:
```ts
{
  code: string;     // contents to write
  path: string;     // file path (relative to cwd)
  append?: boolean; // if true, append rather than overwrite
  overwrite?: boolean;
}
```
The Drizzle and Prisma adapters use this to emit `schema.ts` / `schema.prisma`.

## Required internal-adapter methods (used by core)

The auth core consumes `DBAdapter` through
`reference/packages/better-auth/src/db/internal-adapter.ts`, which composes
typed helpers around the raw adapter. Notable methods (consumed by routes):

```
createUser, createAccount,
findUserByEmail, findUserById, updateUser, updateUserByEmail, updatePassword,
findAccounts, findAccount, findAccountByProviderId, findAccountByUserId,
linkAccount, updateAccount, deleteAccount, deleteAccounts,
createSession, findSession, findSessions, listSessions, updateSession,
deleteSession, deleteSessions,
createVerificationValue, findVerificationValue, deleteVerificationByIdentifier,
consumeVerificationValue, // race-safe: backed by adapter.consumeOne
```

`consumeVerificationValue` is the user-visible single-shot operation; under
the hood it delegates to `adapter.consumeOne({ model: "verification", … })`.

## Memory adapter reference

`reference/packages/memory-adapter/src/memory-adapter.ts` is the canonical
in-memory implementation. It defines `consumeOne` natively (line 400) and
is the model to mimic when building a Python port's in-memory test adapter.

## Python port notes

- `where` clause arrays map naturally to lists of dataclass instances
  (`Where(field=..., operator=..., value=...)`). Use a sentinel
  `UNDEFINED` (or just `None` with a default in `__post_init__`) to encode
  "operator not supplied" until it reaches the factory transform.
- `transaction(cb)` must accept an async callback; the adapter passes the
  transactional `DBTransactionAdapter` which exposes everything except
  `transaction`.
- `consumeOne` MUST be atomic. In Python this means either:
  1. `DELETE … RETURNING *` (Postgres / SQLite ≥ 3.35).
  2. `WITH cte AS (SELECT … FOR UPDATE SKIP LOCKED) DELETE …` pattern.
  3. A `transaction()` wrapper around `findMany + deleteMany` (the fallback
     the factory provides).
- `createSchema` is optional in the MVP — only required if the adapter is
  intended to be used with the `generate` CLI.
