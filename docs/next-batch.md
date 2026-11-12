# Next rule batch

Three items, in priority order. Each is a port of a check the Amelia app already
runs in its own `scripts/`; read the source script and its tests there before
writing the supacheck version, and add a case to
`packages/rules/test/amelia-cross-check.test.ts` so the port is run against real
migrations.

## 1. Destructive-migration guard (new rule)

Source: `check-destructive-migrations.mjs`.

A migration that destroys state must carry a guard that names the object it
protects, placed before the statement. Covered statements: `DROP TABLE`,
`DROP COLUMN`, `DROP SCHEMA`, `TRUNCATE`, a `DELETE` with no `WHERE`, and the
`UPDATE … SET col = col - 'key'` jsonb-removal shape. Coverage is per object, not
per file. An explicit `-- destructive-ok: <why>` comment that names the object is
the escape hatch.

Decide before building: the default severity, and whether the rule applies only
after `migrations_baseline` (a squash baseline legitimately has none of these).

## 2. Server-action auth (new rule)

Source: `check-server-action-auth.mjs`.

Every exported function in a `'use server'` file must check the session before
doing work. The rule needs a configurable list of accepted auth helpers, the same
way R01 takes one for route handlers.

## 3. Parser and replay hardening (existing rules R04a, R07, R09)

Lessons from fixing the same parser in the source app:

- `ALTER FUNCTION … SET search_path FROM CURRENT` is not handled. It pins
  whatever path the applying session had, so it must fail R04a with its own
  message, not pass and not be reported as "missing pg_temp".
- One `ALTER FUNCTION` can carry several actions, applied in order
  (`RESET ALL SET search_path TO …`). The last action that touches the path
  decides. Check `secdef-state.ts` reads it that way.
- Confirm the replay applies a file's CREATE, DROP and ALTER statements in
  document order for every piece of state, including a rename or drop followed
  by a re-create of the old name in the same file. `secdef-state.ts` sorts
  events by offset; add the tests that prove it.
- Confirm a migration file with no timestamp prefix cannot delete or overwrite
  state built from timestamped files. Check what `sortMigrations` and
  `isMigrationInScope` do with such a name and add a test.
- The bare form (`ALTER FUNCTION fn RENAME TO …`, no argument list) is accepted
  with `argTypes: null`; add tests that a bare rename and a bare
  `RESET search_path` reach the right function.

## Also open

- R05 flags relative URLs; the source app's SSRF check exempts them.
- R04a requires an explicit `REVOKE` only on SECURITY DEFINER functions. Postgres
  grants EXECUTE to PUBLIC on every new function, so a deny-by-default rule for
  all functions is a candidate.
- The Semgrep pack covers only R01, R03 and R04a.
- The GitHub Action's documented `@v1` ref needs a `v1` tag.
- `@supacheck/safe-fetch` has no README of its own.
