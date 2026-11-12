<div align="center">

# supacheck

**The Supabase + Next.js linter that catches what your squash quietly broke.**

[![License](https://img.shields.io/badge/license-Apache_2.0-blue)](./LICENSE)
[![Status](https://img.shields.io/badge/status-pre--release-orange)](#status)
[![CI](https://github.com/ameliavibe/supacheck/actions/workflows/test.yml/badge.svg)](https://github.com/ameliavibe/supacheck/actions)

</div>

supacheck is a free, deterministic linter for Supabase + Next.js apps. It runs in seconds on every pull request and catches the application-layer security footguns that live-DB scanners cannot see and that audit-time LLM tools skip.

## Install

Drop this into `.github/workflows/supacheck.yml`:

```yaml
name: supacheck
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - uses: ameliavibe/supacheck/packages/github-action@v1
```

Findings show up as annotations directly on the changed lines in the PR diff view.

Prefer the CLI?

```bash
npx supacheck init       # generate a starter .supacheck.yml
npx supacheck baseline   # record current findings so only new ones fail CI
npx supacheck scan       # see what is in the codebase right now
npx supacheck fix        # apply deterministic auto-fixes (R03 today)
```

## What you see when it fires

```
supabase/migrations/20260601000001_user_drafts.sql
  R03  supabase/migrations/20260601000001_user_drafts.sql:4:24
    Bare auth.uid() in RLS policy forces per-row evaluation.
    Wrap as (select auth.uid()) so Postgres caches the value once per query.

1 finding
```

Run `npx supacheck fix` and the policy gets patched deterministically. No LLM, no guessing, no diff to argue about in review.

## What it catches

| Rule | What it catches | Auto-fix | Squash defense |
|------|-----------------|----------|----------------|
| **R01** | Bare `auth.getUser()` in an API route (DAL cache-coherence) | | |
| **R02** | `select('*')` on a sensitive table | | |
| **R03** | Bare `auth.uid()` in an RLS policy (per-row perf) | yes | |
| **R04a** | SECDEF function missing `search_path` (or one without `pg_temp`) / `OWNER` / `REVOKE` | | yes |
| **R04b** | Service-role policy without explicit `TO service_role` | | yes |
| **R05** | Server-side `fetch()` outside an SSRF-safe helper | | |
| **R06** | View without `security_invoker = on` (state machine over migrations) | | yes |
| **R07** | Locked-down SECDEF with PUBLIC-only REVOKE | | yes |
| **R08** | RLS policy with no `TO` clause or `TO public`, which applies to `anon` | | |
| **R09** | SECDEF function that `anon` can still execute | | yes |

Five of the ten defend against `pg_dump` rewriting your security posture during a Supabase squash. The other five catch application-layer footguns that other Supabase security tools miss.

The migration rules R04a, R06, R07, R08 and R09 replay your whole migration history in timestamp order and judge the state it leaves behind. A fix in a later migration clears the finding, and a later migration that undoes a lockdown raises one.

## Why supacheck exists

Every Supabase project that runs `supabase db dump` or `supabase migration squash` regenerates its baseline by running `pg_dump` against the current database. The output is **not idempotent** with the security posture you wrote. `pg_dump` emits default-privilege statements that quietly undo carefully written REVOKE lockdowns, strip `security_invoker = on` from views during their first emission, and lose body-level `SET search_path` declarations inside SECURITY DEFINER functions.

This is not a hypothetical. The following is a real squash baseline from a production codebase (Amelia Vibe), at `supabase/migrations/20260503210000_squashed_baseline.sql`.

What the author wrote:

```sql
CREATE OR REPLACE FUNCTION public.admin_adjust_credits(...)
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path TO 'public', 'pg_temp'
AS $$ ... $$;

ALTER FUNCTION public.admin_adjust_credits(...) OWNER TO postgres;

REVOKE EXECUTE ON FUNCTION public.admin_adjust_credits(...)
  FROM PUBLIC, anon, authenticated;
```

What `pg_dump` emits in the squashed baseline:

```sql
-- line 5364
REVOKE ALL ON FUNCTION "public"."admin_adjust_credits"(...) FROM PUBLIC;
-- line 5365
GRANT ALL ON FUNCTION "public"."admin_adjust_credits"(...) TO "anon";
-- line 5366
GRANT ALL ON FUNCTION "public"."admin_adjust_credits"(...) TO "authenticated";
-- line 5367
GRANT ALL ON FUNCTION "public"."admin_adjust_credits"(...) TO "service_role";
```

Same intent, completely different security posture. The role-by-role REVOKE that blocked anon and authenticated clients is gone, replaced by GRANTs that `pg_dump` derives from postgres default privileges. **An admin function is now callable from any anonymous or logged-in Supabase client.**

Views get clobbered the same way. The same baseline file emits `email_sends_with_stats` twice:

```sql
-- line 1918: first emission, RLS-bypassing
CREATE OR REPLACE VIEW "public"."email_sends_with_stats" AS SELECT ...;

-- line 3740: second emission, RLS-respecting
CREATE OR REPLACE VIEW "public"."email_sends_with_stats"
  WITH ("security_invoker"='on') AS SELECT ...;
```

Between the two emissions the view runs as the definer (postgres), bypassing RLS on the underlying table. If anything runs the file partially, or replicates to a follower at the wrong moment, every row in the underlying table is readable across users.

supacheck catches every known way this happens, before the regenerated baseline lands in production.

## How it compares

| Tool | Coverage | When it runs | Cost per scan |
|------|----------|--------------|----------------|
| **supacheck** | Supabase + Next.js app layer, migrations, squash defenses | Every PR | Free OSS |
| [deepsec](https://github.com/vercel-labs/deepsec) | Next.js auth, generic SSRF, multi-framework. Skips migrations explicitly. | On demand | $1,000+ in LLM costs |
| [Splinter](https://github.com/supabase/splinter) | DB-only: RLS-disabled tables, exposed columns, definer views | Live DB scan | Free, built-in |
| Supabase Advisors | DB-only: similar surface to Splinter | Live DB scan | Free, dashboard |
| Semgrep / Snyk | Generic SAST. No Supabase rulepack ships. | Every PR | Free OSS / paid per contributor |

deepsec catches missing auth on Next.js routes. supacheck catches the migration-time and Supabase-specific footguns that deepsec explicitly skips. They are complementary, not competing. Run both, plus Splinter for live-DB hygiene.

## Configuration

`npx supacheck init` drops a fully-commented `.supacheck.yml` with defaults you can edit. The interesting knobs:

```yaml
rules:
  R02:
    # Per-project knowledge. supacheck does nothing without a list.
    sensitive_tables:
      - users
      - subscriptions
      - stripe_events
  R03:
    # After 'supacheck baseline', set this to skip files at or before the
    # baseline so historical violations do not block CI.
    migrations_baseline_timestamp: "20260503210000"
  R08:
    # Schemas whose policies must name their roles.
    schemas: [public]
  R09:
    # SECURITY DEFINER functions that are meant to be callable without a session.
    allow_anon: []

baseline_file: .supacheck-baseline.json

# Findings present in the baseline are treated as known; only NEW findings
# cause a non-zero exit. This is non-negotiable for first-day adoption on a
# real codebase.

# Minimum severity that causes a non-zero exit: critical, high, medium or low.
# Findings below it are still printed.
fail_on: high
```

## Packages

supacheck is a small monorepo. Two packages are built for npm; the rest are used straight from this repo:

| Package | Where | Description |
|---------|-------|-------------|
| `supacheck` | npm | The CLI, with the rules bundled in |
| `@supacheck/safe-fetch` | npm | Reference SSRF-safe drop-in replacement for `fetch()`. The library R05 enforces use of. |
| `packages/semgrep-rules` | this repo | Subset of rules as Semgrep YAML for users who already run Semgrep |
| `packages/github-action` | this repo | GitHub Action wrapper around the CLI. Emits PR annotations and optional SARIF. |

## Status

**Pre-release.** The 10 rules are implemented and tested (~230 unit tests, plus cross-checks against a real production codebase). `supacheck` and `@supacheck/safe-fetch` are on npm at 0.1.0, so `npx supacheck scan` works. To run it from a clone instead:

```bash
git clone https://github.com/ameliavibe/supacheck && cd supacheck
pnpm install && pnpm build
cd /path/to/your/project
node /path/to/supacheck/packages/cli/dist/index.js scan
```

Star the repo or watch [Releases](https://github.com/ameliavibe/supacheck/releases) to hear about new versions.

## Contributing

Rules are TypeScript files in `packages/rules/src/rules/` with fixtures in `packages/rules/fixtures/`. To add one:

1. Create `R0X-<slug>.ts` exporting `createR0X(options): Rule`.
2. Add 8 or more positive fixtures (rule should fire) and 8 or more negative fixtures (rule should not fire).
3. Write `test/R0X.test.ts` that auto-discovers fixtures.
4. Register in `packages/cli/src/registry.ts` and `packages/rules/src/index.ts`.
5. Run `pnpm test` and `pnpm typecheck`.

The squash-clobber family (R04a, R04b, R06, R07, R09) sets `squashClobberFamily: true` on the Rule interface so docs and marketing can fan out from a single flag.

## License

[Apache 2.0](./LICENSE). See [NOTICE](./NOTICE) for acknowledgments, notably [deepsec](https://github.com/vercel-labs/deepsec), which informed the architectural choice to ship a deterministic CI gate alongside their LLM-driven audit tool.

---

<div align="center">
Made by <a href="https://ameliavibe.com">Amelia Vibe, LLC</a>
</div>
