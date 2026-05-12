# supa-shield

Static analysis for Supabase + Next.js apps. Catches the application-layer security
footguns that live-DB scanners miss and that audit-time LLM tools skip.

**Status: pre-release.** Building toward v0.1 with 7 rules, a CLI, and a GitHub Action.

---

## The thesis: Supabase squashes silently weaken your security posture

Every Supabase project that runs `supabase db dump` or `supabase migration squash`
regenerates its baseline by running `pg_dump` against the current database. The
output is not idempotent with the security posture you originally wrote.
`pg_dump` emits default-privilege statements that quietly undo carefully written
REVOKE lockdowns, strip `security_invoker = on` from views during their first
emission, and lose body-level `SET search_path` declarations inside SECURITY
DEFINER functions.

This is not a hypothetical. Here is a real squash baseline from a production
codebase (Amelia Vibe), `supabase/migrations/20260503210000_squashed_baseline.sql`.

What the author wrote (paraphrased from the pre-squash migration):

```sql
CREATE OR REPLACE FUNCTION public.admin_adjust_credits(...)
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path TO 'public', 'pg_temp'
AS $$ ... $$;

ALTER FUNCTION public.admin_adjust_credits(...) OWNER TO postgres;

REVOKE EXECUTE ON FUNCTION public.admin_adjust_credits(...)
  FROM PUBLIC, anon, authenticated;
```

What `pg_dump` emits in the squashed baseline (line numbers from the file above):

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

Same intent, completely different security posture. The PUBLIC-only REVOKE is
preserved. The role-by-role REVOKE that actually blocked anon and authenticated
clients is gone, replaced by GRANTs that `pg_dump` derives from postgres default
privileges. An admin function is now callable from any logged-in or anonymous
Supabase client.

Views are clobbered too. The same baseline file emits the `email_sends_with_stats`
view twice:

```sql
-- line 1918: first emission, RLS-bypassing
CREATE OR REPLACE VIEW "public"."email_sends_with_stats" AS
SELECT ...;

-- line 3740: second emission, RLS-respecting
CREATE OR REPLACE VIEW "public"."email_sends_with_stats"
  WITH ("security_invoker"='on') AS
SELECT ...;
```

Between the two emissions the view runs as the definer (postgres), bypassing
RLS on the underlying table. If anything ran the file partially, or replicated
to a follower at the wrong moment, every row in the underlying table would be
readable across users. This is the same class of bug that ships as
"cross-user data leak" headlines.

supa-shield catches every known way this happens, before the regenerated
baseline lands in production.

---

## What it catches

| Rule | Catches | Squash defense |
|------|---------|----------------|
| R01 | DAL cookie-form auth bypass (`getUser()` with no token argument in an API route) | |
| R02 | `select('*')` on sensitive tables in TypeScript code | |
| R03 | Bare `auth.uid()` in RLS policy (forces per-row evaluation, perf footgun) | |
| R04a | SECURITY DEFINER function missing `SET search_path` attribute, `OWNER TO postgres`, or role-by-role REVOKE | yes |
| R04b | Service-role-targeted policy without explicit `TO service_role` clause | yes |
| R05 | Server-side `fetch()` without going through an SSRF-safe helper | |
| R06 | `CREATE VIEW` without `security_invoker = on` (state machine over migration history) | yes |
| R07 | Locked-down SECDEF function with PUBLIC-only REVOKE (will be undone by squash) | yes |

The four squash-defense rules (R04a, R04b, R06, R07) all defend against the same
underlying mechanism: `pg_dump`'s re-emission of GRANTs and reloptions overriding
your hand-written security posture during the squash workflow.

---

## How it compares

| Tool | Coverage | When it runs | Cost per run |
|------|----------|--------------|--------------|
| **supa-shield** | Supabase + Next.js app layer, migrations, squash defenses | Every PR | Free OSS |
| deepsec (vercel-labs) | Next.js auth, generic SSRF, multi-framework, LLM-driven | On demand, audit cadence | $1,000+ per scan in LLM costs |
| Supabase Splinter | DB-only: RLS-disabled tables, exposed columns, definer views | Live DB scan | Free, built-in |
| Supabase Advisors | DB-only: similar surface to Splinter | Live DB scan | Free, dashboard |
| Semgrep / Snyk | Generic SAST. No Supabase rulepack ships. | Every PR | Free OSS / paid per contributor |

deepsec catches missing auth on Next.js routes. supa-shield catches the
migration-time and Supabase-specific footguns that deepsec explicitly skips
(deepsec's `if (/migrations/i.test(filePath)) return []` line is the wedge).
Run both.

---

## Install

Coming soon. v0.1 ships as:

- `supa-shield` CLI on npm
- `@supa-shield/safe-fetch` reference SSRF helper on npm
- `supa-shield-action` GitHub Action
- `@supa-shield/semgrep-rules` rulepack (subset, for Semgrep Marketplace)

---

## Why this exists

The category is empty. Splinter and Supabase Advisors are DB-only. deepsec
explicitly skips migrations and is structurally an audit tool, not a CI gate.
Semgrep ships no Supabase rulepack. Snyk has zero Supabase specificity. The
Supabase community ships incidents in the headlines roughly monthly. The
delta between "we have a CI gate that catches this" and "we have an audit
that catches this once a quarter" is the production breach window.

supa-shield is the deterministic, fast, free CI gate. It pairs with deepsec
for quarterly audit coverage and with Splinter for live-DB hygiene. It is
not a substitute for either.

---

## License

Apache 2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
