# Changelog

Notable changes to `supacheck` and `@supacheck/safe-fetch`. Versions follow [semantic versioning](https://semver.org/); before 1.0 a minor version may change behavior.

## @supacheck/safe-fetch 0.1.1 (2026-11-12)

- Added a README. No code changes.

## 0.1.0 (2026-11-12)

First release on npm, of both packages.

### supacheck

- Ten rules for Supabase and Next.js projects:
  - **R01** bare `auth.getUser()` in an API route
  - **R02** `select('*')` on a sensitive table
  - **R03** bare `auth.uid()` in an RLS policy (auto-fix available)
  - **R04a** SECURITY DEFINER function missing a `search_path` (or one without `pg_temp`), `OWNER` or `REVOKE`
  - **R04b** service-role policy without `TO service_role`
  - **R05** server-side `fetch()` outside an SSRF-safe helper
  - **R06** view without `security_invoker = on`
  - **R07** locked-down SECURITY DEFINER function with a PUBLIC-only `REVOKE`
  - **R08** RLS policy with no `TO` clause or `TO public`
  - **R09** SECURITY DEFINER function that `anon` can still execute
- The migration rules (R04a, R06, R07, R08, R09) replay the whole migration history in timestamp order and judge the state it leaves, so a fix in a later migration clears a finding and a regression in a later migration raises one.
- Commands: `scan`, `init`, `baseline`, `fix`.
- Output formats: pretty, JSON, SARIF and GitHub Actions annotations.
- `fail_on` in `.supacheck.yml` sets the severity at which `scan` exits non-zero.
- A baseline file records existing findings so only new ones fail CI.

### @supacheck/safe-fetch

- `safeFetch`, a `fetch()` that refuses private, loopback, link-local and metadata addresses and validates every redirect hop.
- `assertSafeFetchUrl`, the same checks without sending a request.
- `SsrfBlockedError`, with a `code` for each kind of refusal.
