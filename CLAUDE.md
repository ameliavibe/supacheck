# CLAUDE.md

supacheck is a deterministic linter for Supabase + Next.js projects. It is a pnpm workspace: `packages/rules` (the rules and the SQL migration replay), `packages/cli` (the `supacheck` npm package, with the rules bundled in), `packages/safe-fetch` (the `@supacheck/safe-fetch` npm package), `packages/github-action` and `packages/semgrep-rules` (used from the repo, not published).

## This repository is public

- Commit with your GitHub noreply address (`git config user.email` in this clone). CI fails a push whose HEAD carries any other address.
- No attribution or co-author lines in commit messages.
- Nothing from a private codebase goes in: no file contents, table names, data or paths beyond what the cross-check test already names.
- Never rewrite published history or force-push without the owner asking for it.

## Commands

pnpm only; never npm, npx or yarn for installs or scripts.

```bash
pnpm install
pnpm typecheck
pnpm test          # all packages
pnpm build
node packages/cli/dist/index.js scan   # the built CLI, from a project directory
```

Throwaway work goes in the gitignored `.scratch/`. Do not run `pnpm add` or `pnpm install` inside it: it sits in the workspace, so the root lockfile changes. Install test projects with `pnpm dlx`, or in a directory outside the repository.

## Changing rules

- A rule lives in `packages/rules/src/rules/R0X-<slug>.ts` with fixtures in `packages/rules/fixtures/` and a test in `packages/rules/test/`. Register it in `packages/rules/src/index.ts` and `packages/cli/src/registry.ts`, add its defaults to `packages/cli/src/config.ts`, and add its row to the README table and `CHANGELOG.md`.
- Rule IDs and finding messages are stable: baselines fingerprint them. Changing a message invalidates users' baselines.
- The migration rules judge the state the whole history leaves, through `packages/rules/src/lib/secdef-state.ts` and `sql-function-parse.ts`. Statements apply in document order within a file. A change to the parser needs a test for the statement form and one for its effect on a rule.
- `packages/rules/test/amelia-cross-check.test.ts` runs the rules against a private app's migrations when that checkout exists, and skips otherwise. It must pass in both cases.

## Releasing

1. Bump `version` in the package's `package.json` and add a `CHANGELOG.md` entry.
2. Push to `main` and wait for CI.
3. Run the `publish` workflow for the package (`gh workflow run publish.yml -f package=cli`). It stages the version on npm.
4. The owner approves the staged version on npmjs.com. Nothing is public until then.
5. Tag the release (`vX.Y.Z` for the CLI; move `v1` to it so the GitHub Action example keeps working).

Open work is in `docs/next-batch.md`.
