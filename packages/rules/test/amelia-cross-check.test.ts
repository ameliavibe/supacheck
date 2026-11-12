/**
 * Real-world cross-check: run R03 against the Amelia repo's migrations.
 *
 * Amelia's own CI gate (scripts/check-migration-rls-auth-uid.mjs) enforces R03,
 * so a faithful port should produce zero findings when pointed at the same
 * migrations directory with the same baseline.
 *
 * Skipped automatically when the AMELIA_REPO env var is unset (so CI on the
 * supacheck repo does not require Amelia to be checked out alongside).
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { describe, expect, test } from 'vitest';
import { createR03 } from '../src/rules/R03-sql-bare-auth-uid.js';
import { createR04a } from '../src/rules/R04a-sql-secdef-hygiene.js';
import { createR07 } from '../src/rules/R07-sql-secdef-role-by-role-revoke.js';
import { R08, replayPolicies } from '../src/rules/R08-sql-policy-explicit-roles.js';
import { createR09 } from '../src/rules/R09-sql-secdef-anon-execute.js';
import { replaySecdefState } from '../src/lib/secdef-state.js';

const AMELIA_REPO = process.env.AMELIA_REPO ?? join(homedir(), 'Amelia');
const MIGRATIONS_DIR = join(AMELIA_REPO, 'supabase', 'migrations');
const AMELIA_BASELINE = '20260503210000';

const ameliaAvailable = existsSync(MIGRATIONS_DIR);

describe.skipIf(!ameliaAvailable)('R03 vs. real Amelia migrations', () => {
  const rule = createR03({ migrationsBaselineTimestamp: AMELIA_BASELINE });

  const sqlFiles = readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith('.sql'))
    .sort();

  test('Amelia migrations directory contains at least the squash baseline', () => {
    expect(sqlFiles.length).toBeGreaterThan(0);
  });

  test('no bare auth.uid() violations after the squash baseline', () => {
    const findings = [];
    for (const file of sqlFiles) {
      const contents = readFileSync(join(MIGRATIONS_DIR, file), 'utf8');
      findings.push(...rule.scan({ path: file, contents }));
    }
    // Amelia's own audit:static gate enforces zero violations after the squash
    // baseline. If this fails, either supacheck's port has a false positive
    // or Amelia regressed.
    if (findings.length > 0) {
      const summary = findings
        .slice(0, 10)
        .map((f) => `  ${f.file}:${f.line} ${f.message}`)
        .join('\n');
      throw new Error(
        `Expected zero findings, got ${findings.length}. First few:\n${summary}`,
      );
    }
    expect(findings).toEqual([]);
  });

  test('synthesized bare auth.uid() in a post-baseline file is caught', () => {
    // Build a synthetic migration filename that is after the baseline. Then
    // confirm R03 fires on a clearly bare auth.uid() in that synthetic file.
    const synthetic = {
      path: '20299999999999_synthetic-bare.sql',
      contents:
        'CREATE POLICY "synth" ON public.x FOR SELECT TO authenticated\n' +
        '  USING (user_id = auth.uid());\n',
    };
    const findings = rule.scan(synthetic);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe('R03');
  });
});

/**
 * The replay rules against a real pg_dump baseline plus hand-written
 * migrations. Amelia's own gates (check-policy-roles, check-migration-secdef)
 * enforce the same properties, so a faithful port reports nothing.
 */
describe.skipIf(!ameliaAvailable)('replay rules vs. real Amelia migrations', () => {
  const files = ameliaAvailable
    ? readdirSync(MIGRATIONS_DIR)
        .filter((f) => f.endsWith('.sql'))
        .map((f) => ({
          path: `supabase/migrations/${f}`,
          contents: readFileSync(join(MIGRATIONS_DIR, f), 'utf8'),
        }))
    : [];
  // Amelia's current squash baseline is the oldest file in the directory.
  const squash = files.map((f) => f.path.split('/').pop()!.slice(0, 14)).sort()[0];

  test('every CREATE FUNCTION in the corpus is parsed', () => {
    const replay = replaySecdefState(files);
    expect(replay.unparsed).toEqual([]);
    expect(replay.functions.filter((f) => f.securityDefiner).length).toBeGreaterThan(10);
  });

  test('R08 reads the policies and finds every public one role-scoped', () => {
    expect(replayPolicies(files).filter((p) => p.schema === 'public').length).toBeGreaterThan(50);
    expect(R08.scanAll!(files)).toEqual([]);
  });

  test('R04a, R07 and R09 report nothing after the squash baseline', () => {
    const opts = { migrationsBaselineTimestamp: squash };
    const findings = [createR04a(opts), createR07(opts), createR09(opts)].flatMap((r) => r.scanAll!(files));
    expect(findings.map((f) => `${f.ruleId} ${f.file}:${f.line}`)).toEqual([]);
  });
});
