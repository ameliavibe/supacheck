/**
 * Real-world cross-check: run R03 against the Amelia repo's migrations.
 *
 * Amelia's own CI gate (scripts/check-migration-rls-auth-uid.mjs) enforces R03,
 * so a faithful port should produce zero findings when pointed at the same
 * migrations directory with the same baseline.
 *
 * Skipped automatically when the AMELIA_REPO env var is unset (so CI on the
 * supa-shield repo does not require Amelia to be checked out alongside).
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { describe, expect, test } from 'vitest';
import { createR03 } from '../src/rules/R03-sql-bare-auth-uid.js';

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
    // baseline. If this fails, either supa-shield's port has a false positive
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
