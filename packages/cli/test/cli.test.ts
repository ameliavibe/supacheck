import { mkdtempSync, writeFileSync, rmSync, existsSync, readFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { runScan } from '../src/commands/scan.js';
import { runInit } from '../src/commands/init.js';
import { runBaseline } from '../src/commands/baseline.js';
import { runFix } from '../src/commands/fix.js';

function withTempProject(seed: Record<string, string>, fn: (cwd: string) => void): void {
  const cwd = mkdtempSync(join(tmpdir(), 'supa-shield-test-'));
  try {
    for (const [path, contents] of Object.entries(seed)) {
      const full = join(cwd, path);
      mkdirSync(join(full, '..'), { recursive: true });
      writeFileSync(full, contents);
    }
    fn(cwd);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
}

const BARE_AUTH_UID = `CREATE POLICY "p" ON public.t FOR SELECT TO authenticated
  USING (user_id = auth.uid());
`;

describe('CLI: scan command', () => {
  test('finds R03 violations in a synthetic project', () => {
    withTempProject(
      { 'supabase/migrations/20260601000001_test.sql': BARE_AUTH_UID },
      (cwd) => {
        const result = runScan({
          cwd,
          configPath: null,
          format: 'json',
          noBaseline: true,
          toolVersion: '0.0.0',
        });
        expect(result.findings.length).toBe(1);
        expect(result.findings[0]!.ruleId).toBe('R03');
        expect(result.exitCode).toBe(1);
      },
    );
  });

  test('no findings on a clean project', () => {
    withTempProject(
      {
        'supabase/migrations/20260601000001_clean.sql':
          'CREATE POLICY "p" ON public.t FOR SELECT TO authenticated USING (user_id = (select auth.uid()));\n',
      },
      (cwd) => {
        const result = runScan({
          cwd,
          configPath: null,
          format: 'pretty',
          noBaseline: true,
          toolVersion: '0.0.0',
        });
        expect(result.findings).toEqual([]);
        expect(result.exitCode).toBe(0);
      },
    );
  });
});

describe('CLI: init command', () => {
  test('writes .supa-shield.yml when none exists', () => {
    withTempProject({}, (cwd) => {
      const result = runInit({ cwd, force: false });
      expect(result.written).toBe(true);
      expect(existsSync(join(cwd, '.supa-shield.yml'))).toBe(true);
      const content = readFileSync(join(cwd, '.supa-shield.yml'), 'utf8');
      expect(content).toContain('version: 1');
      expect(content).toContain('R03:');
    });
  });

  test('refuses to overwrite without --force', () => {
    withTempProject({ '.supa-shield.yml': 'version: 1\n' }, (cwd) => {
      const result = runInit({ cwd, force: false });
      expect(result.written).toBe(false);
    });
  });

  test('overwrites with --force', () => {
    withTempProject({ '.supa-shield.yml': 'version: 1\n' }, (cwd) => {
      const result = runInit({ cwd, force: true });
      expect(result.written).toBe(true);
    });
  });
});

describe('CLI: baseline command', () => {
  test('records current violations and subsequent scan reports zero new', () => {
    withTempProject(
      { 'supabase/migrations/20260601000001_test.sql': BARE_AUTH_UID },
      (cwd) => {
        const baseline = runBaseline({ cwd, configPath: null });
        expect(baseline.count).toBe(1);
        expect(existsSync(join(cwd, '.supa-shield-baseline.json'))).toBe(true);

        const scan = runScan({
          cwd,
          configPath: null,
          format: 'pretty',
          noBaseline: false,
          toolVersion: '0.0.0',
        });
        expect(scan.findings.length).toBe(1);
        expect(scan.newFindings).toEqual([]);
        expect(scan.knownFindings.length).toBe(1);
        expect(scan.exitCode).toBe(0); // baseline'd, not failing
      },
    );
  });

  test('new violation introduced after baseline fails the scan', () => {
    withTempProject(
      { 'supabase/migrations/20260601000001_test.sql': BARE_AUTH_UID },
      (cwd) => {
        runBaseline({ cwd, configPath: null });
        // Introduce a NEW file with a NEW bare auth.uid() violation
        writeFileSync(
          join(cwd, 'supabase/migrations/20260602000001_new.sql'),
          'CREATE POLICY "q" ON public.x FOR SELECT TO authenticated USING (user_id = auth.uid());\n',
        );
        const scan = runScan({
          cwd,
          configPath: null,
          format: 'pretty',
          noBaseline: false,
          toolVersion: '0.0.0',
        });
        expect(scan.findings.length).toBe(2);
        expect(scan.newFindings.length).toBe(1);
        expect(scan.newFindings[0]!.file).toContain('20260602000001');
        expect(scan.exitCode).toBe(1);
      },
    );
  });
});

describe('CLI: fix command', () => {
  test('applies deterministic R03 fix and clears the violation', () => {
    withTempProject(
      { 'supabase/migrations/20260601000001_test.sql': BARE_AUTH_UID },
      (cwd) => {
        const fix = runFix({ cwd, configPath: null, dryRun: false });
        expect(fix.patchesApplied).toBe(1);
        expect(fix.filesChanged.length).toBe(1);

        // Rescan: should now be clean
        const scan = runScan({
          cwd,
          configPath: null,
          format: 'pretty',
          noBaseline: true,
          toolVersion: '0.0.0',
        });
        expect(scan.findings).toEqual([]);
      },
    );
  });

  test('dry-run does not write', () => {
    withTempProject(
      { 'supabase/migrations/20260601000001_test.sql': BARE_AUTH_UID },
      (cwd) => {
        const before = readFileSync(
          join(cwd, 'supabase/migrations/20260601000001_test.sql'),
          'utf8',
        );
        const fix = runFix({ cwd, configPath: null, dryRun: true });
        expect(fix.patchesApplied).toBe(1);
        const after = readFileSync(
          join(cwd, 'supabase/migrations/20260601000001_test.sql'),
          'utf8',
        );
        expect(after).toBe(before);
      },
    );
  });
});
