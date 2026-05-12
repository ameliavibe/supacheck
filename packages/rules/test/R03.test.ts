import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';
import type { FixPatch, Finding, ScannedFile } from '../src/lib/rule-types.js';
import { createR03, R03 } from '../src/rules/R03-sql-bare-auth-uid.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures', 'R03');

interface Fixture {
  name: string;
  contents: string;
}

function loadFixtures(kind: 'positive' | 'negative' | 'baseline'): Fixture[] {
  const dir = join(FIXTURES_DIR, kind);
  return readdirSync(dir)
    .filter((f) => f.endsWith('.sql'))
    .sort()
    .map((name) => ({
      name,
      contents: readFileSync(join(dir, name), 'utf8'),
    }));
}

function asScannedFile(fixture: Fixture): ScannedFile {
  return { path: fixture.name, contents: fixture.contents };
}

function applyPatches(original: string, patches: FixPatch[]): string {
  // Sort descending by start offset so each replacement does not shift
  // the offsets of replacements yet to be applied.
  const sorted = [...patches].sort((a, b) => b.range[0] - a.range[0]);
  let result = original;
  for (const p of sorted) {
    result = result.slice(0, p.range[0]) + p.replacement + result.slice(p.range[1]);
  }
  return result;
}

describe('R03 positive fixtures (should fire)', () => {
  const fixtures = loadFixtures('positive');
  expect(fixtures.length).toBeGreaterThanOrEqual(8);

  for (const fixture of fixtures) {
    test(fixture.name, () => {
      const findings = R03.scan(asScannedFile(fixture));
      expect(findings.length).toBeGreaterThan(0);
      for (const f of findings) {
        expect(f.ruleId).toBe('R03');
        expect(f.file).toBe(fixture.name);
        expect(f.line).toBeGreaterThan(0);
        expect(f.range).toBeDefined();
        // The offset range should actually point at a bare auth.uid() match
        // in the original contents.
        const [start, end] = f.range!;
        expect(end).toBeGreaterThan(start);
        expect(fixture.contents.slice(start, end)).toMatch(/auth\s*\.\s*uid\s*\(\s*\)/i);
      }
    });
  }
});

describe('R03 negative fixtures (should not fire)', () => {
  const fixtures = loadFixtures('negative');
  expect(fixtures.length).toBeGreaterThanOrEqual(8);

  for (const fixture of fixtures) {
    test(fixture.name, () => {
      const findings = R03.scan(asScannedFile(fixture));
      expect(findings).toEqual([]);
    });
  }
});

describe('R03 finding multiplicity', () => {
  test('multiple bare instances in one policy are all flagged', () => {
    const fixture = loadFixtures('positive').find((f) =>
      f.name.includes('multiple-bare'),
    );
    expect(fixture).toBeDefined();
    const findings = R03.scan(asScannedFile(fixture!));
    expect(findings.length).toBe(2); // USING + WITH CHECK
  });

  test('OR conjunction with two bare calls produces two findings', () => {
    const fixture = loadFixtures('positive').find((f) =>
      f.name.includes('or-conjunction-bare'),
    );
    expect(fixture).toBeDefined();
    const findings = R03.scan(asScannedFile(fixture!));
    expect(findings.length).toBe(2); // bare auth.uid() and is_admin(auth.uid())
  });

  test('mixed bare and wrapped produces exactly one finding for the bare one', () => {
    const fixture = loadFixtures('positive').find((f) =>
      f.name.includes('mixed-bare-and-wrapped'),
    );
    expect(fixture).toBeDefined();
    const findings = R03.scan(asScannedFile(fixture!));
    expect(findings.length).toBe(1);
  });
});

describe('R03 baseline timestamp filter', () => {
  const fixtures = loadFixtures('baseline');
  expect(fixtures.length).toBeGreaterThan(0);
  const fixture = fixtures[0]!;

  test('without baseline, old file still fires', () => {
    const findings = R03.scan(asScannedFile(fixture));
    expect(findings.length).toBeGreaterThan(0);
  });

  test('with baseline set later than file timestamp, old file is skipped', () => {
    const ruleWithBaseline = createR03({
      migrationsBaselineTimestamp: '20260100000000',
    });
    const findings = ruleWithBaseline.scan(asScannedFile(fixture));
    expect(findings).toEqual([]);
  });

  test('with baseline set earlier than file timestamp, file still fires', () => {
    const ruleWithBaseline = createR03({
      migrationsBaselineTimestamp: '20240101000000',
    });
    const findings = ruleWithBaseline.scan(asScannedFile(fixture));
    expect(findings.length).toBeGreaterThan(0);
  });
});

describe('R03 auto-fix', () => {
  test('produces a deterministic patch that wraps the bare call', () => {
    const fixture = loadFixtures('positive').find((f) =>
      f.name.includes('using-bare'),
    );
    expect(fixture).toBeDefined();
    const scanned = asScannedFile(fixture!);
    const findings = R03.scan(scanned);
    expect(findings.length).toBe(1);
    const fix = R03.autoFix!(scanned, findings[0]!);
    expect(fix).not.toBeNull();
    expect(fix!.deterministic).toBe(true);
    expect(fix!.patches).toHaveLength(1);
    expect(fix!.patches[0]!.replacement).toBe('(select auth.uid())');

    const fixed = applyPatches(scanned.contents, fix!.patches);
    expect(fixed).toContain('(select auth.uid())');
    // The patched content must not contain a bare auth.uid() any more
    const rescanned = R03.scan({ ...scanned, contents: fixed });
    expect(rescanned).toEqual([]);
  });

  test('applies multiple patches across one file without drifting offsets', () => {
    const fixture = loadFixtures('positive').find((f) =>
      f.name.includes('multiple-bare'),
    );
    expect(fixture).toBeDefined();
    const scanned = asScannedFile(fixture!);
    const findings = R03.scan(scanned);
    expect(findings.length).toBe(2);

    const patches: FixPatch[] = [];
    for (const f of findings) {
      const fix = R03.autoFix!(scanned, f);
      expect(fix).not.toBeNull();
      patches.push(...fix!.patches);
    }
    const fixed = applyPatches(scanned.contents, patches);
    // After fixing, every bare instance is wrapped
    const rescanned = R03.scan({ ...scanned, contents: fixed });
    expect(rescanned).toEqual([]);
    // And both wrappings exist in the result
    const wrappedCount = fixed.match(/\(select auth\.uid\(\)\)/g)?.length ?? 0;
    expect(wrappedCount).toBe(2);
  });

  test('normalizes inner-paren whitespace as a bonus', () => {
    const fixture = loadFixtures('positive').find((f) =>
      f.name.includes('whitespace-tolerant-bare'),
    );
    expect(fixture).toBeDefined();
    const scanned = asScannedFile(fixture!);
    const findings = R03.scan(scanned);
    expect(findings.length).toBe(1);
    const fix = R03.autoFix!(scanned, findings[0]!);
    const fixed = applyPatches(scanned.contents, fix!.patches);
    expect(fixed).toContain('(select auth.uid())');
    // The padded original auth.uid(  ) is gone, replaced with the normalized form
    expect(fixed).not.toMatch(/auth\.uid\(\s+\)/);
  });
});

describe('R03 metadata', () => {
  test('identifies as R03 with the expected slug and category', () => {
    expect(R03.id).toBe('R03');
    expect(R03.slug).toBe('sql-bare-auth-uid');
    expect(R03.category).toBe('rls-performance');
    expect(R03.severity).toBe('high');
  });

  test('is NOT a squash-clobber-family rule', () => {
    expect(R03.squashClobberFamily).toBe(false);
  });
});

// Sanity check on the synthetic test helpers
describe('test infrastructure sanity', () => {
  test('Finding type round-trips through JSON without loss', () => {
    const fixtures = loadFixtures('positive');
    const findings = R03.scan(asScannedFile(fixtures[0]!));
    const roundTripped: Finding[] = JSON.parse(JSON.stringify(findings));
    expect(roundTripped).toEqual(findings);
  });
});
