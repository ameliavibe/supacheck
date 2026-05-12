import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';
import { R04a, createR04a } from '../src/rules/R04a-sql-secdef-hygiene.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures', 'R04a');

function loadFixtures(kind: 'positive' | 'negative'): { name: string; contents: string }[] {
  const dir = join(FIXTURES_DIR, kind);
  return readdirSync(dir)
    .filter((f) => f.endsWith('.sql'))
    .sort()
    .map((name) => ({ name, contents: readFileSync(join(dir, name), 'utf8') }));
}

describe('R04a positive fixtures', () => {
  for (const fixture of loadFixtures('positive')) {
    test(fixture.name, () => {
      const findings = R04a.scan({ path: fixture.name, contents: fixture.contents });
      expect(findings.length).toBeGreaterThan(0);
      for (const f of findings) expect(f.ruleId).toBe('R04a');
    });
  }
});

describe('R04a negative fixtures', () => {
  for (const fixture of loadFixtures('negative')) {
    test(fixture.name, () => {
      const findings = R04a.scan({ path: fixture.name, contents: fixture.contents });
      expect(findings).toEqual([]);
    });
  }
});

describe('R04a multiplicity', () => {
  test('three-violations fixture produces three findings', () => {
    const fixture = loadFixtures('positive').find((f) => f.name.includes('three-violations'));
    expect(fixture).toBeDefined();
    const findings = R04a.scan({ path: fixture!.name, contents: fixture!.contents });
    expect(findings.length).toBe(3);
  });
});

describe('R04a metadata', () => {
  test('belongs to the squash-clobber family', () => {
    expect(R04a.id).toBe('R04a');
    expect(R04a.squashClobberFamily).toBe(true);
  });

  test('baseline filter skips old files', () => {
    const fixture = loadFixtures('positive')[0]!;
    const ruleWithBaseline = createR04a({ migrationsBaselineTimestamp: '20300101000000' });
    expect(ruleWithBaseline.scan({ path: fixture.name, contents: fixture.contents })).toEqual([]);
  });
});
