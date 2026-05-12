import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';
import { R04b } from '../src/rules/R04b-sql-policy-service-role-to.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures', 'R04b');

function loadFixtures(kind: 'positive' | 'negative'): { name: string; contents: string }[] {
  const dir = join(FIXTURES_DIR, kind);
  return readdirSync(dir)
    .filter((f) => f.endsWith('.sql'))
    .sort()
    .map((name) => ({ name, contents: readFileSync(join(dir, name), 'utf8') }));
}

describe('R04b positive fixtures', () => {
  for (const fixture of loadFixtures('positive')) {
    test(fixture.name, () => {
      const findings = R04b.scan({ path: fixture.name, contents: fixture.contents });
      expect(findings.length).toBeGreaterThan(0);
      for (const f of findings) expect(f.ruleId).toBe('R04b');
    });
  }
});

describe('R04b negative fixtures', () => {
  for (const fixture of loadFixtures('negative')) {
    test(fixture.name, () => {
      const findings = R04b.scan({ path: fixture.name, contents: fixture.contents });
      expect(findings).toEqual([]);
    });
  }
});

describe('R04b metadata', () => {
  test('belongs to the squash-clobber family', () => {
    expect(R04b.id).toBe('R04b');
    expect(R04b.squashClobberFamily).toBe(true);
  });
});
