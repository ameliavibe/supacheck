import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';
import { R07 } from '../src/rules/R07-sql-secdef-role-by-role-revoke.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures', 'R07');

function loadFixtures(kind: 'positive' | 'negative'): { name: string; contents: string }[] {
  const dir = join(FIXTURES_DIR, kind);
  return readdirSync(dir)
    .filter((f) => f.endsWith('.sql'))
    .sort()
    .map((name) => ({ name, contents: readFileSync(join(dir, name), 'utf8') }));
}

describe('R07 positive fixtures', () => {
  for (const fixture of loadFixtures('positive')) {
    test(fixture.name, () => {
      const findings = R07.scan({ path: fixture.name, contents: fixture.contents });
      expect(findings.length).toBe(1);
      expect(findings[0]!.ruleId).toBe('R07');
    });
  }
});

describe('R07 negative fixtures', () => {
  for (const fixture of loadFixtures('negative')) {
    test(fixture.name, () => {
      const findings = R07.scan({ path: fixture.name, contents: fixture.contents });
      expect(findings).toEqual([]);
    });
  }
});

describe('R07 metadata', () => {
  test('belongs to the squash-clobber family', () => {
    expect(R07.id).toBe('R07');
    expect(R07.squashClobberFamily).toBe(true);
    expect(R07.severity).toBe('critical');
  });
});
