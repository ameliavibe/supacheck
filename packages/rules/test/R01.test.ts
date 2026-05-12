import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';
import type { ScannedFile } from '../src/lib/rule-types.js';
import { createR01, R01 } from '../src/rules/R01-ts-supabase-auth-getuser.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures', 'R01');

interface Fixture {
  path: string;
  contents: string;
}

function loadFixtures(kind: 'positive' | 'negative'): Fixture[] {
  const dir = join(FIXTURES_DIR, kind);
  const out: Fixture[] = [];
  function walk(d: string, prefix: string): void {
    for (const entry of readdirSync(d)) {
      const full = join(d, entry);
      const rel = prefix ? `${prefix}/${entry}` : entry;
      const s = statSync(full);
      if (s.isDirectory()) walk(full, rel);
      else if (s.isFile()) out.push({ path: rel, contents: readFileSync(full, 'utf8') });
    }
  }
  walk(dir, '');
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

describe('R01 positive fixtures', () => {
  for (const fixture of loadFixtures('positive')) {
    test(fixture.path, () => {
      const findings = R01.scan(fixture as ScannedFile);
      expect(findings.length).toBeGreaterThan(0);
      for (const f of findings) {
        expect(f.ruleId).toBe('R01');
        expect(f.file).toBe(fixture.path);
      }
    });
  }
});

describe('R01 negative fixtures', () => {
  for (const fixture of loadFixtures('negative')) {
    test(fixture.path, () => {
      const findings = R01.scan(fixture as ScannedFile);
      expect(findings).toEqual([]);
    });
  }
});

describe('R01 multiplicity', () => {
  test('two bare calls in one file produce two findings', () => {
    const fixture = loadFixtures('positive').find((f) => f.path.includes('multi/route.ts'));
    expect(fixture).toBeDefined();
    const findings = R01.scan(fixture as ScannedFile);
    expect(findings.length).toBe(2);
  });
});

describe('R01 allowlist', () => {
  test('files matching an allowlist entry are skipped', () => {
    const fixture = loadFixtures('positive').find((f) => f.path === 'app/api/basic/route.ts');
    expect(fixture).toBeDefined();
    const rule = createR01({ allowlist: ['app/api/basic/route.ts'] });
    const findings = rule.scan(fixture as ScannedFile);
    expect(findings).toEqual([]);
  });

  test('allowlist suffix match works', () => {
    const fixture = loadFixtures('positive').find((f) => f.path === 'app/api/basic/route.ts');
    expect(fixture).toBeDefined();
    const rule = createR01({ allowlist: ['basic/route.ts'] });
    const findings = rule.scan(fixture as ScannedFile);
    expect(findings).toEqual([]);
  });
});

describe('R01 metadata', () => {
  test('identifies as R01 with the expected slug', () => {
    expect(R01.id).toBe('R01');
    expect(R01.slug).toBe('ts-supabase-auth-getuser');
    expect(R01.category).toBe('auth-cache-coherence');
    expect(R01.severity).toBe('high');
    expect(R01.squashClobberFamily).toBe(false);
  });
});
