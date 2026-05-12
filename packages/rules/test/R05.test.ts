import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';
import type { ScannedFile } from '../src/lib/rule-types.js';
import { createR05, R05 } from '../src/rules/R05-ts-bare-fetch-no-helper.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures', 'R05');

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

describe('R05 positive fixtures', () => {
  for (const fixture of loadFixtures('positive')) {
    test(fixture.path, () => {
      const findings = R05.scan(fixture as ScannedFile);
      expect(findings.length).toBeGreaterThan(0);
      for (const f of findings) {
        expect(f.ruleId).toBe('R05');
        expect(f.file).toBe(fixture.path);
      }
    });
  }
});

describe('R05 negative fixtures', () => {
  for (const fixture of loadFixtures('negative')) {
    test(fixture.path, () => {
      const findings = R05.scan(fixture as ScannedFile);
      expect(findings).toEqual([]);
    });
  }
});

describe('R05 multiplicity', () => {
  test('two bare fetches produce two findings', () => {
    const fixture = loadFixtures('positive').find((f) => f.path.includes('multi/util.ts'));
    expect(fixture).toBeDefined();
    const findings = R05.scan(fixture as ScannedFile);
    expect(findings.length).toBe(2);
  });
});

describe('R05 allowlist', () => {
  test('files in allowlist are skipped', () => {
    const fixture = loadFixtures('positive').find((f) => f.path === 'lib/basic/util.ts');
    expect(fixture).toBeDefined();
    const rule = createR05({ allowlist: ['lib/basic/util.ts'] });
    const findings = rule.scan(fixture as ScannedFile);
    expect(findings).toEqual([]);
  });
});

describe('R05 custom helper imports', () => {
  test('importing a custom helper exempts the file', () => {
    const fixture: Fixture = {
      path: 'lib/foo.ts',
      contents: "import { safeFetch } from '@my-org/safe-fetch';\nawait fetch('https://x');\n",
    };
    const rule = createR05({ helperImports: ['@my-org/safe-fetch'] });
    const findings = rule.scan(fixture as ScannedFile);
    expect(findings).toEqual([]);
  });
});

describe('R05 metadata', () => {
  test('identifies as R05 with the expected slug', () => {
    expect(R05.id).toBe('R05');
    expect(R05.slug).toBe('ts-bare-fetch-no-helper');
    expect(R05.category).toBe('ssrf');
    expect(R05.severity).toBe('high');
    expect(R05.squashClobberFamily).toBe(false);
  });
});
