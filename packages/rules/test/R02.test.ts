import { describe, expect, test } from 'vitest';
import type { ScannedFile } from '../src/lib/rule-types.js';
import { createR02, R02 } from '../src/rules/R02-ts-sensitive-select-star.js';

const SENSITIVE = ['users', 'subscriptions', 'stripe_events'];

function tsFile(contents: string, path = 'app/api/test/route.ts'): ScannedFile {
  return { path, contents };
}

const rule = createR02({ sensitiveTables: SENSITIVE });

describe('R02 positive cases', () => {
  test('basic select * on a sensitive table', () => {
    const findings = rule.scan(
      tsFile(`const { data } = await supabase.from('users').select('*');`),
    );
    expect(findings.length).toBe(1);
    expect(findings[0]!.ruleId).toBe('R02');
    expect(findings[0]!.message).toContain('users');
  });

  test('chained eq().select(*) still flagged', () => {
    const findings = rule.scan(
      tsFile(
        `const { data } = await supabase.from('subscriptions')
  .eq('user_id', userId)
  .order('created_at', { ascending: false })
  .limit(1)
  .single()
  .select('*');`,
      ),
    );
    expect(findings.length).toBe(1);
  });

  test('multi-line chain with nested calls is still walked correctly', () => {
    const findings = rule.scan(
      tsFile(
        `const { data } = await supabase
  .from('users')
  .eq('id', getCurrentUserId(req.headers.get('x-user')))
  .select('*');`,
      ),
    );
    expect(findings.length).toBe(1);
  });

  test('two from() calls in the same file produce two findings', () => {
    const findings = rule.scan(
      tsFile(`
const a = await supabase.from('users').select('*');
const b = await supabase.from('subscriptions').select('*');
`),
    );
    expect(findings.length).toBe(2);
  });

  test('select with backticks (template literal star)', () => {
    const findings = rule.scan(
      tsFile("const { data } = await supabase.from('users').select(`*`);"),
    );
    expect(findings.length).toBe(1);
  });

  test('select with double quotes', () => {
    const findings = rule.scan(
      tsFile(`const { data } = await supabase.from('users').select("*");`),
    );
    expect(findings.length).toBe(1);
  });
});

describe('R02 negative cases', () => {
  test('select with explicit columns is fine', () => {
    const findings = rule.scan(
      tsFile(`const { data } = await supabase.from('users').select('id, email');`),
    );
    expect(findings).toEqual([]);
  });

  test('from() with no select is fine', () => {
    const findings = rule.scan(
      tsFile(`const r = await supabase.from('users').delete();`),
    );
    expect(findings).toEqual([]);
  });

  test('select(*) on a non-sensitive table is not flagged', () => {
    const findings = rule.scan(
      tsFile(`const { data } = await supabase.from('public_posts').select('*');`),
    );
    expect(findings).toEqual([]);
  });

  test('sibling .from(other) chain on the next line does not bleed', () => {
    const findings = rule.scan(
      tsFile(
        `const a = await supabase.from('users').select('id');
const b = await supabase.from('subscriptions').select('id');
`,
      ),
    );
    // Both narrowed; neither uses select('*'). Walker correctly bounded each chain.
    expect(findings).toEqual([]);
  });

  test('a wholesale select on a NON-sensitive table near a sensitive read does not bleed', () => {
    const findings = rule.scan(
      tsFile(
        `const safe = await supabase.from('public_data').select('*');
const protect = await supabase.from('users').select('id');
`,
      ),
    );
    expect(findings).toEqual([]);
  });

  test('test files are skipped', () => {
    const findings = rule.scan(
      tsFile(
        `await supabase.from('users').select('*');`,
        'lib/users.test.ts',
      ),
    );
    expect(findings).toEqual([]);
  });

  test('non-TS files are skipped', () => {
    const findings = rule.scan(
      tsFile(
        `await supabase.from('users').select('*');`,
        'app/page.jsx',
      ),
    );
    expect(findings).toEqual([]);
  });
});

describe('R02 configuration', () => {
  test('empty sensitiveTables list is a no-op', () => {
    const empty = createR02({ sensitiveTables: [] });
    const findings = empty.scan(
      tsFile(`await supabase.from('users').select('*');`),
    );
    expect(findings).toEqual([]);
  });

  test('default rule export uses empty list', () => {
    const findings = R02.scan(
      tsFile(`await supabase.from('users').select('*');`),
    );
    expect(findings).toEqual([]);
  });
});

describe('R02 metadata', () => {
  test('identifies as R02', () => {
    expect(R02.id).toBe('R02');
    expect(R02.slug).toBe('ts-sensitive-select-star');
    expect(R02.category).toBe('data-exposure');
    expect(R02.severity).toBe('high');
    expect(R02.squashClobberFamily).toBe(false);
  });
});
