import { describe, expect, test } from 'vitest';
import type { ScannedFile } from '../src/lib/rule-types.js';
import { createR08, R08, replayPolicies } from '../src/rules/R08-sql-policy-explicit-roles.js';

function migration(name: string, body: string): ScannedFile {
  return { path: `supabase/migrations/${name}`, contents: body };
}

const one = (sql: string) => R08.scanAll!([migration('20260601000001_a.sql', sql)]);

describe('R08 CREATE POLICY', () => {
  test('a policy with no TO clause fires', () => {
    const findings = one(`\nCREATE POLICY "own rows" ON public.notes FOR SELECT USING (user_id = (select auth.uid()));`);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: 'R08', line: 2 });
    expect(findings[0]!.message).toContain('"own rows" on public.notes');
    expect(findings[0]!.message).toContain('no TO clause');
  });

  test('TO public fires and says which spelling it found', () => {
    const findings = one(`CREATE POLICY p ON notes TO public USING (true);`);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('(TO public)');
  });

  test('a role list that includes public still applies to everyone', () => {
    expect(one(`CREATE POLICY p ON notes TO authenticated, PUBLIC USING (true);`)).toHaveLength(1);
  });

  test('named roles are clean: bare, quoted, several, with AS and FOR', () => {
    expect(
      one(`
CREATE POLICY a ON public.notes TO authenticated USING (true);
CREATE POLICY "b" ON "public"."notes" AS RESTRICTIVE FOR UPDATE TO "authenticated", "service_role" USING (true) WITH CHECK (true);
CREATE POLICY c ON notes FOR INSERT TO anon WITH CHECK (true);`),
    ).toEqual([]);
  });

  test('an unqualified table is public; other schemas are out of scope unless configured', () => {
    expect(one(`CREATE POLICY p ON notes USING (true);`)).toHaveLength(1);
    const storage = `CREATE POLICY "Public read avatars" ON storage.objects FOR SELECT USING (bucket_id = 'avatars');`;
    expect(one(storage)).toEqual([]);
    const rule = createR08({ schemas: ['public', 'storage'] });
    expect(rule.scanAll!([migration('20260601000001_a.sql', storage)])).toHaveLength(1);
  });

  test('a "to" inside a predicate or a string is not a TO clause', () => {
    const findings = one(
      `CREATE POLICY p ON notes FOR SELECT USING (shared_to = 'TO authenticated; x' AND to_tsvector(body) IS NOT NULL);`,
    );
    expect(findings).toHaveLength(1);
  });

  test('a policy without USING does not swallow the next statement', () => {
    const policies = replayPolicies([
      migration(
        '20260601000001_a.sql',
        `CREATE POLICY a ON notes TO authenticated;
CREATE POLICY b ON tasks USING (true);`,
      ),
    ]);
    expect(policies.map((p) => [p.name, p.table, p.roles])).toEqual([
      ['a', 'notes', ['authenticated']],
      ['b', 'tasks', undefined],
    ]);
  });

  test('commented-out policies and non-migration files are ignored', () => {
    expect(one(`-- CREATE POLICY p ON notes USING (true);\n/* CREATE POLICY q ON notes USING (true); */`)).toEqual([]);
    expect(R08.scanAll!([{ path: 'supabase/seed.sql', contents: `CREATE POLICY p ON notes USING (true);` }])).toEqual([]);
  });
});

describe('R08 replay', () => {
  const OPEN = migration('20260601000001_a.sql', `CREATE POLICY "p" ON public.notes USING (true);`);

  test('a later ALTER POLICY ... TO clears the finding', () => {
    expect(
      R08.scanAll!([OPEN, migration('20260602000001_fix.sql', `ALTER POLICY "p" ON public.notes TO authenticated;`)]),
    ).toEqual([]);
  });

  test('a later ALTER POLICY ... TO public raises one, anchored on the ALTER', () => {
    const findings = R08.scanAll!([
      migration('20260601000001_a.sql', `CREATE POLICY p ON notes TO authenticated USING (true);`),
      migration('20260602000001_widen.sql', `ALTER POLICY p ON notes TO public;`),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.file).toContain('20260602000001_widen.sql');
  });

  test('ALTER replaces the role list rather than merging it', () => {
    const [policy] = replayPolicies([
      migration('20260601000001_a.sql', `CREATE POLICY p ON notes TO authenticated, service_role USING (true);`),
      migration('20260602000001_b.sql', `ALTER POLICY p ON notes TO service_role USING (true);`),
    ]);
    expect(policy!.roles).toEqual(['service_role']);
  });

  test('an ALTER that only changes the predicate leaves the roles alone', () => {
    expect(
      R08.scanAll!([OPEN, migration('20260602000001_b.sql', `ALTER POLICY "p" ON public.notes USING (owner_id = 1);`)]),
    ).toHaveLength(1);
  });

  test('files replay in timestamp order whatever order they arrive in', () => {
    const fix = migration('20260602000001_fix.sql', `ALTER POLICY "p" ON public.notes TO authenticated;`);
    expect(R08.scanAll!([fix, OPEN])).toEqual([]);
  });

  test('DROP POLICY removes it; a re-create in the same file is judged on its own', () => {
    expect(R08.scanAll!([OPEN, migration('20260602000001_b.sql', `DROP POLICY IF EXISTS "p" ON public.notes;`)])).toEqual([]);
    expect(
      R08.scanAll!([
        OPEN,
        migration(
          '20260602000001_b.sql',
          `DROP POLICY "p" ON public.notes;
CREATE POLICY "p" ON public.notes TO authenticated USING (true);`,
        ),
      ]),
    ).toEqual([]);
  });

  test('DROP TABLE cascades to its policies, including in a comma list', () => {
    expect(
      R08.scanAll!([
        OPEN,
        migration('20260602000001_b.sql', `DROP TABLE IF EXISTS public.other, public.notes CASCADE;`),
      ]),
    ).toEqual([]);
  });

  test('ALTER TABLE ... RENAME TO carries policies; a later ALTER lands on the new name', () => {
    const renamed = migration('20260602000001_b.sql', `ALTER TABLE public.notes RENAME TO memos;`);
    const findings = R08.scanAll!([OPEN, renamed]);
    expect(findings[0]!.message).toContain('public.memos');
    expect(
      R08.scanAll!([OPEN, renamed, migration('20260603000001_c.sql', `ALTER POLICY "p" ON memos TO authenticated;`)]),
    ).toEqual([]);
  });

  test('a column rename is not a table rename', () => {
    const findings = R08.scanAll!([
      OPEN,
      migration('20260602000001_b.sql', `ALTER TABLE public.notes RENAME COLUMN body TO content;`),
    ]);
    expect(findings[0]!.message).toContain('public.notes');
  });

  test('ALTER POLICY ... RENAME TO re-keys the policy and keeps its roles', () => {
    const [policy] = replayPolicies([
      OPEN,
      migration('20260602000001_b.sql', `ALTER POLICY "p" ON public.notes RENAME TO "q";`),
    ]);
    expect(policy).toMatchObject({ name: 'q', roles: undefined });
  });

  test('pre-baseline policies are not reported, but a post-baseline widening is', () => {
    const rule = createR08({ migrationsBaselineTimestamp: '20260601000001' });
    expect(rule.scanAll!([OPEN])).toEqual([]);
    expect(
      rule.scanAll!([
        migration('20260601000001_a.sql', `CREATE POLICY p ON notes TO authenticated USING (true);`),
        migration('20260602000001_widen.sql', `ALTER POLICY p ON notes TO public;`),
      ]),
    ).toHaveLength(1);
  });
});
