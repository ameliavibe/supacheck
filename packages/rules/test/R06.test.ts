import { describe, expect, test } from 'vitest';
import type { ScannedFile } from '../src/lib/rule-types.js';
import { R06 } from '../src/rules/R06-sql-view-security-invoker.js';

function migration(name: string, body: string): ScannedFile {
  return { path: `supabase/migrations/${name}`, contents: body };
}

describe('R06 single-file scenarios', () => {
  test('CREATE VIEW WITH (security_invoker = on) clean', () => {
    const findings = R06.scanAll!([
      migration(
        '20260601000001_v.sql',
        `CREATE VIEW public.v WITH (security_invoker = on) AS SELECT 1;`,
      ),
    ]);
    expect(findings).toEqual([]);
  });

  test('CREATE VIEW WITHOUT security_invoker fires', () => {
    const findings = R06.scanAll!([
      migration('20260601000001_v.sql', `CREATE VIEW public.v AS SELECT 1;`),
    ]);
    expect(findings.length).toBe(1);
    expect(findings[0]!.ruleId).toBe('R06');
    expect(findings[0]!.file).toBe('supabase/migrations/20260601000001_v.sql');
  });

  test('CREATE then ALTER VIEW SET (security_invoker = on) is clean', () => {
    const findings = R06.scanAll!([
      migration(
        '20260601000001_v.sql',
        `CREATE VIEW public.v AS SELECT 1;
ALTER VIEW public.v SET (security_invoker = on);`,
      ),
    ]);
    expect(findings).toEqual([]);
  });

  test('non-public schema views are not flagged', () => {
    const findings = R06.scanAll!([
      migration('20260601000001_v.sql', `CREATE VIEW auth.v AS SELECT 1;`),
    ]);
    expect(findings).toEqual([]);
  });

  test('DROP VIEW after CREATE clears tracking', () => {
    const findings = R06.scanAll!([
      migration(
        '20260601000001_v.sql',
        `CREATE VIEW public.v AS SELECT 1;
DROP VIEW public.v;`,
      ),
    ]);
    expect(findings).toEqual([]);
  });

  test('ALTER VIEW RESET security_invoker re-introduces vulnerability', () => {
    const findings = R06.scanAll!([
      migration(
        '20260601000001_v.sql',
        `CREATE VIEW public.v WITH (security_invoker = on) AS SELECT 1;
ALTER VIEW public.v RESET (security_invoker);`,
      ),
    ]);
    expect(findings.length).toBe(1);
  });

  test('ALTER VIEW SET (security_invoker = off) re-introduces vulnerability', () => {
    const findings = R06.scanAll!([
      migration(
        '20260601000001_v.sql',
        `CREATE VIEW public.v WITH (security_invoker = on) AS SELECT 1;
ALTER VIEW public.v SET (security_invoker = off);`,
      ),
    ]);
    expect(findings.length).toBe(1);
  });
});

describe('R06 multi-file scenarios (the squash-clobber case)', () => {
  test('earlier file has SI on, later file CREATE OR REPLACE wipes it, fires', () => {
    const findings = R06.scanAll!([
      migration(
        '20260601000001_create.sql',
        `CREATE VIEW public.v WITH (security_invoker = on) AS SELECT 1;`,
      ),
      // Squash baseline re-emits without the WITH clause first
      migration(
        '20260901000002_squash.sql',
        `CREATE OR REPLACE VIEW public.v AS SELECT 1, 2;`,
      ),
    ]);
    expect(findings.length).toBe(1);
    expect(findings[0]!.file).toBe('supabase/migrations/20260901000002_squash.sql');
  });

  test('pg_dump style: emitted twice, second with SI, clean', () => {
    const findings = R06.scanAll!([
      migration(
        '20260901000001_first-emission.sql',
        `CREATE OR REPLACE VIEW public.v AS SELECT 1;`,
      ),
      migration(
        '20260901000002_second-emission.sql',
        `CREATE OR REPLACE VIEW public.v WITH (security_invoker = on) AS SELECT 1;`,
      ),
    ]);
    expect(findings).toEqual([]);
  });

  test('quoted reloption form (pg_dump shape) is accepted', () => {
    const findings = R06.scanAll!([
      migration(
        '20260901000001_quoted.sql',
        `CREATE OR REPLACE VIEW public.v WITH ("security_invoker"='on') AS SELECT 1;`,
      ),
    ]);
    expect(findings).toEqual([]);
  });

  test('two views, one clean, one not; only the bad one fires', () => {
    const findings = R06.scanAll!([
      migration(
        '20260601000001_v.sql',
        `CREATE VIEW public.good WITH (security_invoker = on) AS SELECT 1;
CREATE VIEW public.bad AS SELECT 2;`,
      ),
    ]);
    expect(findings.length).toBe(1);
    expect(findings[0]!.message).toContain('public.bad');
  });
});

describe('R06 metadata', () => {
  test('belongs to the squash-clobber family', () => {
    expect(R06.id).toBe('R06');
    expect(R06.squashClobberFamily).toBe(true);
    expect(R06.severity).toBe('critical');
  });

  test('per-file scan is a no-op', () => {
    const out = R06.scan(migration('x.sql', 'CREATE VIEW public.v AS SELECT 1;'));
    expect(out).toEqual([]);
  });
});
