import { describe, expect, test } from 'vitest';
import type { ScannedFile } from '../src/lib/rule-types.js';
import { createR04a, R04a } from '../src/rules/R04a-sql-secdef-hygiene.js';
import { R07 } from '../src/rules/R07-sql-secdef-role-by-role-revoke.js';
import { createR09, R09 } from '../src/rules/R09-sql-secdef-anon-execute.js';

function migration(name: string, body: string): ScannedFile {
  return { path: `supabase/migrations/${name}`, contents: body };
}

const LOCKED = `
CREATE OR REPLACE FUNCTION public.f(p uuid) RETURNS void LANGUAGE sql SECURITY DEFINER
  SET search_path TO 'public', 'pg_temp' AS $$ select 1 $$;
ALTER FUNCTION public.f(uuid) OWNER TO postgres;
REVOKE EXECUTE ON FUNCTION public.f(uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.f(uuid) TO service_role;`;

const BARE = `
CREATE FUNCTION public.f(p uuid) RETURNS void LANGUAGE sql SECURITY DEFINER AS $$ select 1 $$;`;

const messages = (rule: { scanAll?: (f: ScannedFile[]) => { message: string }[] }, files: ScannedFile[]) =>
  rule.scanAll!(files).map((f) => f.message);

describe('R04a across migrations', () => {
  test('a fully locked-down function is clean', () => {
    expect(R04a.scanAll!([migration('20260601000001_a.sql', LOCKED)])).toEqual([]);
  });

  test('a bare definition raises all three findings, anchored on its file', () => {
    const findings = R04a.scanAll!([migration('20260601000001_a.sql', BARE)]);
    expect(findings).toHaveLength(3);
    expect(findings.every((f) => f.file.endsWith('20260601000001_a.sql') && f.line === 2)).toBe(true);
  });

  test('a later migration that adds the missing statements clears them', () => {
    const findings = R04a.scanAll!([
      migration('20260601000001_a.sql', BARE),
      migration(
        '20260602000001_fix.sql',
        `ALTER FUNCTION public.f(uuid) SET search_path = public, pg_temp;
ALTER FUNCTION public.f(uuid) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.f(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.f(uuid) FROM anon, authenticated;`,
      ),
    ]);
    expect(findings).toEqual([]);
  });

  test('files replay in timestamp order whatever order they arrive in', () => {
    const fix = migration('20260602000001_fix.sql', `DROP FUNCTION public.f(uuid);`);
    expect(R04a.scanAll!([fix, migration('20260601000001_a.sql', BARE)])).toEqual([]);
  });

  test('CREATE OR REPLACE of the same identity keeps the owner and REVOKEs', () => {
    const findings = R04a.scanAll!([
      migration('20260601000001_a.sql', LOCKED),
      migration(
        '20260602000001_replace.sql',
        `CREATE OR REPLACE FUNCTION public.f("p_renamed" "uuid" DEFAULT NULL) RETURNS void LANGUAGE sql
  SECURITY DEFINER SET "search_path" TO 'public', 'pg_temp' AS $$ select 2 $$;`,
      ),
    ]);
    expect(findings).toEqual([]);
  });

  test('a changed argument type is a new function and needs its own lock-down', () => {
    const findings = R04a.scanAll!([
      migration('20260601000001_a.sql', LOCKED),
      migration(
        '20260602000001_overload.sql',
        `CREATE OR REPLACE FUNCTION public.f(p text) RETURNS void LANGUAGE sql SECURITY DEFINER
  SET search_path TO 'public', 'pg_temp' AS $$ select 2 $$;`,
      ),
    ]);
    expect(findings.map((f) => f.file.split('/').pop())).toEqual([
      '20260602000001_overload.sql',
      '20260602000001_overload.sql',
    ]);
  });

  test('a replace that drops the search_path attribute is flagged on the replace', () => {
    const findings = R04a.scanAll!([
      migration('20260601000001_a.sql', LOCKED),
      migration(
        '20260602000001_replace.sql',
        `CREATE OR REPLACE FUNCTION public.f(p uuid) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
AS $$ BEGIN SET search_path TO public, pg_temp; END $$;`,
      ),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('missing SET search_path');
    expect(findings[0]!.file).toContain('20260602000001_replace.sql');
  });

  test('RESET search_path in a later migration re-raises the finding there', () => {
    const findings = R04a.scanAll!([
      migration('20260601000001_a.sql', LOCKED),
      migration('20260602000001_reset.sql', `\nALTER FUNCTION public.f(uuid) RESET search_path;`),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ line: 2 });
    expect(findings[0]!.file).toContain('20260602000001_reset.sql');
  });

  test('a later non-postgres owner is flagged; an owner fix on another overload does not count', () => {
    expect(
      messages(R04a, [
        migration('20260601000001_a.sql', LOCKED),
        migration('20260602000001_own.sql', `ALTER FUNCTION public.f(uuid) OWNER TO app_admin;`),
      ]),
    ).toEqual([expect.stringContaining('OWNER TO postgres')]);

    const bareOwnerOnly = LOCKED.replace('ALTER FUNCTION public.f(uuid) OWNER TO postgres;', '');
    expect(
      messages(R04a, [
        migration('20260601000001_a.sql', bareOwnerOnly),
        migration('20260602000001_own.sql', `ALTER FUNCTION public.f(text) OWNER TO postgres;`),
      ]),
    ).toEqual([expect.stringContaining('OWNER TO postgres')]);
  });

  test('a REVOKE that schema-qualifies a type the definition left bare still lands', () => {
    const sql = `
CREATE FUNCTION public.g(p plan_tier) RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$ select 1 $$;
ALTER FUNCTION public.g(public.plan_tier) OWNER TO postgres;
REVOKE EXECUTE ON FUNCTION public.g("public"."plan_tier") FROM PUBLIC, anon, authenticated;`;
    expect(R04a.scanAll!([migration('20260601000001_a.sql', sql)])).toEqual([]);
  });

  test('a schema-wide REVOKE locks down the functions that exist at that point', () => {
    const findings = messages(R04a, [
      migration(
        '20260601000001_a.sql',
        `${LOCKED.replace('REVOKE EXECUTE ON FUNCTION public.f(uuid) FROM PUBLIC, anon, authenticated;', '')}
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, anon, authenticated;`,
      ),
    ]);
    expect(findings).toEqual([]);
  });

  test('SECURITY INVOKER functions are ignored, and ALTER ... SECURITY INVOKER retires the obligation', () => {
    expect(
      R04a.scanAll!([
        migration('20260601000001_a.sql', `CREATE FUNCTION public.h() RETURNS void LANGUAGE sql AS $$ select 1 $$;`),
      ]),
    ).toEqual([]);
    expect(
      R04a.scanAll!([
        migration('20260601000001_a.sql', BARE),
        migration('20260602000001_inv.sql', `ALTER FUNCTION public.f(uuid) SECURITY INVOKER;`),
      ]),
    ).toEqual([]);
  });

  test('a renamed function carries its state to the new name', () => {
    const findings = R04a.scanAll!([
      migration('20260601000001_a.sql', LOCKED),
      migration(
        '20260602000001_rename.sql',
        `ALTER FUNCTION public.f(uuid) RENAME TO f2;
ALTER FUNCTION public.f2(uuid) RESET search_path;`,
      ),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('f2()');
  });
});

describe('R04a search_path contents', () => {
  const withPath = (path: string): ScannedFile =>
    migration('20260601000001_a.sql', LOCKED.replace(`SET search_path TO 'public', 'pg_temp'`, path));

  test('a non-empty path without pg_temp is flagged with the path it has', () => {
    const findings = messages(R04a, [withPath(`SET search_path = public, extensions`)]);
    expect(findings).toEqual([expect.stringContaining('without pg_temp (has: public, extensions)')]);
  });

  test("the empty path Supabase recommends is accepted", () => {
    expect(R04a.scanAll!([withPath(`SET search_path = ''`)])).toEqual([]);
    expect(R04a.scanAll!([withPath(`SET "search_path" TO ''`)])).toEqual([]);
  });

  test('pg_temp anywhere in the list satisfies it, quoted or not', () => {
    expect(R04a.scanAll!([withPath(`SET search_path TO "public", "pg_temp"`)])).toEqual([]);
    expect(R04a.scanAll!([withPath(`SET search_path = pg_catalog, public, pg_temp`)])).toEqual([]);
  });

  test('the attribute is read when the body opener follows on the same line', () => {
    const sql = `CREATE FUNCTION public.k() RETURNS void SET search_path = '' SECURITY DEFINER LANGUAGE sql AS $$ select 1 $$;
ALTER FUNCTION public.k() OWNER TO postgres;
REVOKE ALL ON FUNCTION public.k() FROM PUBLIC, anon, authenticated;`;
    expect(R04a.scanAll!([migration('20260601000001_a.sql', sql)])).toEqual([]);
  });
});

describe('R04a baseline and coverage', () => {
  test('pre-baseline files are not reported but their lock-down is inherited', () => {
    const rule = createR04a({ migrationsBaselineTimestamp: '20260601000001' });
    expect(rule.scanAll!([migration('20260601000001_a.sql', BARE)])).toEqual([]);
    expect(
      rule.scanAll!([
        migration('20260601000001_a.sql', LOCKED),
        migration(
          '20260602000001_replace.sql',
          `CREATE OR REPLACE FUNCTION public.f(p uuid) RETURNS void LANGUAGE sql SECURITY DEFINER
  SET search_path TO 'public', 'pg_temp' AS $$ select 2 $$;`,
        ),
      ]),
    ).toEqual([]);
  });

  test('a post-baseline regression of a pre-baseline function is reported', () => {
    const rule = createR04a({ migrationsBaselineTimestamp: '20260601000001' });
    const findings = rule.scanAll!([
      migration('20260601000001_a.sql', LOCKED),
      migration('20260602000001_reset.sql', `ALTER FUNCTION public.f(uuid) RESET search_path;`),
    ]);
    expect(findings).toHaveLength(1);
  });

  test('a CREATE FUNCTION the parser cannot read is reported, not skipped', () => {
    const findings = R04a.scanAll!([
      migration('20260601000001_a.sql', `CREATE FUNCTION broken(a int RETURNS void SECURITY DEFINER AS $$ $$;`),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('Could not parse');
  });

  test('non-migration SQL files are ignored', () => {
    expect(R04a.scanAll!([{ path: 'supabase/seed.sql', contents: BARE }])).toEqual([]);
  });
});

describe('R07 across migrations', () => {
  const PUBLIC_ONLY = LOCKED.replace('FROM PUBLIC, anon, authenticated', 'FROM PUBLIC');

  test('a PUBLIC-only REVOKE fires', () => {
    expect(R07.scanAll!([migration('20260601000001_a.sql', PUBLIC_ONLY)])).toHaveLength(1);
  });

  test('role-by-role REVOKEs in a later migration clear it', () => {
    expect(
      R07.scanAll!([
        migration('20260601000001_a.sql', PUBLIC_ONLY),
        migration('20260602000001_fix.sql', `REVOKE EXECUTE ON FUNCTION f FROM anon, authenticated;`),
      ]),
    ).toEqual([]);
  });

  test('no REVOKE at all is left to R04a', () => {
    expect(R07.scanAll!([migration('20260601000001_a.sql', BARE)])).toEqual([]);
  });
});

describe('R09 anon EXECUTE', () => {
  const GRANT_ANON = `GRANT EXECUTE ON FUNCTION public.f(uuid) TO anon;`;

  test('a locked-down function is clean', () => {
    expect(R09.scanAll!([migration('20260601000001_a.sql', LOCKED)])).toEqual([]);
  });

  test('a GRANT to anon after the REVOKE fires, anchored on the GRANT', () => {
    const findings = R09.scanAll!([
      migration('20260601000001_a.sql', LOCKED),
      migration('20260602000001_grant.sql', `\n\n${GRANT_ANON}`),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: 'R09', line: 3 });
    expect(findings[0]!.file).toContain('20260602000001_grant.sql');
  });

  test('a REVOKE after the GRANT clears it, in the same file or a later one', () => {
    expect(
      R09.scanAll!([
        migration('20260601000001_a.sql', `${LOCKED}\n${GRANT_ANON}\nREVOKE ALL ON FUNCTION public.f(uuid) FROM anon;`),
      ]),
    ).toEqual([]);
    expect(
      R09.scanAll!([
        migration('20260601000001_a.sql', `${LOCKED}\n${GRANT_ANON}`),
        migration('20260602000001_fix.sql', `REVOKE EXECUTE ON FUNCTION public.f(uuid) FROM anon;`),
      ]),
    ).toEqual([]);
  });

  test('a GRANT to PUBLIC counts, and is cleared only by a REVOKE from PUBLIC', () => {
    const granted = `${LOCKED}\nGRANT EXECUTE ON FUNCTION public.f(uuid) TO PUBLIC;`;
    expect(R09.scanAll!([migration('20260601000001_a.sql', granted)])).toHaveLength(1);
    expect(
      R09.scanAll!([
        migration('20260601000001_a.sql', `${granted}\nREVOKE EXECUTE ON FUNCTION public.f(uuid) FROM anon;`),
      ]),
    ).toHaveLength(1);
    expect(
      R09.scanAll!([
        migration('20260601000001_a.sql', `${granted}\nREVOKE EXECUTE ON FUNCTION public.f(uuid) FROM PUBLIC;`),
      ]),
    ).toEqual([]);
  });

  test('default privileges make later functions anon-executable, not earlier ones', () => {
    const adp = `ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "anon";`;
    const findings = R09.scanAll!([
      migration('20260601000001_a.sql', BARE),
      migration('20260602000001_adp.sql', adp),
      migration(
        '20260603000001_later.sql',
        `CREATE FUNCTION public.later() RETURNS void LANGUAGE sql SECURITY DEFINER AS $$ select 1 $$;`,
      ),
    ]);
    expect(findings.map((f) => f.message)).toEqual([expect.stringContaining('public.later()')]);
  });

  test('default privileges for another schema do not apply, and a REVOKE turns them off', () => {
    const later = migration(
      '20260603000001_later.sql',
      `CREATE FUNCTION public.later() RETURNS void LANGUAGE sql SECURITY DEFINER AS $$ select 1 $$;`,
    );
    expect(
      R09.scanAll!([
        migration('20260601000001_adp.sql', `ALTER DEFAULT PRIVILEGES IN SCHEMA private GRANT EXECUTE ON FUNCTIONS TO anon;`),
        later,
      ]),
    ).toEqual([]);
    expect(
      R09.scanAll!([
        migration(
          '20260601000001_adp.sql',
          `ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO anon;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM anon;`,
        ),
        later,
      ]),
    ).toEqual([]);
  });

  test('GRANT ON ALL FUNCTIONS IN SCHEMA reaches existing functions only', () => {
    const findings = R09.scanAll!([
      migration('20260601000001_a.sql', LOCKED),
      migration('20260602000001_bulk.sql', `GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO anon, authenticated;`),
      migration(
        '20260603000001_later.sql',
        `CREATE FUNCTION public.later() RETURNS void LANGUAGE sql SECURITY DEFINER AS $$ select 1 $$;`,
      ),
    ]);
    expect(findings.map((f) => f.message)).toEqual([expect.stringContaining('public.f()')]);
  });

  test('trigger functions, SECURITY INVOKER functions and allow-listed names are skipped', () => {
    const trigger = `CREATE FUNCTION public.t() RETURNS "trigger" LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN RETURN NEW; END $$;
GRANT ALL ON FUNCTION public.t() TO anon;
CREATE FUNCTION public.inv() RETURNS void LANGUAGE sql AS $$ select 1 $$;
GRANT ALL ON FUNCTION public.inv() TO anon;`;
    expect(R09.scanAll!([migration('20260601000001_a.sql', trigger)])).toEqual([]);
    const allowed = createR09({ allowAnon: ['f'] });
    expect(allowed.scanAll!([migration('20260601000001_a.sql', `${LOCKED}\n${GRANT_ANON}`)])).toEqual([]);
  });

  test('a GRANT of a non-EXECUTE privilege list is ignored', () => {
    expect(
      R09.scanAll!([
        migration('20260601000001_a.sql', `${LOCKED}\nGRANT SELECT ON TABLE public.things TO anon;`),
      ]),
    ).toEqual([]);
  });

  test('dropping and recreating the function starts from a clean ACL', () => {
    expect(
      R09.scanAll!([
        migration('20260601000001_a.sql', `${LOCKED}\n${GRANT_ANON}`),
        migration('20260602000001_recreate.sql', `DROP FUNCTION public.f(uuid);\n${LOCKED}`),
      ]),
    ).toEqual([]);
  });
});
