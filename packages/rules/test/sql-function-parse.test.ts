import { describe, expect, test } from 'vitest';
import {
  countCreateFunctionStatements,
  lexSql,
  normalizeArgType,
  parseSqlFunctions,
  signatureOf,
} from '../src/lib/sql-function-parse.js';

function identity(sql: string): string {
  const fn = parseSqlFunctions(sql).functions[0]!;
  return signatureOf(fn.name, fn.argTypes);
}

describe('lexSql', () => {
  test('blanks comments in place so offsets match the original', () => {
    const sql = 'SELECT 1; -- CREATE FUNCTION x()\n/* outer /* nested */ still */ SELECT 2;';
    const { clean, statements } = lexSql(sql);
    expect(clean.length).toBe(sql.length);
    expect(clean).not.toContain('CREATE');
    expect(clean).not.toContain('still');
    expect(statements.map((s) => s.text.trim())).toEqual(['SELECT 1;', 'SELECT 2;']);
  });

  test('a semicolon inside a string, identifier or body does not end a statement', () => {
    const sql = `SELECT 'a;b' AS "c;d"; DO $x$ BEGIN PERFORM 1; END $x$;`;
    expect(lexSql(sql).statements).toHaveLength(2);
  });

  test('-- inside a string is not a comment, and $1 is not a dollar tag', () => {
    const { clean, dollarSpans } = lexSql(`SELECT '--not a comment', $1;`);
    expect(clean).toContain('--not a comment');
    expect(dollarSpans).toEqual([]);
  });

  test('offsets stay aligned after a character outside the BMP', () => {
    const sql = `SELECT '😀'; -- gone\nSELECT 2;`;
    const { clean, statements } = lexSql(sql);
    expect(clean.length).toBe(sql.length);
    expect(clean.slice(statements[1]!.start, statements[1]!.end).trim()).toBe('SELECT 2;');
  });
});

describe('parseSqlFunctions: definitions', () => {
  test('reads the pg_dump quoted form, the qualified form and the bare form', () => {
    const { functions } = parseSqlFunctions(`
CREATE OR REPLACE FUNCTION "public"."a"("p" "uuid") RETURNS void LANGUAGE sql AS $$ select 1 $$;
CREATE FUNCTION public.b() RETURNS void LANGUAGE sql AS $$ select 1 $$;
CREATE FUNCTION C() RETURNS void LANGUAGE sql AS $$ select 1 $$;`);
    expect(functions.map((f) => [f.schema, f.name, f.isReplace])).toEqual([
      ['public', 'a', true],
      ['public', 'b', false],
      [null, 'c', false],
    ]);
  });

  test('a tagged body with $$ and positional parameters inside is one statement', () => {
    const { functions, statements } = parseSqlFunctions(
      `CREATE FUNCTION f(a int) RETURNS text LANGUAGE plpgsql AS $_$ BEGIN RETURN $1 || '$$;'; END $_$;`,
    );
    expect(statements).toHaveLength(1);
    expect(functions[0]!.hasBody).toBe(true);
  });

  test("reads the AS 'literal' body form without taking a search_path literal as the body", () => {
    const fn = parseSqlFunctions(
      `CREATE FUNCTION f() RETURNS int LANGUAGE sql SET search_path TO 'public', 'pg_temp' AS 'select 1';`,
    ).functions[0]!;
    expect(fn.preBodyText).toContain("'pg_temp'");
    expect(fn.preBodyText).not.toContain('select 1');
  });

  test('preBodyText never includes a SET written inside the body', () => {
    const fn = parseSqlFunctions(
      `CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $fn$ BEGIN SET search_path TO public; END $fn$;`,
    ).functions[0]!;
    expect(fn.preBodyText).toContain('SECURITY DEFINER');
    expect(fn.preBodyText).not.toContain('search_path');
  });

  test('reports the line of the CREATE keyword, not the comment above it', () => {
    const fn = parseSqlFunctions(`-- header\n\n-- more\nCREATE FUNCTION f() RETURNS void LANGUAGE sql AS $$ $$;`)
      .functions[0]!;
    expect(fn.line).toBe(4);
  });

  test('does not parse a commented-out definition', () => {
    expect(parseSqlFunctions(`-- CREATE FUNCTION f() RETURNS void AS $$ $$;`).functions).toEqual([]);
  });
});

describe('parseSqlFunctions: argument identity', () => {
  const body = `RETURNS void LANGUAGE sql AS $$ $$;`;

  test('is unmoved by names, quoting, defaults, modifiers and aliases', () => {
    const a = identity(
      `CREATE FUNCTION f("p_id" "uuid", p_at timestamp with time zone DEFAULT now(), p_n numeric(10,2) = 0, p_tags "text"[]) ${body}`,
    );
    const b = identity(`CREATE FUNCTION f(uuid, timestamptz, numeric, text[]) ${body}`);
    expect(a).toBe(b);
    expect(a).toBe('f(uuid,timestamp with time zone,numeric,text[])');
  });

  test('is moved by a changed or added argument type', () => {
    expect(identity(`CREATE FUNCTION f(a uuid) ${body}`)).not.toBe(identity(`CREATE FUNCTION f(a text) ${body}`));
    expect(identity(`CREATE FUNCTION f(a uuid) ${body}`)).not.toBe(
      identity(`CREATE FUNCTION f(a uuid, b int) ${body}`),
    );
  });

  test('excludes OUT parameters and keeps INOUT and VARIADIC', () => {
    expect(identity(`CREATE FUNCTION f(IN a int, OUT b text, INOUT c bool, VARIADIC d text[]) ${body}`)).toBe(
      'f(integer,boolean,text[])',
    );
  });

  test('reads an unnamed multi-word type as a type', () => {
    expect(identity(`CREATE FUNCTION f(double precision, character varying(20)) ${body}`)).toBe(
      'f(double precision,character varying)',
    );
  });

  test('normalizeArgType strips pg_catalog and keeps a qualified enum', () => {
    expect(normalizeArgType('"pg_catalog"."int4"')).toBe('integer');
    expect(normalizeArgType('"public"."Plan_Tier"')).toBe('public.plan_tier');
    expect(normalizeArgType('integer ARRAY')).toBe('integer[]');
  });
});

describe('parseSqlFunctions: DROP, ALTER, GRANT, REVOKE', () => {
  test('DROP with and without an arglist; a comma-list is declined', () => {
    const { drops } = parseSqlFunctions(`
DROP FUNCTION IF EXISTS public.a(uuid) CASCADE;
DROP FUNCTION b;
DROP FUNCTION c(uuid), d(uuid);`);
    expect(drops.map((d) => [d.name, d.argTypes])).toEqual([
      ['a', ['uuid']],
      ['b', null],
    ]);
  });

  test('ALTER reads owner, search_path, reset, rename and security, with or without an arglist', () => {
    const { alters } = parseSqlFunctions(`
ALTER FUNCTION "public"."a"("uuid") OWNER TO "postgres";
ALTER FUNCTION a(uuid) SET search_path = public, pg_temp;
ALTER FUNCTION a(uuid) RESET search_path;
ALTER FUNCTION a(uuid) RENAME TO b;
ALTER FUNCTION b SECURITY INVOKER;`);
    expect(alters[0]!.ownerTo).toBe('postgres');
    expect(alters[1]!.searchPath).toBe('public, pg_temp');
    expect(alters[2]!.resetsSearchPath).toBe(true);
    expect(alters[3]!.renameTo).toBe('b');
    expect(alters[4]).toMatchObject({ argTypes: null, securityDefiner: false });
  });

  test('an OWNER TO inside the arglist text is not read as the owner clause', () => {
    const { alters } = parseSqlFunctions(`ALTER FUNCTION a("OWNER TO x" text) SET search_path = '';`);
    expect(alters[0]!.ownerTo).toBeNull();
  });

  test('GRANT and REVOKE carry privileges, roles and a distinct offset each', () => {
    const { grants, revokes } = parseSqlFunctions(`
REVOKE ALL ON FUNCTION "public"."a"("uuid") FROM PUBLIC, "anon";
GRANT EXECUTE ON FUNCTION public.a(uuid) TO authenticated WITH GRANT OPTION;
REVOKE GRANT OPTION FOR EXECUTE ON FUNCTION a(uuid) FROM authenticated CASCADE;
GRANT EXECUTE ON FUNCTION a TO service_role;`);
    expect(revokes.map((r) => [r.privileges, r.roles])).toEqual([
      ['ALL', ['public', 'anon']],
      ['EXECUTE', ['authenticated']],
    ]);
    expect(grants.map((g) => [g.argTypes, g.roles])).toEqual([
      [['uuid'], ['authenticated']],
      [null, ['service_role']],
    ]);
    const offsets = [...grants, ...revokes].map((e) => e.index);
    expect(new Set(offsets).size).toBe(4);
  });

  test('a comma-list of function references is declined rather than half-read', () => {
    const { revokes } = parseSqlFunctions(`REVOKE EXECUTE ON FUNCTION a(uuid), b(uuid) FROM anon;`);
    expect(revokes).toEqual([]);
  });

  test('a table GRANT is not read as a function GRANT', () => {
    const { grants } = parseSqlFunctions(`GRANT SELECT ON TABLE public.t TO anon; GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO anon;`);
    expect(grants).toEqual([]);
  });
});

describe('countCreateFunctionStatements', () => {
  test('agrees with the parser on well-formed input', () => {
    const sql = `
CREATE FUNCTION a() RETURNS void LANGUAGE sql AS $$ $$;
CREATE OR REPLACE FUNCTION "public"."b"() RETURNS void LANGUAGE sql AS $_$ $_$;`;
    const parsed = parseSqlFunctions(sql);
    expect(countCreateFunctionStatements(parsed).map((c) => c.index)).toEqual(
      parsed.functions.map((f) => f.index),
    );
  });

  test('ignores a CREATE FUNCTION in a body, a string, a comment or an identifier', () => {
    const parsed = parseSqlFunctions(`
-- CREATE FUNCTION commented()
CREATE FUNCTION a() RETURNS void LANGUAGE plpgsql AS $$ BEGIN
  -- the CREATE FUNCTION in the next migration
  EXECUTE 'CREATE FUNCTION dyn() RETURNS void AS ''x''';
END $$;
COMMENT ON TABLE "CREATE FUNCTION log" IS 'CREATE FUNCTION history';`);
    expect(countCreateFunctionStatements(parsed)).toHaveLength(1);
  });

  test('counts a definition the parser cannot read', () => {
    const parsed = parseSqlFunctions(`CREATE FUNCTION broken(a int RETURNS void LANGUAGE sql AS $$ $$;`);
    expect(parsed.functions).toEqual([]);
    expect(countCreateFunctionStatements(parsed)).toHaveLength(1);
  });
});
