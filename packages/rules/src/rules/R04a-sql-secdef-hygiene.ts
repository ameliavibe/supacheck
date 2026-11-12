import type { Finding, Rule, ScannedFile } from '../lib/rule-types.js';
import { isEmptySearchPath, replaySecdefState, type Anchor } from '../lib/secdef-state.js';
import { isMigrationInScope } from '../lib/sql-utils.js';

export interface R04aOptions {
  migrationsBaselineTimestamp?: string;
}

const REQUIRED_REVOKES = ['public', 'anon', 'authenticated'];

export function createR04a(options: R04aOptions = {}): Rule {
  const baseline = options.migrationsBaselineTimestamp;

  // Pre-baseline files still replay, so a later CREATE OR REPLACE inherits the
  // owner and REVOKEs they set. Only findings anchored after it are reported.
  function scanAll(files: ScannedFile[]): Finding[] {
    const { functions, unparsed } = replaySecdefState(files);
    const findings: Finding[] = [];
    const report = (at: Anchor, message: string): void => {
      if (!isMigrationInScope(at.file, baseline)) return;
      findings.push({ ruleId: 'R04a', file: at.file, line: at.line, column: at.column, message });
    };

    for (const at of unparsed) {
      report(
        at,
        'Could not parse this CREATE FUNCTION statement, so it was not checked for SECURITY DEFINER hygiene. Please report the statement shape at https://github.com/ameliavibe/supacheck/issues.',
      );
    }

    for (const fn of functions) {
      if (!fn.securityDefiner) continue;

      if (fn.searchPath === null) {
        report(
          fn.searchPathAt,
          `SECURITY DEFINER function ${fn.name}() missing SET search_path TO ... as attribute (must appear before AS $$). Body-level SET runs after the search_path is already used and is stripped by pg_dump during squash.`,
        );
      } else if (!isEmptySearchPath(fn.searchPath) && !/\bpg_temp\b/i.test(fn.searchPath)) {
        report(
          fn.searchPathAt,
          `SECURITY DEFINER function ${fn.name}() sets search_path without pg_temp (has: ${fn.searchPath}). Postgres searches the temp schema first unless pg_temp is listed, so a caller-created temp table can shadow an unqualified table in the body. List pg_temp last, or use SET search_path = '' with schema-qualified names.`,
        );
      }

      if (fn.owner !== 'postgres') {
        report(
          fn.definedAt,
          `SECURITY DEFINER function ${fn.name}() missing ALTER FUNCTION ... OWNER TO postgres. Without it, the function runs as the migration role rather than postgres.`,
        );
      }

      if (!REQUIRED_REVOKES.every((role) => fn.revoked.has(role))) {
        report(
          fn.definedAt,
          `SECURITY DEFINER function ${fn.name}() missing REVOKE EXECUTE ... FROM PUBLIC, anon, authenticated. Without all three roles named, pg_dump default privileges will re-grant EXECUTE during squash.`,
        );
      }
    }
    return findings;
  }

  return {
    id: 'R04a',
    slug: 'sql-secdef-hygiene',
    name: 'SECURITY DEFINER function without search_path / OWNER / REVOKE',
    category: 'secdef-hygiene',
    severity: 'high',
    filePatterns: ['**/migrations/**/*.sql', '**/supabase/migrations/**/*.sql'],
    squashClobberFamily: true,
    scan: (file) => scanAll([file]),
    scanAll,
  };
}

export const R04a: Rule = createR04a();
