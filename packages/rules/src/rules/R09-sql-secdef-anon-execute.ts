import type { Finding, Rule, ScannedFile } from '../lib/rule-types.js';
import { replaySecdefState } from '../lib/secdef-state.js';
import { isMigrationInScope } from '../lib/sql-utils.js';

export interface R09Options {
  migrationsBaselineTimestamp?: string;
  /** Function names that are meant to be callable without a session. */
  allowAnon?: string[];
}

/**
 * R09 flags a SECURITY DEFINER function that anon can still execute once every
 * migration has applied: an explicit GRANT to anon or PUBLIC, a schema-wide
 * GRANT ... ON ALL FUNCTIONS, or an ALTER DEFAULT PRIVILEGES grant in force
 * when the function was created, with no later REVOKE.
 *
 * It does not model Postgres' implicit EXECUTE for PUBLIC on a new function;
 * R04a covers that case by requiring the REVOKE to be written.
 */
export function createR09(options: R09Options = {}): Rule {
  const baseline = options.migrationsBaselineTimestamp;
  const allow = new Set((options.allowAnon ?? []).map((n) => n.toLowerCase()));

  function scanAll(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];
    for (const fn of replaySecdefState(files).functions) {
      if (!fn.securityDefiner || fn.isTrigger || !fn.anonExecute) continue;
      if (allow.has(fn.name.toLowerCase())) continue;
      if (!isMigrationInScope(fn.anonExecuteAt.file, baseline)) continue;
      findings.push({
        ruleId: 'R09',
        file: fn.anonExecuteAt.file,
        line: fn.anonExecuteAt.line,
        column: fn.anonExecuteAt.column,
        message: `SECURITY DEFINER function ${fn.schema}.${fn.name}() is executable by anon at the end of the migration history. It runs with its owner's privileges and bypasses RLS, so a caller with no session can invoke it. Add REVOKE EXECUTE ON FUNCTION ${fn.schema}.${fn.name}(${fn.argTypes.join(', ')}) FROM PUBLIC, anon; or list the function under allow_anon if anonymous access is intended.`,
      });
    }
    return findings;
  }

  return {
    id: 'R09',
    slug: 'sql-secdef-anon-execute',
    name: 'SECURITY DEFINER function executable by anon',
    category: 'secdef-hygiene',
    severity: 'high',
    filePatterns: ['**/migrations/**/*.sql', '**/supabase/migrations/**/*.sql'],
    squashClobberFamily: true,
    scan: (file) => scanAll([file]),
    scanAll,
  };
}

export const R09: Rule = createR09();
