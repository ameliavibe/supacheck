import type { Finding, Rule, ScannedFile } from '../lib/rule-types.js';
import {
  isMigrationInScope,
  lineAndColumn,
  stripSqlComments,
} from '../lib/sql-utils.js';

export interface R07Options {
  migrationsBaselineTimestamp?: string;
}

/**
 * R07 catches the specific squash-clobber failure mode: a SECURITY DEFINER
 * function written with REVOKE ... FROM PUBLIC but missing the role-by-role
 * REVOKE for anon and authenticated. pg_dump derives default-privilege GRANTs
 * to anon / authenticated when only PUBLIC is REVOKE'd, silently undoing the
 * lockdown during the next squash. The role-by-role form is preserved.
 *
 * R04a (SECDEF hygiene) catches the broader case of "no REVOKE at all". R07
 * is the subset where the developer signaled lockdown intent (a PUBLIC
 * REVOKE) but used the form that pg_dump will overwrite.
 */

const FN_DEF_RE =
  /CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(?:"?\w+"?\.)?"?(\w+)"?\s*\(([^)]*(?:\([^)]*\)[^)]*)*)\)[\s\S]*?\$\$[\s\S]*?\$\$\s*;/gi;

const REVOKE_FN_RE =
  /REVOKE\s+(?:GRANT\s+OPTION\s+FOR\s+)?(?:EXECUTE|ALL(?:\s+PRIVILEGES)?)\s+ON\s+FUNCTION\s+(?:"?\w+"?\.)?"?(\w+)"?\s*\([^)]*\)\s+FROM\s+([^;]+);/gi;

export function createR07(options: R07Options = {}): Rule {
  const baseline = options.migrationsBaselineTimestamp;
  return {
    id: 'R07',
    slug: 'sql-secdef-role-by-role-revoke',
    name: 'Locked-down SECURITY DEFINER function with PUBLIC-only REVOKE',
    category: 'secdef-hygiene',
    severity: 'critical',
    filePatterns: ['**/migrations/**/*.sql', '**/supabase/migrations/**/*.sql'],
    squashClobberFamily: true,

    scan(file: ScannedFile): Finding[] {
      if (!isMigrationInScope(file.path, baseline)) return [];

      const src = stripSqlComments(file.contents);

      // Aggregate REVOKE statements by function name.
      const revokesByFn = new Map<string, string[]>();
      REVOKE_FN_RE.lastIndex = 0;
      let r: RegExpExecArray | null;
      while ((r = REVOKE_FN_RE.exec(src)) !== null) {
        const name = r[1]!;
        const arr = revokesByFn.get(name) ?? [];
        arr.push(r[2]!);
        revokesByFn.set(name, arr);
      }

      const findings: Finding[] = [];
      FN_DEF_RE.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = FN_DEF_RE.exec(src)) !== null) {
        const fnDef = m[0];
        const fnName = m[1]!;
        if (!/SECURITY\s+DEFINER/i.test(fnDef)) continue;

        const targets = revokesByFn.get(fnName) ?? [];
        if (targets.length === 0) continue; // R04a covers "no REVOKE at all".

        const aggregate = targets.join(' ').toLowerCase();
        const hasPublic = /\bpublic\b/.test(aggregate);
        const hasAnon = /\banon\b/.test(aggregate);
        const hasAuth = /\bauthenticated\b/.test(aggregate);
        if (hasPublic && (!hasAnon || !hasAuth)) {
          const { line, column } = lineAndColumn(src, m.index);
          findings.push({
            ruleId: 'R07',
            file: file.path,
            line,
            column,
            message: `SECURITY DEFINER function ${fnName}() has REVOKE ... FROM PUBLIC but no role-by-role REVOKE for anon and authenticated. pg_dump will emit default-privilege GRANTs to anon and authenticated on the next squash, silently undoing the lockdown. Replace with REVOKE ... FROM PUBLIC, anon, authenticated (or add separate role-by-role REVOKE statements).`,
            range: [m.index, m.index + fnDef.length],
          });
        }
      }
      return findings;
    },
  };
}

export const R07: Rule = createR07();
