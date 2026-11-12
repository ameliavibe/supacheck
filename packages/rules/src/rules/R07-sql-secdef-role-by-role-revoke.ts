import type { Finding, Rule, ScannedFile } from '../lib/rule-types.js';
import { replaySecdefState } from '../lib/secdef-state.js';
import { isMigrationInScope } from '../lib/sql-utils.js';

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
export function createR07(options: R07Options = {}): Rule {
  const baseline = options.migrationsBaselineTimestamp;

  function scanAll(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];
    for (const fn of replaySecdefState(files).functions) {
      if (!fn.securityDefiner) continue;
      if (!fn.revoked.has('public')) continue; // R04a covers "no REVOKE at all".
      if (fn.revoked.has('anon') && fn.revoked.has('authenticated')) continue;
      if (!isMigrationInScope(fn.definedAt.file, baseline)) continue;
      findings.push({
        ruleId: 'R07',
        file: fn.definedAt.file,
        line: fn.definedAt.line,
        column: fn.definedAt.column,
        message: `SECURITY DEFINER function ${fn.name}() has REVOKE ... FROM PUBLIC but no role-by-role REVOKE for anon and authenticated. pg_dump will emit default-privilege GRANTs to anon and authenticated on the next squash, silently undoing the lockdown. Replace with REVOKE ... FROM PUBLIC, anon, authenticated (or add separate role-by-role REVOKE statements).`,
      });
    }
    return findings;
  }

  return {
    id: 'R07',
    slug: 'sql-secdef-role-by-role-revoke',
    name: 'Locked-down SECURITY DEFINER function with PUBLIC-only REVOKE',
    category: 'secdef-hygiene',
    severity: 'critical',
    filePatterns: ['**/migrations/**/*.sql', '**/supabase/migrations/**/*.sql'],
    squashClobberFamily: true,
    scan: (file) => scanAll([file]),
    scanAll,
  };
}

export const R07: Rule = createR07();
