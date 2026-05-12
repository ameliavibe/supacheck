import type { Finding, Rule, ScannedFile } from '../lib/rule-types.js';
import {
  isMigrationInScope,
  lineAndColumn,
  stripSqlComments,
} from '../lib/sql-utils.js';

export interface R04bOptions {
  migrationsBaselineTimestamp?: string;
}

const POLICY_BLOCK_RE = /CREATE\s+POLICY\s+"([^"]+)"[\s\S]*?;/gi;
const SERVICE_ROLE_NAME_RE = /service[\s_-]*role/i;
const SERVICE_ACCESS_NAME_RE = /\bservice\b.*\baccess\b/i;
const TO_SERVICE_ROLE_RE = /\bTO\s+service_role\b/i;

export function createR04b(options: R04bOptions = {}): Rule {
  const baseline = options.migrationsBaselineTimestamp;
  return {
    id: 'R04b',
    slug: 'sql-policy-service-role-to',
    name: 'Service-role-targeted policy without explicit TO service_role',
    category: 'rls-correctness',
    severity: 'high',
    filePatterns: ['**/migrations/**/*.sql', '**/supabase/migrations/**/*.sql'],
    squashClobberFamily: true,

    scan(file: ScannedFile): Finding[] {
      if (!isMigrationInScope(file.path, baseline)) return [];

      const src = stripSqlComments(file.contents);
      const findings: Finding[] = [];

      POLICY_BLOCK_RE.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = POLICY_BLOCK_RE.exec(src)) !== null) {
        const policyName = m[1]!;
        const block = m[0];
        const intendedForServiceRole =
          SERVICE_ROLE_NAME_RE.test(policyName) ||
          SERVICE_ACCESS_NAME_RE.test(policyName);
        if (!intendedForServiceRole) continue;
        if (TO_SERVICE_ROLE_RE.test(block)) continue;

        const { line, column } = lineAndColumn(src, m.index);
        findings.push({
          ruleId: 'R04b',
          file: file.path,
          line,
          column,
          message: `Policy "${policyName}" appears to target the service role but does not declare TO service_role. Without the TO clause PostgREST applies the policy to PUBLIC and the policy masks RLS entirely.`,
          range: [m.index, m.index + block.length],
        });
      }
      return findings;
    },
  };
}

export const R04b: Rule = createR04b();
