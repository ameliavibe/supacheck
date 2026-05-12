import type { Finding, Rule, ScannedFile } from '../lib/rule-types.js';
import {
  isMigrationInScope,
  lineAndColumn,
  stripSqlComments,
} from '../lib/sql-utils.js';

export interface R04aOptions {
  migrationsBaselineTimestamp?: string;
}

// Match a function definition through the closing `$$ ... $$;`. Assumes
// the body is delimited by bare `$$`. Tagged dollar-quotes (e.g. `$body$`)
// are not handled.
const FN_DEF_RE =
  /CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(?:"?\w+"?\.)?"?(\w+)"?\s*\(([^)]*(?:\([^)]*\)[^)]*)*)\)[\s\S]*?\$\$[\s\S]*?\$\$\s*;/gi;

const REVOKE_FN_RE =
  /REVOKE\s+(?:GRANT\s+OPTION\s+FOR\s+)?EXECUTE\s+ON\s+FUNCTION\s+(?:"?\w+"?\.)?"?(\w+)"?\s*\([^)]*\)\s+FROM\s+([^;]+);/gi;

const ALTER_OWNER_RE =
  /ALTER\s+FUNCTION\s+(?:"?\w+"?\.)?"?(\w+)"?\s*\([^)]*\)\s+OWNER\s+TO\s+postgres\s*;/gi;

function collectByName<T>(
  src: string,
  re: RegExp,
  pick: (m: RegExpExecArray) => T,
): Map<string, T[]> {
  const out = new Map<string, T[]>();
  re.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src)) !== null) {
    const name = m[1]!;
    const arr = out.get(name) ?? [];
    arr.push(pick(m));
    out.set(name, arr);
  }
  return out;
}

export function createR04a(options: R04aOptions = {}): Rule {
  const baseline = options.migrationsBaselineTimestamp;
  return {
    id: 'R04a',
    slug: 'sql-secdef-hygiene',
    name: 'SECURITY DEFINER function without search_path / OWNER / REVOKE',
    category: 'secdef-hygiene',
    severity: 'high',
    filePatterns: ['**/migrations/**/*.sql', '**/supabase/migrations/**/*.sql'],
    squashClobberFamily: true,

    scan(file: ScannedFile): Finding[] {
      if (!isMigrationInScope(file.path, baseline)) return [];

      const src = stripSqlComments(file.contents);
      const owners = collectByName(src, ALTER_OWNER_RE, (m) => m[1]!);
      const revokes = collectByName(src, REVOKE_FN_RE, (m) => m[2]!);

      const findings: Finding[] = [];
      FN_DEF_RE.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = FN_DEF_RE.exec(src)) !== null) {
        const fnDef = m[0];
        const fnName = m[1]!;
        if (!/SECURITY\s+DEFINER/i.test(fnDef)) continue;
        const fnStart = m.index;
        const { line, column } = lineAndColumn(src, fnStart);

        const beforeBody = fnDef.split('$$')[0]!;
        const hasSearchPathAttr = /SET\s+search_path\s+TO\s+/i.test(beforeBody);
        if (!hasSearchPathAttr) {
          findings.push({
            ruleId: 'R04a',
            file: file.path,
            line,
            column,
            message: `SECURITY DEFINER function ${fnName}() missing SET search_path TO ... as attribute (must appear before AS $$). Body-level SET runs after the search_path is already used and is stripped by pg_dump during squash.`,
            range: [fnStart, fnStart + fnDef.length],
          });
        }

        if (!owners.has(fnName)) {
          findings.push({
            ruleId: 'R04a',
            file: file.path,
            line,
            column,
            message: `SECURITY DEFINER function ${fnName}() missing ALTER FUNCTION ... OWNER TO postgres. Without it, the function runs as the migration role rather than postgres.`,
            range: [fnStart, fnStart + fnDef.length],
          });
        }

        const revokeTargets = revokes.get(fnName) ?? [];
        const aggregate = revokeTargets.join(' ').toLowerCase();
        const hasFullRevoke =
          /\bpublic\b/.test(aggregate) &&
          /\banon\b/.test(aggregate) &&
          /\bauthenticated\b/.test(aggregate);
        if (!hasFullRevoke) {
          findings.push({
            ruleId: 'R04a',
            file: file.path,
            line,
            column,
            message: `SECURITY DEFINER function ${fnName}() missing REVOKE EXECUTE ... FROM PUBLIC, anon, authenticated. Without all three roles named, pg_dump default privileges will re-grant EXECUTE during squash.`,
            range: [fnStart, fnStart + fnDef.length],
          });
        }
      }
      return findings;
    },
  };
}

export const R04a: Rule = createR04a();
