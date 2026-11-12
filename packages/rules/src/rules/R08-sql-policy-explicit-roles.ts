import type { Finding, Rule, ScannedFile } from '../lib/rule-types.js';
import { lexSql, parseObjectRef, parseRoleList, splitTopLevel } from '../lib/sql-function-parse.js';
import { isMigrationInScope, lineAndColumn, sortMigrations } from '../lib/sql-utils.js';

export interface R08Options {
  migrationsBaselineTimestamp?: string;
  /** Schemas whose policies must name their roles. Defaults to `public`. */
  schemas?: string[];
}

/**
 * R08 flags an RLS policy that applies to every role once every migration has
 * applied: one created without a TO clause, or with TO public. Both include
 * anon, so the policy's predicate is the only thing keeping anonymous callers
 * out. The history is replayed, so a later ALTER POLICY ... TO authenticated
 * clears the finding and a later ALTER POLICY ... TO public raises one.
 *
 * Policies created by dynamic SQL inside a DO block are not seen.
 */

const NAME = String.raw`("(?:[^"]|"")*"|[\w$]+)`;
const REF = String.raw`((?:"(?:[^"]|"")*"|[\w$]+)(?:\s*\.\s*(?:"(?:[^"]|"")*"|[\w$]+))*)`;
const ROLE_LIST = String.raw`((?:"[^"]+"|[\w$]+)(?:\s*,\s*(?:"[^"]+"|[\w$]+))*)`;

const CREATE_POLICY_RE = new RegExp(
  String.raw`^\s*CREATE\s+POLICY\s+${NAME}\s+ON\s+(?:ONLY\s+)?${REF}(?:\s+AS\s+(?:PERMISSIVE|RESTRICTIVE))?(?:\s+FOR\s+(?:ALL|SELECT|INSERT|UPDATE|DELETE))?(?:\s+TO\s+${ROLE_LIST})?`,
  'i',
);
// The TO clause sits right after the table name, so a `to` inside a predicate
// can never be read as one.
const ALTER_POLICY_RE = new RegExp(
  String.raw`^\s*ALTER\s+POLICY\s+${NAME}\s+ON\s+(?:ONLY\s+)?${REF}(?:\s+RENAME\s+TO\s+${NAME}|\s+TO\s+${ROLE_LIST})?`,
  'i',
);
const DROP_POLICY_RE = new RegExp(
  String.raw`^\s*DROP\s+POLICY\s+(?:IF\s+EXISTS\s+)?${NAME}\s+ON\s+(?:ONLY\s+)?${REF}`,
  'i',
);
const DROP_TABLE_RE = /^\s*DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(.+?)(?:\s+(?:CASCADE|RESTRICT))?\s*;?\s*$/is;
const RENAME_TABLE_RE = new RegExp(
  String.raw`^\s*ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?${REF}\s+RENAME\s+TO\s+${NAME}`,
  'i',
);

export interface PolicyState {
  name: string;
  schema: string;
  table: string;
  /** undefined when the declaration had no TO clause. */
  roles: string[] | undefined;
  file: string;
  line: number;
  column: number;
}

function identifier(raw: string): string {
  return parseObjectRef(raw).name;
}

function tableOf(raw: string): { schema: string; table: string } {
  const ref = parseObjectRef(raw);
  return { schema: ref.schema ?? 'public', table: ref.name };
}

function appliesToEveryRole(roles: string[] | undefined): boolean {
  return roles === undefined || roles.includes('public');
}

/** Every policy left standing once the migrations have applied in order. */
export function replayPolicies(files: ScannedFile[]): PolicyState[] {
  const policies = new Map<string, PolicyState>();
  const keyOf = (schema: string, table: string, name: string): string =>
    `${schema}.${table}::${name}`;
  const onTable = (schema: string, table: string): [string, PolicyState][] =>
    [...policies].filter(([, p]) => p.schema === schema && p.table === table);

  for (const file of sortMigrations(files)) {
    const { clean, statements } = lexSql(file.contents);

    for (const stmt of statements) {
      const head = stmt.start + (stmt.text.length - stmt.text.trimStart().length);
      const at = (): { file: string; line: number; column: number } => ({
        file: file.path,
        ...lineAndColumn(clean, head),
      });

      const create = CREATE_POLICY_RE.exec(stmt.text);
      if (create) {
        const name = identifier(create[1]!);
        const { schema, table } = tableOf(create[2]!);
        policies.set(keyOf(schema, table, name), {
          name,
          schema,
          table,
          roles: create[3] ? parseRoleList(create[3]) : undefined,
          ...at(),
        });
        continue;
      }

      const alter = ALTER_POLICY_RE.exec(stmt.text);
      if (alter) {
        const { schema, table } = tableOf(alter[2]!);
        const key = keyOf(schema, table, identifier(alter[1]!));
        const policy = policies.get(key);
        if (!policy) continue;
        if (alter[3]) {
          policies.delete(key);
          policy.name = identifier(alter[3]);
          policies.set(keyOf(schema, table, policy.name), policy);
        } else if (alter[4]) {
          // ALTER POLICY ... TO replaces the role list outright.
          Object.assign(policy, { roles: parseRoleList(alter[4]) }, at());
        }
        continue;
      }

      const drop = DROP_POLICY_RE.exec(stmt.text);
      if (drop) {
        const { schema, table } = tableOf(drop[2]!);
        policies.delete(keyOf(schema, table, identifier(drop[1]!)));
        continue;
      }

      const dropTable = DROP_TABLE_RE.exec(stmt.text);
      if (dropTable) {
        for (const raw of splitTopLevel(dropTable[1]!)) {
          const { schema, table } = tableOf(raw);
          for (const [key] of onTable(schema, table)) policies.delete(key);
        }
        continue;
      }

      const rename = RENAME_TABLE_RE.exec(stmt.text);
      if (rename) {
        // Policies travel with the relation.
        const { schema, table } = tableOf(rename[1]!);
        const newTable = identifier(rename[2]!);
        for (const [key, policy] of onTable(schema, table)) {
          policies.delete(key);
          policy.table = newTable;
          policies.set(keyOf(schema, newTable, policy.name), policy);
        }
      }
    }
  }

  return [...policies.values()];
}

export function createR08(options: R08Options = {}): Rule {
  const baseline = options.migrationsBaselineTimestamp;
  const schemas = new Set((options.schemas ?? ['public']).map((s) => s.toLowerCase()));

  function scanAll(files: ScannedFile[]): Finding[] {
    const policies = replayPolicies(files);
    const findings: Finding[] = [];
    for (const p of policies) {
      if (!schemas.has(p.schema)) continue;
      if (!appliesToEveryRole(p.roles)) continue;
      if (!isMigrationInScope(p.file, baseline)) continue;
      const how = p.roles === undefined ? 'no TO clause' : 'TO public';
      findings.push({
        ruleId: 'R08',
        file: p.file,
        line: p.line,
        column: p.column,
        message: `Policy "${p.name}" on ${p.schema}.${p.table} applies to every role, anon included (${how}). Name the roles it is for: TO authenticated for signed-in users, TO service_role for server paths, TO anon only for a deliberately public surface. Postgres stores TO public the same as an omitted clause.`,
      });
    }
    return findings;
  }

  return {
    id: 'R08',
    slug: 'sql-policy-explicit-roles',
    name: 'RLS policy without an explicit role list',
    category: 'rls-correctness',
    severity: 'high',
    filePatterns: ['**/migrations/**/*.sql', '**/supabase/migrations/**/*.sql'],
    scan: (file) => scanAll([file]),
    scanAll,
  };
}

export const R08: Rule = createR08();
