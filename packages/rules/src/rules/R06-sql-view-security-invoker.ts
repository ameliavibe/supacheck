import type { Finding, Rule, ScannedFile } from '../lib/rule-types.js';
import {
  isMigrationInScope,
  lineAndColumn,
  stripSqlComments,
} from '../lib/sql-utils.js';

export interface R06Options {
  migrationsBaselineTimestamp?: string;
}

/**
 * Standard (non-materialized) views only. Materialized views don't apply
 * RLS the same way and don't accept security_invoker.
 */
const CREATE_VIEW_RE =
  /CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\s+(?:"?(\w+)"?\.)?"?(\w+)"?(?:\s*\([^)]*\))?\s*(?:WITH\s*\(([^)]+)\))?\s+AS/gi;

const ALTER_VIEW_RE =
  /ALTER\s+VIEW\s+(?:"?(\w+)"?\.)?"?(\w+)"?\s+(SET|RESET)\s*\(([^)]+)\)/gi;

const DROP_VIEW_RE = /DROP\s+VIEW\s+(?:IF\s+EXISTS\s+)?(?:"?(\w+)"?\.)?"?(\w+)"?/gi;

function hasSecurityInvokerOn(optionsStr: string | undefined): boolean {
  if (!optionsStr) return false;
  return /"?security_invoker"?\s*=\s*'?(on|true)'?/i.test(optionsStr);
}

function hasSecurityInvokerOff(optionsStr: string | undefined): boolean {
  if (!optionsStr) return false;
  return /"?security_invoker"?\s*=\s*'?(off|false)'?/i.test(optionsStr);
}

function mentionsSecurityInvoker(optionsStr: string | undefined): boolean {
  if (!optionsStr) return false;
  return /security_invoker/i.test(optionsStr);
}

interface ViewEvent {
  at: number;
  kind: 'create' | 'alter' | 'drop';
  schema?: string | undefined;
  name: string;
  op?: 'SET' | 'RESET';
  opts?: string;
}

interface ViewState {
  lastFile: string;
  lastOffset: number;
  securityInvoker: boolean;
}

function key(schema: string | undefined, name: string): string {
  return `${schema || 'public'}.${name}`;
}

function collectEvents(cleaned: string): ViewEvent[] {
  const events: ViewEvent[] = [];
  for (const m of cleaned.matchAll(CREATE_VIEW_RE)) {
    events.push({
      at: m.index ?? 0,
      kind: 'create',
      schema: m[1],
      name: m[2]!,
      opts: m[3],
    });
  }
  for (const m of cleaned.matchAll(ALTER_VIEW_RE)) {
    events.push({
      at: m.index ?? 0,
      kind: 'alter',
      schema: m[1],
      name: m[2]!,
      op: m[3]!.toUpperCase() as 'SET' | 'RESET',
      opts: m[4],
    });
  }
  for (const m of cleaned.matchAll(DROP_VIEW_RE)) {
    events.push({ at: m.index ?? 0, kind: 'drop', schema: m[1], name: m[2]! });
  }
  events.sort((a, b) => a.at - b.at);
  return events;
}

export function createR06(options: R06Options = {}): Rule {
  const baseline = options.migrationsBaselineTimestamp;
  return {
    id: 'R06',
    slug: 'sql-view-security-invoker',
    name: 'View without security_invoker = on bypasses RLS',
    category: 'view-hygiene',
    severity: 'critical',
    filePatterns: ['**/migrations/**/*.sql', '**/supabase/migrations/**/*.sql'],
    squashClobberFamily: true,

    scan(): Finding[] {
      // R06 is cross-file; per-file scan is a no-op.
      return [];
    },

    scanAll(files: ScannedFile[]): Finding[] {
      // Only consider .sql migration files in scope; sort chronologically
      // by filename (timestamp prefix orders correctly).
      const sorted = files
        .filter((f) => isMigrationInScope(f.path, baseline))
        .sort((a, b) => a.path.localeCompare(b.path));

      const fileByPath = new Map(sorted.map((f) => [f.path, f]));
      const views = new Map<string, ViewState>();

      for (const file of sorted) {
        const stripped = stripSqlComments(file.contents);
        for (const e of collectEvents(stripped)) {
          const k = key(e.schema, e.name);
          if (e.kind === 'create') {
            views.set(k, {
              lastFile: file.path,
              lastOffset: e.at,
              securityInvoker: hasSecurityInvokerOn(e.opts),
            });
          } else if (e.kind === 'alter') {
            const prev = views.get(k);
            if (!prev) continue;
            if (e.op === 'RESET' && mentionsSecurityInvoker(e.opts)) {
              views.set(k, { ...prev, securityInvoker: false, lastFile: file.path, lastOffset: e.at });
            } else if (e.op === 'SET' && hasSecurityInvokerOn(e.opts)) {
              views.set(k, { ...prev, securityInvoker: true, lastFile: file.path, lastOffset: e.at });
            } else if (e.op === 'SET' && hasSecurityInvokerOff(e.opts)) {
              views.set(k, { ...prev, securityInvoker: false, lastFile: file.path, lastOffset: e.at });
            }
          } else if (e.kind === 'drop') {
            views.delete(k);
          }
        }
      }

      const findings: Finding[] = [];
      for (const [name, state] of views) {
        if (!name.startsWith('public.')) continue;
        if (state.securityInvoker) continue;
        const file = fileByPath.get(state.lastFile);
        const stripped = file ? stripSqlComments(file.contents) : '';
        const { line, column } = lineAndColumn(stripped, state.lastOffset);
        findings.push({
          ruleId: 'R06',
          file: state.lastFile,
          line,
          column,
          message: `View ${name} does not have security_invoker = on at the end of the migration history. Without it, the view runs with the owner's privileges and bypasses RLS on the underlying table. Add WITH (security_invoker = on) to the CREATE VIEW, or follow it with ALTER VIEW ${name} SET (security_invoker = on);.`,
        });
      }
      return findings;
    },
  };
}

export const R06: Rule = createR06();
