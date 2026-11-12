import type { ScannedFile } from './rule-types.js';
import {
  countCreateFunctionStatements,
  parseRoleList,
  parseSqlFunctions,
  signatureOf,
} from './sql-function-parse.js';
import { lineAndColumn, sortMigrations } from './sql-utils.js';

/**
 * Replays every migration in timestamp order and returns the state each
 * function ends up in. The secdef rules assert properties of that final state
 * instead of reading one file at a time, so a correction in a later migration
 * clears the finding and a regression in a later migration raises one.
 */

export interface Anchor {
  file: string;
  line: number;
  column: number;
}

export interface FunctionState {
  schema: string;
  name: string;
  argTypes: string[];
  securityDefiner: boolean;
  /** Trigger functions are not callable through the API. */
  isTrigger: boolean;
  /** The last CREATE for this identity. */
  definedAt: Anchor;
  /** Attribute-level search_path list as written, or null when unset. */
  searchPath: string | null;
  searchPathAt: Anchor;
  /** Role named by the last `OWNER TO`, or null when none was written. */
  owner: string | null;
  /** Roles a REVOKE of EXECUTE has named since this identity was created. */
  revoked: Set<string>;
  /** anon holds EXECUTE through an explicit grant or a default-privilege grant. */
  anonExecute: boolean;
  anonExecuteAt: Anchor;
}

export interface SecdefReplay {
  functions: FunctionState[];
  /** CREATE FUNCTION statements the parser could not read. */
  unparsed: Anchor[];
}

interface MutableState extends FunctionState {
  anonDirect: boolean;
  anonViaPublic: boolean;
}

const SEARCH_PATH_LIST = String.raw`((?:'[^']*'|"[^"]*"|[\w$]+)(?:\s*,\s*(?:'[^']*'|"[^"]*"|[\w$]+))*)`;
const SEARCH_PATH_ATTR_RE = new RegExp(
  String.raw`\bSET\s+"?search_path"?\s*(?:TO|=)\s*${SEARCH_PATH_LIST}`,
  'i',
);
const SEARCH_PATH_LIST_RE = new RegExp(`^${SEARCH_PATH_LIST}`);

const TRAILER = String.raw`(?:\s+(?:WITH\s+GRANT\s+OPTION|CASCADE|RESTRICT))?\s*;?\s*$`;
const EXEC_PRIV = String.raw`(?:ALL(?:\s+PRIVILEGES)?|EXECUTE)`;

// GRANT|REVOKE ... ON ALL FUNCTIONS IN SCHEMA <schemas> TO|FROM <roles>
const BULK_RE = new RegExp(
  String.raw`^\s*(GRANT|REVOKE)\s+(?:GRANT\s+OPTION\s+FOR\s+)?${EXEC_PRIV}\s+ON\s+ALL\s+(?:FUNCTIONS|ROUTINES)\s+IN\s+SCHEMA\s+(.+?)\s+(?:TO|FROM)\s+(.+?)${TRAILER}`,
  'is',
);

// ALTER DEFAULT PRIVILEGES [FOR ROLE r] [IN SCHEMA s] GRANT|REVOKE ... ON FUNCTIONS TO|FROM <roles>
const DEFAULT_PRIVS_RE = new RegExp(
  String.raw`^\s*ALTER\s+DEFAULT\s+PRIVILEGES\b(.*?)\b(GRANT|REVOKE)\s+(?:GRANT\s+OPTION\s+FOR\s+)?${EXEC_PRIV}\s+ON\s+(?:FUNCTIONS|ROUTINES)\s+(?:TO|FROM)\s+(.+?)${TRAILER}`,
  'is',
);

function carriesExecute(privileges: string): boolean {
  return /^(?:ALL(?: PRIVILEGES)?|EXECUTE)$/.test(privileges);
}

function searchPathList(raw: string | null): string | null {
  if (raw === null) return null;
  const m = SEARCH_PATH_LIST_RE.exec(raw.trim());
  return m ? m[1]! : null;
}

/** `''` is the form Supabase recommends: nothing resolves unqualified. */
export function isEmptySearchPath(list: string): boolean {
  return list === "''" || list === '""';
}

const cache = new WeakMap<ScannedFile[], SecdefReplay>();

export function replaySecdefState(files: ScannedFile[]): SecdefReplay {
  const cached = cache.get(files);
  if (cached) return cached;

  const states = new Map<string, MutableState>();
  const unparsed: Anchor[] = [];
  // `<schema or *>:<role>` for each default-privilege EXECUTE grant in force.
  const defaultGrants = new Set<string>();

  const keyOf = (schema: string, name: string, argTypes: string[]): string =>
    `${schema}.${signatureOf(name, argTypes)}`;

  // Exact identity first. A reference that qualifies a type the definition
  // left bare (or the reverse) falls back to comparing unqualified type names.
  const unqualified = (types: string[]): string => types.map((t) => t.replace(/^.*\./, '')).join(',');
  const resolve = (
    schema: string | null,
    name: string,
    argTypes: string[] | null,
  ): [string, MutableState][] => {
    const s = schema ?? 'public';
    if (argTypes) {
      const key = keyOf(s, name, argTypes);
      const exact = states.get(key);
      if (exact) return [[key, exact]];
    }
    return [...states].filter(
      ([, st]) =>
        st.schema === s &&
        st.name === name &&
        (argTypes === null || unqualified(st.argTypes) === unqualified(argTypes)),
    );
  };

  for (const file of sortMigrations(files)) {
    const parsed = parseSqlFunctions(file.contents);
    const anchor = (offset: number): Anchor => ({
      file: file.path,
      ...lineAndColumn(parsed.clean, offset),
    });

    const parsedOffsets = new Set(parsed.functions.map((f) => f.index));
    for (const naive of countCreateFunctionStatements(parsed)) {
      if (!parsedOffsets.has(naive.index)) unparsed.push(anchor(naive.index));
    }

    const setAnon = (st: MutableState, at: Anchor, direct: boolean | null, viaPublic: boolean | null): void => {
      const before = st.anonDirect || st.anonViaPublic;
      if (direct !== null) st.anonDirect = direct;
      if (viaPublic !== null) st.anonViaPublic = viaPublic;
      st.anonExecute = st.anonDirect || st.anonViaPublic;
      if (st.anonExecute && (!before || direct === true || viaPublic === true)) st.anonExecuteAt = at;
    };

    const applyAcl = (st: MutableState, at: Anchor, grant: boolean, roles: string[]): void => {
      if (!grant) for (const r of roles) st.revoked.add(r);
      setAnon(
        st,
        at,
        roles.includes('anon') ? grant : null,
        roles.includes('public') ? grant : null,
      );
    };

    const events: { index: number; apply: () => void }[] = [];

    for (const fn of parsed.functions) {
      events.push({
        index: fn.index,
        apply: () => {
          const schema = fn.schema ?? 'public';
          const key = keyOf(schema, fn.name, fn.argTypes);
          // CREATE OR REPLACE keeps the owner and ACL of an existing identity.
          const prior = fn.isReplace ? states.get(key) : undefined;
          const at = anchor(fn.index);
          const attr = SEARCH_PATH_ATTR_RE.exec(fn.preBodyText);
          const anonDirect =
            prior?.anonDirect ?? (defaultGrants.has('*:anon') || defaultGrants.has(`${schema}:anon`));
          const anonViaPublic =
            prior?.anonViaPublic ??
            (defaultGrants.has('*:public') || defaultGrants.has(`${schema}:public`));
          states.set(key, {
            schema,
            name: fn.name,
            argTypes: fn.argTypes,
            securityDefiner: /\bSECURITY\s+DEFINER\b/i.test(fn.preBodyText),
            isTrigger: /\bRETURNS\s+(?:"?pg_catalog"?\s*\.\s*)?"?(?:event_)?trigger"?(?![\w"])/i.test(
              fn.preBodyText,
            ),
            definedAt: at,
            searchPath: attr ? attr[1]! : null,
            searchPathAt: at,
            owner: prior?.owner ?? null,
            revoked: prior?.revoked ?? new Set(),
            anonDirect,
            anonViaPublic,
            anonExecute: anonDirect || anonViaPublic,
            anonExecuteAt: prior?.anonExecuteAt ?? at,
          });
        },
      });
    }

    for (const drop of parsed.drops) {
      events.push({
        index: drop.index,
        apply: () => {
          for (const [key] of resolve(drop.schema, drop.name, drop.argTypes)) states.delete(key);
        },
      });
    }

    for (const alter of parsed.alters) {
      events.push({
        index: alter.index,
        apply: () => {
          const at = anchor(alter.index);
          for (const [key, st] of resolve(alter.schema, alter.name, alter.argTypes)) {
            if (alter.ownerTo) st.owner = alter.ownerTo;
            if (alter.securityDefiner !== null) st.securityDefiner = alter.securityDefiner;
            if (alter.resetsSearchPath) {
              st.searchPath = null;
              st.searchPathAt = at;
            } else if (alter.searchPath !== null) {
              st.searchPath = searchPathList(alter.searchPath);
              st.searchPathAt = at;
            }
            if (alter.renameTo) {
              states.delete(key);
              st.name = alter.renameTo;
              states.set(keyOf(st.schema, st.name, st.argTypes), st);
            }
          }
        },
      });
    }

    for (const [list, grant] of [
      [parsed.grants, true],
      [parsed.revokes, false],
    ] as const) {
      for (const acl of list) {
        if (!carriesExecute(acl.privileges)) continue;
        events.push({
          index: acl.index,
          apply: () => {
            const at = anchor(acl.index);
            for (const [, st] of resolve(acl.schema, acl.name, acl.argTypes)) {
              applyAcl(st, at, grant, acl.roles);
            }
          },
        });
      }
    }

    for (const stmt of parsed.statements) {
      const head = stmt.start + (stmt.text.length - stmt.text.trimStart().length);

      const bulk = BULK_RE.exec(stmt.text);
      if (bulk) {
        const grant = bulk[1]!.toUpperCase() === 'GRANT';
        const schemas = new Set(parseRoleList(bulk[2]!));
        const roles = parseRoleList(bulk[3]!);
        events.push({
          index: head,
          apply: () => {
            const at = anchor(head);
            for (const st of states.values()) {
              if (schemas.has(st.schema)) applyAcl(st, at, grant, roles);
            }
          },
        });
        continue;
      }

      const defaults = DEFAULT_PRIVS_RE.exec(stmt.text);
      if (defaults) {
        const inSchema = /\bIN\s+SCHEMA\s+(.+?)\s*$/is.exec(defaults[1]!);
        const schemas = inSchema ? parseRoleList(inSchema[1]!) : ['*'];
        const grant = defaults[2]!.toUpperCase() === 'GRANT';
        const roles = parseRoleList(defaults[3]!);
        events.push({
          index: head,
          apply: () => {
            for (const schema of schemas) {
              for (const role of roles) {
                if (grant) defaultGrants.add(`${schema}:${role}`);
                else defaultGrants.delete(`${schema}:${role}`);
              }
            }
          },
        });
      }
    }

    events.sort((a, b) => a.index - b.index);
    for (const e of events) e.apply();
  }

  const replay: SecdefReplay = { functions: [...states.values()], unparsed };
  cache.set(files, replay);
  return replay;
}
