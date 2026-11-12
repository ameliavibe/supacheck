/**
 * One lexing pass over a migration's SQL, shared by every rule that reasons
 * about functions or policies.
 *
 * Not a SQL parser. It lexes far enough to know what is inside a string, a
 * quoted identifier, a comment or a dollar-quoted body, splits on the
 * semicolons that remain, and recognizes function DDL plus GRANT / REVOKE.
 * `countCreateFunctionStatements` is the counterweight: a rule compares it to
 * what was parsed, so a form this module cannot read is reported, not skipped.
 */

export interface Span {
  start: number;
  end: number;
}

export interface DollarSpan extends Span {
  tag: string;
}

export interface SqlStatement extends Span {
  /** Statement text with comments blanked, offsets unchanged. */
  text: string;
}

export interface LexedSql {
  /** The input with comments replaced by spaces. Offsets match the original. */
  clean: string;
  statements: SqlStatement[];
  dollarSpans: DollarSpan[];
  stringSpans: Span[];
  identSpans: Span[];
}

export interface ParsedFunction {
  name: string;
  /** null when the statement wrote a bare name. */
  schema: string | null;
  /** Normalized IN / INOUT / VARIADIC argument types: the Postgres identity. */
  argTypes: string[];
  isReplace: boolean;
  /** Attribute span between the argument list and the body. Never the body. */
  preBodyText: string;
  hasBody: boolean;
  index: number;
  line: number;
}

export interface ParsedDrop {
  name: string;
  schema: string | null;
  /** null means the arglist was omitted: every identity with this name. */
  argTypes: string[] | null;
  index: number;
  line: number;
}

export interface ParsedAlter {
  name: string;
  schema: string | null;
  /** null means the arglist was omitted: every identity with this name. */
  argTypes: string[] | null;
  renameTo: string | null;
  ownerTo: string | null;
  /** Raw value of `SET search_path TO|= ...`, or null when absent. */
  searchPath: string | null;
  resetsSearchPath: boolean;
  /** true / false for `SECURITY DEFINER` / `SECURITY INVOKER`, else null. */
  securityDefiner: boolean | null;
  index: number;
  line: number;
}

export interface ParsedAcl {
  name: string;
  schema: string | null;
  /** null means the arglist was omitted: every identity with this name. */
  argTypes: string[] | null;
  /** Upper-cased privilege list, e.g. `EXECUTE` or `ALL PRIVILEGES`. */
  privileges: string;
  /** Lower-cased, unquoted role names. */
  roles: string[];
  index: number;
  line: number;
}

export interface ParsedSql extends LexedSql {
  functions: ParsedFunction[];
  drops: ParsedDrop[];
  alters: ParsedAlter[];
  grants: ParsedAcl[];
  revokes: ParsedAcl[];
}

/** Type names that can start a multi-word type (`timestamp with time zone`). */
const MULTIWORD_TYPE_STARTERS = new Set([
  'timestamp',
  'time',
  'double',
  'character',
  'bit',
  'interval',
  'national',
]);

/**
 * Spellings of the same type. pg_dump writes `timestamp with time zone` where
 * a hand-written migration replacing that function writes `timestamptz`.
 */
const TYPE_ALIASES = new Map([
  ['timestamptz', 'timestamp with time zone'],
  ['timestamp without time zone', 'timestamp'],
  ['timetz', 'time with time zone'],
  ['time without time zone', 'time'],
  ['varchar', 'character varying'],
  ['char', 'character'],
  ['int', 'integer'],
  ['int4', 'integer'],
  ['int2', 'smallint'],
  ['int8', 'bigint'],
  ['bool', 'boolean'],
  ['float4', 'real'],
  ['float8', 'double precision'],
  ['decimal', 'numeric'],
]);

const DOLLAR_TAG_RE = /\$(?:[A-Za-z_]\w*)?\$/y;

/** `$$` or `$tag$` starting at `i`, or null when this `$` is e.g. `$1`. */
function matchDollarTag(sql: string, i: number): string | null {
  DOLLAR_TAG_RE.lastIndex = i;
  const m = DOLLAR_TAG_RE.exec(sql);
  return m ? m[0] : null;
}

/** End offset (exclusive) of the quoted run opening at `i`. A doubled quote escapes itself. */
function skipQuoted(text: string, i: number, limit = text.length): number {
  const quote = text[i];
  let k = i + 1;
  while (k < limit) {
    if (text[k] === quote) {
      if (text[k + 1] === quote) k += 2;
      else return k + 1;
    } else k++;
  }
  return k;
}

export function lexSql(sql: string): LexedSql {
  // UTF-16 units, not code points: every offset here indexes the string.
  const out = sql.split('');
  const bounds: Span[] = [];
  const dollarSpans: DollarSpan[] = [];
  const stringSpans: Span[] = [];
  const identSpans: Span[] = [];
  let stmtStart = 0;
  let i = 0;

  const blank = (from: number, to: number): void => {
    for (let k = from; k < to && k < out.length; k++) {
      if (out[k] !== '\n') out[k] = ' ';
    }
  };

  while (i < sql.length) {
    const ch = sql[i];
    const next = sql[i + 1];

    if (ch === '-' && next === '-') {
      const nl = sql.indexOf('\n', i);
      const end = nl === -1 ? sql.length : nl;
      blank(i, end);
      i = end;
      continue;
    }

    if (ch === '/' && next === '*') {
      // Postgres block comments nest.
      let depth = 1;
      let k = i + 2;
      while (k < sql.length && depth > 0) {
        if (sql[k] === '/' && sql[k + 1] === '*') {
          depth++;
          k += 2;
        } else if (sql[k] === '*' && sql[k + 1] === '/') {
          depth--;
          k += 2;
        } else k++;
      }
      blank(i, k);
      i = k;
      continue;
    }

    if (ch === "'" || ch === '"') {
      const end = skipQuoted(sql, i);
      (ch === "'" ? stringSpans : identSpans).push({ start: i, end });
      i = end;
      continue;
    }

    if (ch === '$') {
      const tag = matchDollarTag(sql, i);
      if (tag !== null) {
        const close = sql.indexOf(tag, i + tag.length);
        const end = close === -1 ? sql.length : close + tag.length;
        dollarSpans.push({ start: i, end, tag });
        i = end;
        continue;
      }
    }

    if (ch === ';') {
      if (sql.slice(stmtStart, i + 1).trim()) bounds.push({ start: stmtStart, end: i + 1 });
      i++;
      stmtStart = i;
      continue;
    }

    i++;
  }

  if (sql.slice(stmtStart).trim()) bounds.push({ start: stmtStart, end: sql.length });

  const clean = out.join('');
  return {
    clean,
    // Sliced from the comment-blanked copy so a commented-out keyword is never seen.
    statements: bounds
      .map((b) => ({ ...b, text: clean.slice(b.start, b.end) }))
      .filter((s) => s.text.trim().length > 0),
    dollarSpans,
    stringSpans,
    identSpans,
  };
}

/** Split on `sep` at nesting depth 0, respecting quotes and brackets. */
export function splitTopLevel(text: string, sep = ','): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === "'" || ch === '"') {
      i = skipQuoted(text, i);
      continue;
    }
    if (ch === '(' || ch === '[') depth++;
    else if (ch === ')' || ch === ']') depth--;
    else if (ch === sep && depth === 0) {
      parts.push(text.slice(start, i));
      start = i + 1;
    }
    i++;
  }
  parts.push(text.slice(start));
  return parts.map((p) => p.trim()).filter((p) => p.length > 0);
}

/** Index of the `)` matching the `(` at `open`, or -1. Quote-aware. */
function matchParen(text: string, open: number): number {
  if (open < 0) return -1;
  let depth = 0;
  let i = open;
  while (i < text.length) {
    const ch = text[i];
    if (ch === "'" || ch === '"') {
      i = skipQuoted(text, i);
      continue;
    }
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return i;
    }
    i++;
  }
  return -1;
}

function isTopLevel(text: string, index: number): boolean {
  let depth = 0;
  let i = 0;
  while (i < index) {
    const ch = text[i];
    if (ch === "'" || ch === '"') {
      i = skipQuoted(text, i, index);
      continue;
    }
    if (ch === '(' || ch === '[') depth++;
    else if (ch === ')' || ch === ']') depth--;
    i++;
  }
  return depth === 0;
}

// Postgres' rule, so parsed names match pg_catalog: an unquoted part folds to
// lowercase, a quoted one keeps its case, and both truncate to 63 bytes.
const MAX_IDENTIFIER_BYTES = 63;

function utf8Bytes(codePoint: number): number {
  return codePoint < 0x80 ? 1 : codePoint < 0x800 ? 2 : codePoint < 0x10000 ? 3 : 4;
}

function truncateIdentifier(name: string): string {
  let bytes = 0;
  let out = '';
  for (const ch of name) {
    bytes += utf8Bytes(ch.codePointAt(0)!);
    if (bytes > MAX_IDENTIFIER_BYTES) break;
    out += ch;
  }
  return out;
}

/** Each dot-separated part, unquoted and normalized the way Postgres stores it. */
function refParts(raw: string): string[] {
  // Split on dots outside quotes: `"a.b"` is one identifier.
  return [...raw.matchAll(/(?:"(?:[^"]|"")*"|[^."])+/g)].map(([match]) => {
    const part = match.trim();
    const quoted = /^"(.*)"$/s.exec(part);
    return truncateIdentifier(quoted ? quoted[1]!.replace(/""/g, '"') : part.toLowerCase());
  });
}

/** `{schema, name}` for a possibly-quoted, possibly-qualified reference. */
export function parseObjectRef(ref: string): { schema: string | null; name: string } {
  const parts = refParts(ref);
  return {
    schema: parts.length > 1 ? parts[parts.length - 2]! : null,
    name: parts[parts.length - 1] ?? '',
  };
}

function stripQuotes(s: string): string {
  return s.replace(/^"(.*)"$/s, '$1');
}

/** Split an argument into whitespace-separated tokens, keeping quotes and brackets whole. */
function tokenizeArg(text: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < text.length) {
    if (/\s/.test(text[i]!)) {
      i++;
      continue;
    }
    const start = i;
    let depth = 0;
    while (i < text.length) {
      const ch = text[i]!;
      if (ch === '"' || ch === "'") {
        i = skipQuoted(text, i);
        continue;
      }
      if (ch === '(' || ch === '[') depth++;
      else if (ch === ')' || ch === ']') depth--;
      else if (/\s/.test(ch) && depth === 0) break;
      i++;
    }
    tokens.push(text.slice(start, i));
  }
  return tokens;
}

/**
 * Normalize a type expression to its identity form: unquoted, lower-cased,
 * whitespace-collapsed, modifiers dropped, aliases folded. Postgres identity
 * is the type OID, so `numeric(10,2)` and `numeric` are the same argument.
 */
export function normalizeArgType(raw: string): string {
  let t = raw.trim();
  let arrayDepth = 0;
  for (;;) {
    const m = /(\[\s*\d*\s*\])\s*$/.exec(t);
    if (!m) break;
    arrayDepth++;
    t = t.slice(0, m.index).trim();
  }
  if (/\bARRAY$/i.test(t)) {
    arrayDepth++;
    t = t.replace(/\s*\bARRAY$/i, '');
  }
  const openMod = t.lastIndexOf('(');
  if (openMod !== -1 && matchParen(t, openMod) === t.length - 1) {
    t = t.slice(0, openMod).trim();
  }
  t = refParts(t).join('.').toLowerCase().replace(/\s+/g, ' ');
  // `pg_catalog.` is how pg_dump spells built-ins; it names the same type.
  t = t.replace(/^pg_catalog\./, '');
  t = TYPE_ALIASES.get(t) ?? t;
  return t + '[]'.repeat(arrayDepth);
}

/** Identity type of one argument, or null for an OUT parameter. */
function argTypeOf(argText: string): string | null {
  let text = argText.trim();

  // A DEFAULT / `=` initializer is not part of identity.
  const defMatch = /\bDEFAULT\b/i.exec(text);
  if (defMatch && isTopLevel(text, defMatch.index)) text = text.slice(0, defMatch.index).trim();
  else {
    const eq = text.indexOf('=');
    if (eq !== -1 && isTopLevel(text, eq)) text = text.slice(0, eq).trim();
  }

  let tokens = tokenizeArg(text);
  if (tokens.length === 0) return null;

  const mode = tokens[0]!.toLowerCase();
  if (['in', 'out', 'inout', 'variadic'].includes(mode)) {
    tokens = tokens.slice(1);
    if (mode === 'out') return null;
  }
  if (tokens.length === 0) return null;

  // `name type` or bare `type`: the first token is a name only when what
  // follows is itself a type, which is not true of the multi-word built-ins.
  if (tokens.length > 1 && !MULTIWORD_TYPE_STARTERS.has(stripQuotes(tokens[0]!).toLowerCase())) {
    tokens = tokens.slice(1);
  }

  return normalizeArgType(tokens.join(' '));
}

function argTypesFrom(arglist: string): string[] {
  return splitTopLevel(arglist)
    .map(argTypeOf)
    .filter((t): t is string => t !== null);
}

/** Comma-separated role list to lower-cased, unquoted names. */
export function parseRoleList(raw: string): string[] {
  return splitTopLevel(raw)
    .map((r) => stripQuotes(r.trim()).toLowerCase())
    .filter(Boolean);
}

const REF = String.raw`((?:"(?:[^"]|"")*"|[\w$]+)(?:\s*\.\s*(?:"(?:[^"]|"")*"|[\w$]+))*)`;

const CREATE_FN_HEAD = new RegExp(String.raw`^\s*CREATE\s+(OR\s+REPLACE\s+)?FUNCTION\s+${REF}\s*\(`, 'i');
const DROP_FN_HEAD = new RegExp(
  String.raw`^\s*DROP\s+(?:FUNCTION|PROCEDURE|AGGREGATE)\s+(?:IF\s+EXISTS\s+)?${REF}\s*(\()?`,
  'i',
);
const ALTER_FN_HEAD = new RegExp(
  String.raw`^\s*ALTER\s+(?:FUNCTION|PROCEDURE|ROUTINE)\s+${REF}\s*(\()?`,
  'i',
);
const GRANT_FN_HEAD = new RegExp(
  String.raw`^\s*GRANT\s+(.+?)\s+ON\s+(?:FUNCTION|PROCEDURE|ROUTINE)\s+${REF}\s*(\()?`,
  'is',
);
const REVOKE_FN_HEAD = new RegExp(
  String.raw`^\s*REVOKE\s+(?:GRANT\s+OPTION\s+FOR\s+)?(.+?)\s+ON\s+(?:FUNCTION|PROCEDURE|ROUTINE)\s+${REF}\s*(\()?`,
  'is',
);

/** Arglist opening at the head's trailing paren, when the statement wrote one. */
function readArglist(
  text: string,
  headLength: number,
  hasParen: boolean,
): { argTypes: string[] | null; tailFrom: number } | null {
  if (!hasParen) return { argTypes: null, tailFrom: headLength };
  const openParen = headLength - 1;
  const closeParen = matchParen(text, openParen);
  if (closeParen === -1) return null;
  return {
    argTypes: argTypesFrom(text.slice(openParen + 1, closeParen)),
    tailFrom: closeParen + 1,
  };
}

export function lineAt(text: string, offset: number): number {
  let line = 1;
  for (let i = text.indexOf('\n'); i !== -1 && i < offset; i = text.indexOf('\n', i + 1)) line++;
  return line;
}

/** Parse every function definition, DROP, ALTER, GRANT and REVOKE in `sql`. */
export function parseSqlFunctions(sql: string): ParsedSql {
  const lexed = lexSql(sql);
  const { clean, statements, dollarSpans, stringSpans } = lexed;

  const functions: ParsedFunction[] = [];
  const drops: ParsedDrop[] = [];
  const alters: ParsedAlter[] = [];
  const grants: ParsedAcl[] = [];
  const revokes: ParsedAcl[] = [];

  for (const stmt of statements) {
    const { text, start } = stmt;
    // Point at the keyword, not at the blank lines and comments above it.
    const head = start + (text.length - text.trimStart().length);

    const create = CREATE_FN_HEAD.exec(text);
    if (create) {
      const openParen = create[0].length - 1;
      const closeParen = matchParen(text, openParen);
      if (closeParen === -1) continue;

      // The body is the first dollar-quote after the argument list, or the
      // string literal that `AS` introduces. "First string after the arglist"
      // would take `'public'` from `SET search_path TO 'public'` as the body.
      const afterArgs = start + closeParen + 1;
      const dollar = dollarSpans.find((d) => d.start >= afterArgs && d.end <= stmt.end);
      const literal = stringSpans.find(
        (s) =>
          s.start >= afterArgs &&
          s.end <= stmt.end &&
          /\bAS\s*$/i.test(clean.slice(afterArgs, s.start)),
      );
      const bodySpan = dollar ?? literal ?? null;
      const ref = parseObjectRef(create[2]!);

      functions.push({
        name: ref.name,
        schema: ref.schema,
        argTypes: argTypesFrom(text.slice(openParen + 1, closeParen)),
        isReplace: Boolean(create[1]),
        preBodyText: clean.slice(afterArgs, bodySpan ? bodySpan.start : stmt.end),
        hasBody: bodySpan !== null,
        index: head,
        line: lineAt(clean, head),
      });
      continue;
    }

    const drop = DROP_FN_HEAD.exec(text);
    if (drop) {
      const args = readArglist(text, drop[0].length, Boolean(drop[2]));
      if (!args) continue;
      const { argTypes, tailFrom } = args;
      // A comma-list drop reads only its first reference here: decline it.
      if (!/^\s*(?:CASCADE|RESTRICT)?\s*;?\s*$/i.test(text.slice(tailFrom))) continue;
      const ref = parseObjectRef(drop[1]!);
      drops.push({ name: ref.name, schema: ref.schema, argTypes, index: head, line: lineAt(clean, head) });
      continue;
    }

    const alter = ALTER_FN_HEAD.exec(text);
    if (alter) {
      const args = readArglist(text, alter[0].length, Boolean(alter[2]));
      if (!args) continue;
      const tail = text.slice(args.tailFrom);
      const owner = /\bOWNER\s+TO\s+("(?:[^"]|"")*"|[\w$]+)/i.exec(tail);
      const setPath = /\bSET\s+"?search_path"?\s*(?:TO|=)\s*([^;]*)/i.exec(tail);
      const rename = /^\s*RENAME\s+TO\s+("(?:[^"]|"")*"|[\w$]+)\s*;?\s*$/i.exec(tail);
      const security = /\bSECURITY\s+(DEFINER|INVOKER)\b/i.exec(tail);
      const ref = parseObjectRef(alter[1]!);
      alters.push({
        name: ref.name,
        schema: ref.schema,
        argTypes: args.argTypes,
        renameTo: rename ? parseObjectRef(rename[1]!).name : null,
        ownerTo: owner ? stripQuotes(owner[1]!).toLowerCase() : null,
        searchPath: setPath ? setPath[1]!.trim() : null,
        resetsSearchPath: /\bRESET\s+(?:"?search_path"?|ALL)\b/i.test(tail),
        securityDefiner: security ? security[1]!.toUpperCase() === 'DEFINER' : null,
        index: head,
        line: lineAt(clean, head),
      });
      continue;
    }

    const acl: [RegExp, ParsedAcl[], RegExp][] = [
      [GRANT_FN_HEAD, grants, /\bTO\b/i],
      [REVOKE_FN_HEAD, revokes, /\bFROM\b/i],
    ];
    for (const [headRe, sink, sep] of acl) {
      const m = headRe.exec(text);
      if (!m) continue;
      const args = readArglist(text, m[0].length, Boolean(m[3]));
      if (!args) break;
      const rest = text.slice(args.tailFrom);
      const sepMatch = sep.exec(rest);
      if (!sepMatch) break;
      // A comma-list of function references reads only its first one: decline.
      if (rest.slice(0, sepMatch.index).trim()) break;
      const roleText = rest
        .slice(sepMatch.index + sepMatch[0].length)
        .replace(/;\s*$/, '')
        .replace(/\s+(?:CASCADE|RESTRICT|WITH\s+GRANT\s+OPTION|GRANTED\s+BY\s+\S+)\s*$/i, '');
      const roles = parseRoleList(roleText);
      // Whitespace inside one grantee is a swallowed trailing clause.
      if (!roles.every((r) => /^\S+$/.test(r))) break;
      const ref = parseObjectRef(m[2]!);
      sink.push({
        name: ref.name,
        schema: ref.schema,
        argTypes: args.argTypes,
        privileges: m[1]!.trim().toUpperCase().replace(/\s+/g, ' '),
        roles,
        index: head,
        line: lineAt(clean, head),
      });
      break;
    }
  }

  return { ...lexed, functions, drops, alters, grants, revokes };
}

/**
 * Every `CREATE FUNCTION` a naive reader sees outside bodies and literals.
 * Deliberately independent of the statement splitter, so it is a real second
 * opinion on what `parseSqlFunctions` returned.
 */
export function countCreateFunctionStatements(lexed: LexedSql): { index: number; line: number }[] {
  const { clean, dollarSpans, stringSpans, identSpans } = lexed;
  const excluded = [...dollarSpans, ...stringSpans, ...identSpans];
  const inside = (i: number): boolean => excluded.some((sp) => i > sp.start && i < sp.end);
  return [...clean.matchAll(/\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\b/gi)]
    .filter((m) => !inside(m.index))
    .map((m) => ({ index: m.index, line: lineAt(clean, m.index) }));
}

/** Identity key for a function: name plus its normalized IN / INOUT type list. */
export function signatureOf(name: string, argTypes: string[]): string {
  return `${name}(${argTypes.join(',')})`;
}
