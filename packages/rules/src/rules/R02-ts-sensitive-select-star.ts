import type { Finding, Rule, ScannedFile } from '../lib/rule-types.js';
import { lineAndColumn, normalizePath } from '../lib/ts-comment-strip.js';
import { findChainEnd } from '../lib/chain-walker.js';

export interface R02Options {
  /**
   * Names of tables that must never be queried with select('*'). Defaults to
   * an empty list (rule does nothing without a list — sensitive tables are
   * per-project knowledge the customer curates).
   */
  sensitiveTables?: string[];
  /** Max chars to walk forward from a .from() call. Defaults to 800. */
  chainMaxChars?: number;
}

const SELECT_STAR_RE = /\.select\(\s*['"`]\*['"`]\s*\)/;

function isInScope(filePath: string): boolean {
  const norm = normalizePath(filePath);
  if (norm.endsWith('.test.ts') || norm.endsWith('.test.tsx')) return false;
  if (norm.endsWith('.spec.ts')) return false;
  if (norm.endsWith('.d.ts')) return false;
  return (
    norm.endsWith('.ts') ||
    norm.endsWith('.tsx') ||
    norm.endsWith('.mts') ||
    norm.endsWith('.cts')
  );
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function findFromCalls(src: string, table: string): { index: number; length: number }[] {
  const re = new RegExp(
    String.raw`\.from\(\s*['"\`]${escapeRegex(table)}['"\`]\s*\)`,
    'g',
  );
  const out: { index: number; length: number }[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(src)) !== null) {
    out.push({ index: m.index, length: m[0].length });
  }
  return out;
}

export function createR02(options: R02Options = {}): Rule {
  const sensitiveTables = options.sensitiveTables ?? [];
  const chainMaxChars = options.chainMaxChars ?? 800;

  return {
    id: 'R02',
    slug: 'ts-sensitive-select-star',
    name: "select('*') on a sensitive table",
    category: 'data-exposure',
    severity: 'high',
    filePatterns: ['app/**/*.ts', 'app/**/*.tsx', 'lib/**/*.ts', 'lib/**/*.tsx'],
    squashClobberFamily: false,

    scan(file: ScannedFile): Finding[] {
      if (sensitiveTables.length === 0) return [];
      if (!isInScope(file.path)) return [];

      const src = file.contents;
      const findings: Finding[] = [];

      for (const table of sensitiveTables) {
        for (const from of findFromCalls(src, table)) {
          const chainStart = from.index + from.length;
          const chainStop = findChainEnd(src, chainStart, { maxChars: chainMaxChars });
          const chunk = src.slice(from.index, chainStop);
          if (!SELECT_STAR_RE.test(chunk)) continue;
          const { line, column } = lineAndColumn(src, from.index);
          findings.push({
            ruleId: 'R02',
            file: file.path,
            line,
            column,
            message: `select('*') on sensitive table "${table}". Tables that hold tokens, PII, or billing data must be queried with explicit columns even via service role. Wholesale reads make stale-data leakage harder to audit and increase blast radius if RLS is misconfigured.`,
            range: [from.index, chainStop],
          });
        }
      }
      return findings;
    },
  };
}

export const R02: Rule = createR02();
