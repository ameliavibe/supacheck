import type {
  Finding,
  FixSuggestion,
  Rule,
  ScannedFile,
} from '../lib/rule-types.js';

export interface R03Options {
  /**
   * Migrations with a YYYYMMDDHHMMSS timestamp less than or equal to this
   * value are skipped. Lets adopters baseline an existing repo so historical
   * violations do not block CI. Defaults to scanning every file.
   */
  migrationsBaselineTimestamp?: string;
}

const POLICY_BLOCK_RE = /(?:CREATE|ALTER)\s+POLICY\b[\s\S]*?;/gi;
const AUTH_UID_RE = /\bauth\.uid\s*\(\s*\)/g;
const SELECT_LOOKBACK_RE = /\bselect\s+$/i;
const LOOKBACK_CHARS = 64;

const TIMESTAMP_RE = /^(\d{14})/;

/**
 * Replace SQL comments with whitespace of equal length so byte offsets (and
 * therefore line / column reports) match the original file.
 */
function stripSqlComments(src: string): string {
  let out = src.replace(/--[^\n]*/g, (m) => ' '.repeat(m.length));
  out = out.replace(/\/\*[\s\S]*?\*\//g, (m) =>
    m.replace(/[^\n]/g, ' '),
  );
  return out;
}

function lineAndColumn(src: string, offset: number): { line: number; column: number } {
  const before = src.slice(0, offset);
  const lines = before.split('\n');
  const line = lines.length;
  const column = (lines[lines.length - 1] ?? '').length + 1;
  return { line, column };
}

function basename(path: string): string {
  const slash = path.lastIndexOf('/');
  return slash === -1 ? path : path.slice(slash + 1);
}

function isInScope(filePath: string, baseline: string | undefined): boolean {
  if (!filePath.endsWith('.sql')) return false;
  const name = basename(filePath);
  const match = TIMESTAMP_RE.exec(name);
  if (!match) {
    // Files without a timestamp prefix are not migration files. Skip.
    return false;
  }
  if (!baseline) return true;
  return match[1]! > baseline;
}

export function createR03(options: R03Options = {}): Rule {
  const baseline = options.migrationsBaselineTimestamp;

  return {
    id: 'R03',
    slug: 'sql-bare-auth-uid',
    name: 'Bare auth.uid() in RLS policy',
    category: 'rls-performance',
    severity: 'high',
    filePatterns: [
      '**/migrations/**/*.sql',
      '**/supabase/migrations/**/*.sql',
    ],
    squashClobberFamily: false,

    scan(file: ScannedFile): Finding[] {
      if (!isInScope(file.path, baseline)) return [];

      const stripped = stripSqlComments(file.contents);
      const findings: Finding[] = [];

      POLICY_BLOCK_RE.lastIndex = 0;
      let block: RegExpExecArray | null;
      while ((block = POLICY_BLOCK_RE.exec(stripped)) !== null) {
        const blockStart = block.index;
        const blockText = block[0];

        AUTH_UID_RE.lastIndex = 0;
        let hit: RegExpExecArray | null;
        while ((hit = AUTH_UID_RE.exec(blockText)) !== null) {
          const before = blockText.slice(
            Math.max(0, hit.index - LOOKBACK_CHARS),
            hit.index,
          );
          if (SELECT_LOOKBACK_RE.test(before)) continue;

          const absIndex = blockStart + hit.index;
          const matchLength = hit[0].length;
          const { line, column } = lineAndColumn(stripped, absIndex);

          findings.push({
            ruleId: 'R03',
            file: file.path,
            line,
            column,
            message:
              'Bare auth.uid() in RLS policy forces per-row evaluation. ' +
              'Wrap as (select auth.uid()) so Postgres caches the value once per query.',
            range: [absIndex, absIndex + matchLength],
          });
        }
      }

      return findings;
    },

    autoFix(file: ScannedFile, finding: Finding): FixSuggestion | null {
      if (!finding.range) return null;
      return {
        description:
          'Wrap auth.uid() as (select auth.uid()) so Postgres caches the value once per query.',
        deterministic: true,
        patches: [
          {
            file: file.path,
            range: finding.range,
            replacement: '(select auth.uid())',
          },
        ],
      };
    },
  };
}

/** Default rule instance with no baseline filter (scans every migration). */
export const R03: Rule = createR03();
