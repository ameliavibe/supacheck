import type { Finding, Rule, ScannedFile } from '../lib/rule-types.js';
import { lineAndColumn, normalizePath, stripJsComments } from '../lib/ts-comment-strip.js';

export interface R05Options {
  /**
   * Files allowed to call bare fetch() against URLs that are NOT user-derived
   * (provider API constants, signed temp URLs from trusted internal sources,
   * etc.). Each entry is matched as substring/suffix of the normalized path.
   */
  allowlist?: string[];

  /**
   * Additional helper import specifiers that, when imported by a file, mark
   * it as "covered" and exempt from the rule. Defaults already match the
   * @supa-shield/safe-fetch package and any local security/ssrf module
   * imported via relative path.
   */
  helperImports?: string[];
}

const FORBIDDEN = /(?<![\w.])fetch\s*\(/g;
const SSRF_SAFE_ANNOTATION = /\/\/\s*ssrf-safe:/;

const DEFAULT_HELPER_IMPORTS = [
  '@supa-shield/safe-fetch',
];

const SSRF_HELPER_RE_LOCAL = /from\s+['"]\.\.?\/(?:[\w-]+\/)*security\/ssrf['"]/;

function isInScope(filePath: string, allowlist: string[]): boolean {
  const norm = normalizePath(filePath);
  for (const entry of allowlist) {
    if (norm === entry || norm.endsWith(entry)) return false;
  }
  if (norm.endsWith('.test.ts') || norm.endsWith('.test.tsx')) return false;
  if (norm.endsWith('.d.ts')) return false;
  // The SSRF helper itself is not in scope (it owns the call).
  if (norm.endsWith('/security/ssrf.ts')) return false;
  if (norm.endsWith('@supa-shield/safe-fetch/src/index.ts')) return false;
  if (!norm.endsWith('.ts') && !norm.endsWith('.tsx')) return false;
  const underLib = norm === 'lib' || norm.startsWith('lib/') || norm.includes('/lib/');
  const underApi = norm === 'app/api' || norm.startsWith('app/api/') || norm.includes('/app/api/');
  return underLib || underApi;
}

function fileImportsHelper(raw: string, helperImports: string[]): boolean {
  if (SSRF_HELPER_RE_LOCAL.test(raw)) return true;
  for (const spec of helperImports) {
    const escaped = spec.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`from\\s+['"]${escaped}['"]`);
    if (re.test(raw)) return true;
  }
  return false;
}

export function createR05(options: R05Options = {}): Rule {
  const allowlist = options.allowlist ?? [];
  const helperImports = options.helperImports ?? DEFAULT_HELPER_IMPORTS;

  return {
    id: 'R05',
    slug: 'ts-bare-fetch-no-helper',
    name: 'Server-side fetch() without SSRF-safe helper',
    category: 'ssrf',
    severity: 'high',
    filePatterns: ['lib/**/*.ts', 'lib/**/*.tsx', 'app/api/**/*.ts', 'app/api/**/*.tsx'],
    squashClobberFamily: false,

    scan(file: ScannedFile): Finding[] {
      if (!isInScope(file.path, allowlist)) return [];
      if (fileImportsHelper(file.contents, helperImports)) return [];

      const stripped = stripJsComments(file.contents);
      const rawLines = file.contents.split('\n');

      const findings: Finding[] = [];
      FORBIDDEN.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = FORBIDDEN.exec(stripped)) !== null) {
        const { line, column } = lineAndColumn(stripped, m.index);
        const sameLine = rawLines[line - 1] ?? '';
        const prevLine = rawLines[line - 2] ?? '';
        if (SSRF_SAFE_ANNOTATION.test(sameLine) || SSRF_SAFE_ANNOTATION.test(prevLine)) continue;
        findings.push({
          ruleId: 'R05',
          file: file.path,
          line,
          column,
          message:
            'Server-side fetch() may issue requests to attacker-controlled URLs (SSRF). ' +
            'Use safeFetch() from @supa-shield/safe-fetch or import a local security/ssrf helper. ' +
            'For known-safe constant URLs, add `// ssrf-safe: <reason>` on the same line or the line above.',
          range: [m.index, m.index + m[0].length],
        });
      }
      return findings;
    },
  };
}

export const R05: Rule = createR05();
