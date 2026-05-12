import type { Finding, Rule, ScannedFile } from '../lib/rule-types.js';
import { lineAndColumn, normalizePath, stripJsComments } from '../lib/ts-comment-strip.js';

export interface R01Options {
  /**
   * Files whose path matches any entry here are skipped. Use for routes that
   * are themselves the auth flow (e.g. an endpoint that issues a token and
   * deliberately reads the cookie-session via getUser() with no argument).
   *
   * Paths are matched as substring of the normalized (forward-slash) path. A
   * full relative path or a suffix both work; pick whichever is least likely
   * to clash with sibling files.
   */
  allowlist?: string[];
}

const FORBIDDEN = /\.auth\.getUser\s*\(\s*\)/g;

function isInScope(filePath: string, allowlist: string[]): boolean {
  const norm = normalizePath(filePath);
  for (const entry of allowlist) {
    if (norm === entry || norm.endsWith(entry)) return false;
  }
  if (!norm.includes('/app/api/') && !norm.startsWith('app/api/')) return false;
  return norm.endsWith('/route.ts') || norm.endsWith('/route.tsx');
}

export function createR01(options: R01Options = {}): Rule {
  const allowlist = options.allowlist ?? [];
  return {
    id: 'R01',
    slug: 'ts-supabase-auth-getuser',
    name: 'Bare supabase.auth.getUser() in API route bypasses cached DAL',
    category: 'auth-cache-coherence',
    severity: 'high',
    filePatterns: ['**/app/api/**/route.ts', '**/app/api/**/route.tsx'],
    squashClobberFamily: false,

    scan(file: ScannedFile): Finding[] {
      if (!isInScope(file.path, allowlist)) return [];
      const stripped = stripJsComments(file.contents);
      const findings: Finding[] = [];
      FORBIDDEN.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = FORBIDDEN.exec(stripped)) !== null) {
        const { line, column } = lineAndColumn(stripped, m.index);
        findings.push({
          ruleId: 'R01',
          file: file.path,
          line,
          column,
          message:
            'Bare auth.getUser() (cookie-form) in an API route bypasses the request-cached DAL. ' +
            'Use a wrapped requireAuth() helper so multiple callers in one request share one round-trip. ' +
            'The bearer-token form auth.getUser(token) is allowed.',
          range: [m.index, m.index + m[0].length],
        });
      }
      return findings;
    },
  };
}

export const R01: Rule = createR01();
