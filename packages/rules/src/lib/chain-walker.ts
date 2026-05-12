/**
 * Forward chain walker. Used by R02 to find the end of a fluent
 * `.from('table').select(...)` chain so we can scan it for select('*')
 * without bleeding into the next statement on the same table.
 *
 * Tracks paren depth so nested calls (e.g. `.eq('user_id', auth.uid())`)
 * don't terminate the walk early. Stops at:
 *
 *   - `;` at depth 0
 *   - end-of-line followed by a sibling chain on the next line
 *     (`.from(`, `const `, `await ` at line start)
 *   - max chars (defensive guard against runaway walks)
 */
export interface ChainWalkOptions {
  maxChars?: number;
}

const DEFAULT_MAX_CHARS = 800;

const SIBLING_LINE_STARTERS = ['.from(', 'const ', 'await ', 'let ', 'var '];

export function findChainEnd(src: string, start: number, options: ChainWalkOptions = {}): number {
  const limit = Math.min(src.length, start + (options.maxChars ?? DEFAULT_MAX_CHARS));
  let depth = 0;
  let i = start;
  while (i < limit) {
    const c = src[i];
    if (c === '(') depth++;
    else if (c === ')') depth--;
    else if (depth === 0) {
      if (c === ';') break;
      if (c === '\n') {
        const next = src.slice(i + 1, i + 32).trimStart();
        if (SIBLING_LINE_STARTERS.some((s) => next.startsWith(s))) break;
      }
    }
    i++;
  }
  return i;
}
