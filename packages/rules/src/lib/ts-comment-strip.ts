/**
 * Replace JS/TS line and block comments with whitespace of equal length so
 * byte offsets (and therefore line / column reports) match the original file.
 * Newlines are preserved so line-number math still works.
 */
export function stripJsComments(src: string): string {
  let out = src.replace(/\/\/[^\n]*/g, (m) => ' '.repeat(m.length));
  out = out.replace(/\/\*[\s\S]*?\*\//g, (m) =>
    m.replace(/[^\n]/g, ' '),
  );
  return out;
}

export function lineAndColumn(src: string, offset: number): { line: number; column: number } {
  const before = src.slice(0, offset);
  const lines = before.split('\n');
  const line = lines.length;
  const column = (lines[lines.length - 1] ?? '').length + 1;
  return { line, column };
}

export function normalizePath(p: string): string {
  return p.split('\\').join('/');
}
