/**
 * SQL helpers shared by the SQL-side rules.
 *
 * - Comment stripping that preserves byte offsets (so line/column reports
 *   match the original file).
 * - File scope by migration filename (timestamp prefix + baseline filter).
 */

export function stripSqlComments(src: string): string {
  let out = src.replace(/--[^\n]*/g, (m) => ' '.repeat(m.length));
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

function basename(path: string): string {
  const slash = path.lastIndexOf('/');
  return slash === -1 ? path : path.slice(slash + 1);
}

const TIMESTAMP_RE = /^(\d{14})/;

export function isMigrationInScope(
  filePath: string,
  baseline: string | undefined,
): boolean {
  if (!filePath.endsWith('.sql')) return false;
  const name = basename(filePath);
  const match = TIMESTAMP_RE.exec(name);
  if (!match) return false;
  if (!baseline) return true;
  return match[1]! > baseline;
}
