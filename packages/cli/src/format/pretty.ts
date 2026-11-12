import pc from 'picocolors';
import type { Finding, Rule } from '@supacheck/rules';

const SEVERITY_COLOR: Record<string, (s: string) => string> = {
  critical: (s) => pc.bold(pc.red(s)),
  high: pc.red,
  medium: pc.yellow,
  low: pc.cyan,
};

export function formatPretty(findings: Finding[], rules: Rule[] = []): string {
  if (findings.length === 0) return pc.green('supacheck: no findings.');

  const severityById = new Map(rules.map((r) => [r.id, r.severity]));
  const byFile = new Map<string, Finding[]>();
  for (const f of findings) {
    const arr = byFile.get(f.file) ?? [];
    arr.push(f);
    byFile.set(f.file, arr);
  }

  const lines: string[] = [];
  for (const [file, list] of byFile) {
    lines.push(pc.bold(pc.underline(file)));
    for (const f of list) {
      const colorize = SEVERITY_COLOR[severityById.get(f.ruleId) ?? 'high'] ?? pc.red;
      const tag = colorize(f.ruleId);
      const loc = pc.dim(`${file}:${f.line}${f.column ? ':' + f.column : ''}`);
      lines.push(`  ${tag}  ${loc}`);
      for (const sub of f.message.split('\n')) {
        lines.push(`    ${sub}`);
      }
    }
    lines.push('');
  }

  lines.push(
    pc.bold(
      findings.length === 1
        ? '1 finding'
        : `${findings.length} findings`,
    ),
  );
  return lines.join('\n');
}
