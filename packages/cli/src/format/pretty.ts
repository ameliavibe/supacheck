import pc from 'picocolors';
import type { Finding } from '@supacheck/rules';

const SEVERITY_COLOR: Record<string, (s: string) => string> = {
  critical: (s) => pc.bold(pc.red(s)),
  high: pc.red,
  medium: pc.yellow,
  low: pc.cyan,
};

export function formatPretty(findings: Finding[]): string {
  if (findings.length === 0) return pc.green('supacheck: no findings.');

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
      const colorize = SEVERITY_COLOR[severityForRule(f.ruleId)] ?? pc.red;
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

function severityForRule(ruleId: string): 'critical' | 'high' | 'medium' | 'low' {
  // Hardcoded for v1; the rule itself owns the severity but the formatter
  // doesn't get it via Finding today. R01/R10/R29 critical, the rest high.
  if (ruleId === 'R01' || ruleId === 'R10' || ruleId === 'R29') return 'critical';
  return 'high';
}
