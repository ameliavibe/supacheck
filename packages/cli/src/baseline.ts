import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import type { Finding } from '@supa-shield/rules';

export interface BaselineEntry {
  ruleId: string;
  file: string;
  message: string;
}

export interface BaselineFile {
  version: 1;
  generated_at: string;
  findings: BaselineEntry[];
}

/**
 * Stable fingerprint for a finding. Intentionally excludes line numbers so a
 * finding that shifts up or down a few lines stays matched. Two findings with
 * the same ruleId+file+message are treated as the same instance.
 */
export function fingerprint(finding: BaselineEntry | Finding): string {
  return `${finding.ruleId}|${finding.file}|${finding.message}`;
}

export function loadBaseline(path: string): BaselineFile | null {
  if (!existsSync(path)) return null;
  const raw = readFileSync(path, 'utf8');
  try {
    const parsed = JSON.parse(raw) as BaselineFile;
    if (parsed.version !== 1) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function saveBaseline(path: string, findings: Finding[]): BaselineFile {
  const baseline: BaselineFile = {
    version: 1,
    generated_at: new Date().toISOString(),
    findings: findings.map((f) => ({
      ruleId: f.ruleId,
      file: f.file,
      message: f.message,
    })),
  };
  writeFileSync(path, JSON.stringify(baseline, null, 2) + '\n', 'utf8');
  return baseline;
}

/**
 * Splits findings into (newOrUnknown, known) based on the baseline. A finding
 * matches a baseline entry if its fingerprint is in the baseline's set.
 */
export function partitionAgainstBaseline(
  findings: Finding[],
  baseline: BaselineFile | null,
): { newFindings: Finding[]; knownFindings: Finding[] } {
  if (!baseline) return { newFindings: findings, knownFindings: [] };
  const knownPrints = new Set(baseline.findings.map((f) => fingerprint(f)));
  const newFindings: Finding[] = [];
  const knownFindings: Finding[] = [];
  for (const f of findings) {
    if (knownPrints.has(fingerprint(f))) {
      knownFindings.push(f);
    } else {
      newFindings.push(f);
    }
  }
  return { newFindings, knownFindings };
}
