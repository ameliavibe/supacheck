import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Finding, RuleSeverity, ScannedFile } from '@supacheck/rules';
import { runRules } from '@supacheck/rules';
import { loadConfig } from '../config.js';
import { buildRules } from '../registry.js';
import { walk } from '../walk.js';
import {
  loadBaseline,
  partitionAgainstBaseline,
} from '../baseline.js';
import { format, isFormatName } from '../format/index.js';

export interface ScanOptions {
  cwd: string;
  configPath: string | null;
  format: string;
  noBaseline: boolean;
  toolVersion: string;
}

export interface ScanResult {
  findings: Finding[];
  newFindings: Finding[];
  knownFindings: Finding[];
  output: string;
  exitCode: number;
}

const SEVERITY_RANK: Record<RuleSeverity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export function runScan(opts: ScanOptions): ScanResult {
  const config = loadConfig(opts.configPath, opts.cwd);
  const rules = buildRules(config);

  const paths = walk({
    cwd: opts.cwd,
    include: config.include,
    exclude: config.exclude,
  });

  const files: ScannedFile[] = paths.map((rel) => ({
    path: rel,
    contents: readFileSync(join(opts.cwd, rel), 'utf8'),
  }));

  const findings = runRules(rules, files);

  const baseline = opts.noBaseline
    ? null
    : loadBaseline(join(opts.cwd, config.baseline_file));
  const { newFindings, knownFindings } = partitionAgainstBaseline(
    findings,
    baseline,
  );

  const formatName = isFormatName(opts.format) ? opts.format : 'pretty';
  // The scan output shows only new findings (the actionable ones). Known
  // baselined findings are reported separately on stderr at end-of-run.
  const output = format(newFindings, formatName, opts.toolVersion, rules);

  const severityById = new Map(rules.map((r) => [r.id, r.severity]));
  const threshold = SEVERITY_RANK[config.fail_on] ?? SEVERITY_RANK.high;
  const failing = newFindings.some(
    (f) => SEVERITY_RANK[severityById.get(f.ruleId) ?? 'critical'] >= threshold,
  );
  const exitCode = failing ? 1 : 0;

  return { findings, newFindings, knownFindings, output, exitCode };
}
