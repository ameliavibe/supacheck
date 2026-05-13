import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ScannedFile } from '@supacheck/rules';
import { runRules } from '@supacheck/rules';
import { loadConfig } from '../config.js';
import { buildRules } from '../registry.js';
import { walk } from '../walk.js';
import { saveBaseline } from '../baseline.js';

export interface BaselineOptions {
  cwd: string;
  configPath: string | null;
}

export interface BaselineResult {
  path: string;
  count: number;
  message: string;
}

export function runBaseline(opts: BaselineOptions): BaselineResult {
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
  const target = join(opts.cwd, config.baseline_file);
  saveBaseline(target, findings);

  return {
    path: target,
    count: findings.length,
    message: `Wrote ${findings.length} finding(s) to ${config.baseline_file}. Subsequent scans will treat these as known; new violations will fail CI.`,
  };
}
