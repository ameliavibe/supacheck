import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Finding, FixPatch, ScannedFile } from '@supacheck/rules';
import { runRules } from '@supacheck/rules';
import { loadConfig } from '../config.js';
import { buildRules } from '../registry.js';
import { walk } from '../walk.js';

export interface FixOptions {
  cwd: string;
  configPath: string | null;
  /** If true, do not write files. Print what would change. */
  dryRun: boolean;
}

export interface FixResult {
  filesChanged: string[];
  patchesApplied: number;
  findingsUnfixable: Finding[];
  message: string;
}

export function runFix(opts: FixOptions): FixResult {
  const config = loadConfig(opts.configPath, opts.cwd);
  const rules = buildRules(config);
  const rulesById = new Map(rules.map((r) => [r.id, r]));

  const paths = walk({
    cwd: opts.cwd,
    include: config.include,
    exclude: config.exclude,
  });
  const files: ScannedFile[] = paths.map((rel) => ({
    path: rel,
    contents: readFileSync(join(opts.cwd, rel), 'utf8'),
  }));
  const fileMap = new Map(files.map((f) => [f.path, f]));

  const findings = runRules(rules, files);

  const patchesByFile = new Map<string, FixPatch[]>();
  const unfixable: Finding[] = [];

  for (const finding of findings) {
    const rule = rulesById.get(finding.ruleId);
    const file = fileMap.get(finding.file);
    if (!rule || !rule.autoFix || !file) {
      unfixable.push(finding);
      continue;
    }
    const fix = rule.autoFix(file, finding);
    if (!fix || !fix.deterministic) {
      unfixable.push(finding);
      continue;
    }
    for (const p of fix.patches) {
      const arr = patchesByFile.get(p.file) ?? [];
      arr.push(p);
      patchesByFile.set(p.file, arr);
    }
  }

  const filesChanged: string[] = [];
  let patchesApplied = 0;

  for (const [filePath, patches] of patchesByFile) {
    const file = fileMap.get(filePath);
    if (!file) continue;
    // Apply patches descending by start offset so earlier replacements don't
    // shift the offsets of later ones.
    const sorted = [...patches].sort((a, b) => b.range[0] - a.range[0]);
    let result = file.contents;
    for (const p of sorted) {
      result = result.slice(0, p.range[0]) + p.replacement + result.slice(p.range[1]);
    }
    if (!opts.dryRun) {
      writeFileSync(join(opts.cwd, filePath), result, 'utf8');
    }
    filesChanged.push(filePath);
    patchesApplied += patches.length;
  }

  const verb = opts.dryRun ? 'Would apply' : 'Applied';
  const message = `${verb} ${patchesApplied} patch(es) across ${filesChanged.length} file(s). ${unfixable.length} finding(s) require manual review.`;

  return { filesChanged, patchesApplied, findingsUnfixable: unfixable, message };
}
