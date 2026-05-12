import type { Finding, Rule, ScannedFile } from './rule-types.js';

/**
 * Runs every rule against every file. Each rule is responsible for filtering
 * its own input via file.path. Order of findings: by rule order, then by file
 * order, then by the order each rule's scan() returned them.
 */
export function runRules(rules: Rule[], files: ScannedFile[]): Finding[] {
  const findings: Finding[] = [];
  for (const rule of rules) {
    if (rule.scanAll) {
      findings.push(...rule.scanAll(files));
    } else {
      for (const file of files) {
        const ruleFindings = rule.scan(file);
        if (ruleFindings.length > 0) findings.push(...ruleFindings);
      }
    }
  }
  return findings;
}
