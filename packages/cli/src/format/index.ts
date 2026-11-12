import type { Finding, Rule } from '@supacheck/rules';
import { formatPretty } from './pretty.js';
import { formatJson } from './json.js';
import { formatGithubActions } from './github-actions.js';
import { formatSarif } from './sarif.js';

export type FormatName = 'pretty' | 'json' | 'sarif' | 'github-actions';

export function isFormatName(value: string): value is FormatName {
  return value === 'pretty' || value === 'json' || value === 'sarif' || value === 'github-actions';
}

export function format(
  findings: Finding[],
  name: FormatName,
  toolVersion: string,
  rules: Rule[] = [],
): string {
  switch (name) {
    case 'pretty':
      return formatPretty(findings, rules);
    case 'json':
      return formatJson(findings);
    case 'github-actions':
      return formatGithubActions(findings);
    case 'sarif':
      return formatSarif(findings, toolVersion, rules);
  }
}
