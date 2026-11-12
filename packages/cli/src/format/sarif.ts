import type { Finding, Rule, RuleSeverity } from '@supacheck/rules';

const LEVEL: Record<RuleSeverity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
};

/**
 * Emits SARIF 2.1.0 so customers can upload to GitHub Code Scanning. SARIF
 * lets the Security tab consume findings without our GitHub App installed.
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */
export function formatSarif(
  findings: Finding[],
  toolVersion: string,
  ruleDefs: Rule[] = [],
): string {
  const defs = new Map(ruleDefs.map((r) => [r.id, r]));
  const ruleIds = Array.from(new Set(findings.map((f) => f.ruleId))).sort();
  const rules = ruleIds.map((id) => ({
    id,
    name: defs.get(id)?.slug ?? id,
    shortDescription: { text: defs.get(id)?.name ?? `supacheck ${id}` },
    helpUri: 'https://github.com/ameliavibe/supacheck#what-it-catches',
  }));

  const results = findings.map((f) => ({
    ruleId: f.ruleId,
    level: LEVEL[defs.get(f.ruleId)?.severity ?? 'high'],
    message: { text: f.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.file, uriBaseId: 'SRCROOT' },
          region: {
            startLine: f.line,
            ...(f.column ? { startColumn: f.column } : {}),
          },
        },
      },
    ],
  }));

  return JSON.stringify(
    {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'supacheck',
              version: toolVersion,
              informationUri: 'https://github.com/ameliavibe/supacheck',
              rules,
            },
          },
          results,
        },
      ],
    },
    null,
    2,
  );
}
