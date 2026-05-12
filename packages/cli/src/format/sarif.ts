import type { Finding } from '@supa-shield/rules';

/**
 * Emits SARIF 2.1.0 so customers can upload to GitHub Code Scanning. SARIF
 * lets the Security tab consume findings without our GitHub App installed.
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */
export function formatSarif(findings: Finding[], toolVersion: string): string {
  const ruleIds = Array.from(new Set(findings.map((f) => f.ruleId))).sort();
  const rules = ruleIds.map((id) => ({
    id,
    name: id,
    shortDescription: { text: `supa-shield ${id}` },
    helpUri: `https://github.com/ameliavibe/supa-shield/blob/main/docs/rules/${id}.md`,
  }));

  const results = findings.map((f) => ({
    ruleId: f.ruleId,
    level: 'error' as const,
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
              name: 'supa-shield',
              version: toolVersion,
              informationUri: 'https://github.com/ameliavibe/supa-shield',
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
