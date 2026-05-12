import type { Finding } from '@supa-shield/rules';

export function formatJson(findings: Finding[]): string {
  return JSON.stringify({ findings }, null, 2);
}
