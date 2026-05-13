import type { Finding } from '@supacheck/rules';

export function formatJson(findings: Finding[]): string {
  return JSON.stringify({ findings }, null, 2);
}
