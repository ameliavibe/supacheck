import type { Finding } from '@supa-shield/rules';

/**
 * Emits GitHub Actions workflow commands so violations show up as PR
 * annotations in the diff view.
 * See https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions
 */
export function formatGithubActions(findings: Finding[]): string {
  const lines: string[] = [];
  for (const f of findings) {
    const props: string[] = [
      `file=${escapeProp(f.file)}`,
      `line=${f.line}`,
    ];
    if (f.column !== undefined) props.push(`col=${f.column}`);
    props.push(`title=${escapeProp(`supa-shield ${f.ruleId}`)}`);
    lines.push(`::error ${props.join(',')}::${escapeMessage(f.message)}`);
  }
  return lines.join('\n');
}

function escapeProp(value: string): string {
  return value.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A').replace(/:/g, '%3A').replace(/,/g, '%2C');
}

function escapeMessage(value: string): string {
  return value.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}
