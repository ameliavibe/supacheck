#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from './commands/scan.js';
import { runInit } from './commands/init.js';
import { runBaseline } from './commands/baseline.js';
import { runFix } from './commands/fix.js';

function getToolVersion(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    // dist/index.js: ../package.json. src/index.ts during dev: same.
    const pkg = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8')) as { version: string };
    return pkg.version;
  } catch {
    return '0.0.0';
  }
}

const HELP = `supacheck ${getToolVersion()}

Static analysis for Supabase + Next.js apps. Catches the application-layer
security footguns that live-DB scanners miss and that audit-time LLM tools skip.

Commands:
  scan [paths...]    Scan the working tree for rule violations (default).
  init               Drop a default .supacheck.yml in the cwd.
  baseline           Record current violations to a baseline file.
                     Subsequent scans only fail on NEW violations.
  fix                Apply deterministic auto-fixes for violations.

Options:
  --config <path>    Path to .supacheck.yml (defaults to cwd lookup).
  --format <name>    pretty | json | sarif | github-actions (default: pretty).
  --no-baseline      Ignore the baseline file even if present.
  --dry-run          For 'fix': do not write files, print what would change.
  --force            For 'init': overwrite an existing .supacheck.yml.
  --version, -v      Print version.
  --help, -h         Print this help.

Examples:
  supacheck scan
  supacheck scan --format=sarif > supacheck.sarif
  supacheck baseline
  supacheck fix --dry-run

Docs: https://github.com/ameliavibe/supacheck
`;

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    args: process.argv.slice(2),
    options: {
      config: { type: 'string' },
      format: { type: 'string', default: 'pretty' },
      'no-baseline': { type: 'boolean', default: false },
      'dry-run': { type: 'boolean', default: false },
      force: { type: 'boolean', default: false },
      version: { type: 'boolean', short: 'v', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
    allowPositionals: true,
    strict: false,
  });

  if (values.version) {
    console.log(getToolVersion());
    return 0;
  }
  if (values.help) {
    console.log(HELP);
    return 0;
  }

  const command = positionals[0] ?? 'scan';
  const cwd = process.cwd();
  const configPath = (values.config as string | undefined) ?? null;
  const toolVersion = getToolVersion();

  switch (command) {
    case 'scan': {
      const result = runScan({
        cwd,
        configPath,
        format: (values.format as string) ?? 'pretty',
        noBaseline: Boolean(values['no-baseline']),
        toolVersion,
      });
      if (result.output) process.stdout.write(result.output + '\n');
      if (result.knownFindings.length > 0) {
        process.stderr.write(
          `\nsupacheck: ${result.knownFindings.length} known finding(s) suppressed by baseline.\n`,
        );
      }
      return result.exitCode;
    }
    case 'init': {
      const result = runInit({ cwd, force: Boolean(values.force) });
      process.stdout.write(result.message + '\n');
      return result.written ? 0 : 1;
    }
    case 'baseline': {
      const result = runBaseline({ cwd, configPath });
      process.stdout.write(result.message + '\n');
      return 0;
    }
    case 'fix': {
      const result = runFix({
        cwd,
        configPath,
        dryRun: Boolean(values['dry-run']),
      });
      process.stdout.write(result.message + '\n');
      return 0;
    }
    default: {
      process.stderr.write(`supacheck: unknown command "${command}"\n\n${HELP}`);
      return 2;
    }
  }
}

main().then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`supacheck: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(2);
  },
);
