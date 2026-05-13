import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { sampleConfig } from '../config.js';

export interface InitOptions {
  cwd: string;
  force: boolean;
}

export interface InitResult {
  path: string;
  written: boolean;
  message: string;
}

export function runInit(opts: InitOptions): InitResult {
  const target = join(opts.cwd, '.supacheck.yml');
  if (existsSync(target) && !opts.force) {
    return {
      path: target,
      written: false,
      message: `.supacheck.yml already exists. Pass --force to overwrite.`,
    };
  }
  writeFileSync(target, sampleConfig(), 'utf8');
  return {
    path: target,
    written: true,
    message: `Wrote default config to .supacheck.yml. Edit per-rule options before your first scan.`,
  };
}
