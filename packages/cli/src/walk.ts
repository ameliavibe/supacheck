import { readdirSync, statSync, existsSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import picomatch from 'picomatch';

export interface WalkOptions {
  cwd: string;
  include: string[];
  exclude: string[];
  /** Honor .gitignore in cwd if present. */
  useGitignore?: boolean;
}

/**
 * Walks the filesystem under cwd and yields files that match include and do
 * not match exclude. Returns paths relative to cwd, using forward slashes so
 * glob matching is consistent across platforms.
 */
export function walk(options: WalkOptions): string[] {
  const exclude = [...options.exclude];
  if (options.useGitignore !== false) {
    const gitignore = join(options.cwd, '.gitignore');
    if (existsSync(gitignore)) {
      exclude.push(...parseGitignore(readFileSync(gitignore, 'utf8')));
    }
  }

  const includeMatcher = picomatch(options.include, { dot: true });
  const excludeMatcher = picomatch(exclude, { dot: true });
  const results: string[] = [];

  function recurse(dir: string): void {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(dir, entry);
      const rel = relative(options.cwd, full).split('\\').join('/');
      if (excludeMatcher(rel)) continue;
      let s;
      try {
        s = statSync(full);
      } catch {
        continue;
      }
      if (s.isDirectory()) {
        recurse(full);
      } else if (s.isFile()) {
        if (includeMatcher(rel)) results.push(rel);
      }
    }
  }
  recurse(options.cwd);
  return results;
}

function parseGitignore(text: string): string[] {
  const patterns: string[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    // Negation patterns ("!foo") are not handled in v1. Skip them rather
    // than silently misinterpret.
    if (line.startsWith('!')) continue;
    // Anchored to repo root: leading "/" means "from the top".
    if (line.startsWith('/')) {
      patterns.push(line.slice(1));
      patterns.push(`${line.slice(1)}/**`);
    } else if (line.endsWith('/')) {
      patterns.push(`**/${line}**`);
    } else {
      patterns.push(`**/${line}`);
      patterns.push(`**/${line}/**`);
    }
  }
  return patterns;
}
