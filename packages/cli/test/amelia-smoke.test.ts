/**
 * End-to-end smoke test: run the full CLI scan against the real Amelia repo
 * if it's present on the developer's machine. Skipped on CI / in any env
 * where ~/Amelia is not checked out. Purpose is to catch breakage in the
 * walker, registry, or per-rule plumbing that the per-rule unit tests miss.
 *
 * We don't assert on exact finding counts because Amelia is a live codebase
 * and the default config (e.g. R02's default sensitive_tables list) may not
 * match Amelia's actual sensitive tables. Instead, we assert:
 *   - scan completes
 *   - it doesn't throw
 *   - it returns within a reasonable time
 *   - findings (if any) carry valid shape
 */

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { describe, expect, test } from 'vitest';
import { runScan } from '../src/commands/scan.js';

const AMELIA_REPO = process.env.AMELIA_REPO ?? join(homedir(), 'Amelia');
const ameliaAvailable = existsSync(AMELIA_REPO);

describe.skipIf(!ameliaAvailable)('CLI end-to-end smoke vs. Amelia', () => {
  test(
    'scan completes without throwing',
    () => {
      const result = runScan({
        cwd: AMELIA_REPO,
        configPath: null,
        format: 'json',
        noBaseline: true,
        toolVersion: '0.0.0',
      });
      // eslint-disable-next-line no-console
      console.log(
        `supa-shield smoke vs. Amelia: ${result.findings.length} finding(s) across the repo.`,
      );
      // Validate finding shape if any landed
      for (const f of result.findings.slice(0, 5)) {
        expect(typeof f.ruleId).toBe('string');
        expect(typeof f.file).toBe('string');
        expect(typeof f.line).toBe('number');
        expect(f.line).toBeGreaterThan(0);
      }
    },
    60_000,
  );
});
