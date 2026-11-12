import { chmodSync, rmSync } from 'node:fs';
import { build } from 'esbuild';

// One file with @supacheck/rules inlined from source, so the published package
// does not depend on a second published package or on a prior rules build.
// Third-party dependencies stay external.
rmSync('dist', { recursive: true, force: true });
await build({
  entryPoints: ['src/index.ts'],
  outfile: 'dist/index.js',
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node20',
  alias: { '@supacheck/rules': '../rules/src/index.ts' },
  external: ['picocolors', 'picomatch', 'yaml'],
});
chmodSync('dist/index.js', 0o755);
