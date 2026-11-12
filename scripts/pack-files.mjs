// prepack copies the repo-level README, LICENSE and NOTICE into the package
// being packed; postpack (--clean) removes the copies again.
import { copyFileSync, existsSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const clean = process.argv.includes('--clean');
const names = process.argv.slice(2).filter((a) => !a.startsWith('--'));

for (const name of names) {
  if (clean) rmSync(name, { force: true });
  else if (!existsSync(name)) copyFileSync(join(root, name), name);
}
