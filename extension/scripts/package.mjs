// Packages the built targets (build-and-test.md §3): dist/picket-browser-extension-<ver>-brave.zip
// and -firefox.xpi (unsigned), each with a `.sha256` file (`<hex>  <name>`). Run after the build
// (`npm run package` builds first). The archives are reproducible: same sources, same bytes.

import { createHash } from 'node:crypto';
import { readdir, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { dist, version } from './build.mjs';
import { zip } from './zip.mjs';

/** @param {string} dir @param {string} [prefix] @returns {Promise<{ name: string, data: Buffer }[]>} */
async function entries(dir, prefix = '') {
  const out = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const name = prefix === '' ? e.name : `${prefix}/${e.name}`;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      out.push(...(await entries(p, name)));
    } else if (e.isFile()) {
      out.push({ name, data: await readFile(p) });
    }
  }
  return out;
}

const ver = await version();
const outputs = [
  { target: 'brave', file: `picket-browser-extension-${ver}-brave.zip` },
  { target: 'firefox', file: `picket-browser-extension-${ver}-firefox.xpi` },
];
for (const { target, file } of outputs) {
  const dir = path.join(dist, target);
  const manifestPath = path.join(dir, 'manifest.json');
  if (!(await stat(manifestPath).catch(() => null))) {
    throw new Error(`${path.relative(process.cwd(), dir)} is missing: run "npm run build" first`);
  }
  const archive = zip(await entries(dir));
  const sum = createHash('sha256').update(archive).digest('hex');
  await writeFile(path.join(dist, file), archive);
  await writeFile(path.join(dist, `${file}.sha256`), `${sum}  ${file}\n`);
  console.log(`${sum}  dist/${file}`);
}
