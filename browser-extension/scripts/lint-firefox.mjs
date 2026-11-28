// Runs Mozilla's add-on linter (web-ext lint) on the Firefox build. Any error or warning fails,
// except the known ones listed in ALLOWED. The build must exist (`npm run build` first; CI builds
// before it lints).

import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';

import { dist } from './build.mjs';

/**
 * Warnings accepted, by code and a text their description must hold: the manifest declares
 * `data_collection_permissions` (no data collected), a key Firefox 140 added and 128 ESR ignores.
 */
const ALLOWED = [
  { code: 'KEY_FIREFOX_UNSUPPORTED_BY_MIN_VERSION', text: 'data_collection_permissions' },
  { code: 'KEY_FIREFOX_ANDROID_UNSUPPORTED_BY_MIN_VERSION', text: 'data_collection_permissions' },
];

const dir = path.join(dist, 'firefox');
if (!existsSync(path.join(dir, 'manifest.json'))) {
  console.error('dist/firefox is missing: run "npm run build" before "npm run lint".');
  process.exit(1);
}
const require = createRequire(import.meta.url);
const bin = path.join(path.dirname(require.resolve('web-ext')), 'bin', 'web-ext.js');
const r = spawnSync(
  process.execPath,
  [bin, 'lint', '--source-dir', dir, '--self-hosted', '--output', 'json', '--no-config-discovery'],
  // No update check: the lint runs offline.
  { encoding: 'utf8', maxBuffer: 16 << 20, env: { ...process.env, NO_UPDATE_NOTIFIER: '1' } },
);
/** @type {{ errors: any[], warnings: any[], notices: any[] }} */
let report;
try {
  report = JSON.parse(r.stdout);
} catch {
  process.stderr.write(r.stdout + r.stderr);
  console.error('web-ext lint gave no JSON report');
  process.exit(1);
}
const problems = [...report.errors, ...report.warnings].filter(
  (p) => !ALLOWED.some((a) => a.code === p.code && String(p.description ?? '').includes(a.text)),
);
for (const p of problems) {
  console.error(`${p._type} ${p.code} ${p.file ?? ''}: ${p.message}\n  ${String(p.description ?? '').replace(/\s+/g, ' ')}`);
}
const allowed = report.errors.length + report.warnings.length - problems.length;
console.log(`web-ext lint dist/firefox: ${String(problems.length)} problem(s), ${String(allowed)} allowed warning(s), ${String(report.notices.length)} notice(s)`);
process.exit(problems.length === 0 ? 0 : 1);
