// Installs and updates (browser-extension.md §1, §5; README "Install"):
//
// - Brave: the build loaded unpacked from a folder (Developer mode on) has the ID the manifest key
//   fixes; replacing the folder's contents with a newer build and pressing Reload updates it, and
//   the settings and the edge's access stay.
// - Firefox: Playwright's Firefox requires signed add-ons (a build-time setting, as on release
//   Firefox), so the documented unsigned .xpi install (Developer Edition, Nightly or ESR with
//   `xpinstall.signatures.required` off) can't run here; the build installs as a temporary add-on
//   with its gecko ID, and a newer build installed over it keeps the settings and access.

import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { CHROMIUM_ID, GECKO_ID } from '../../scripts/manifest.mjs';
import type { ExtGlobal } from './harness/browsers';
import { distOf, eventually, expect, setUp, test as base } from './harness/fixtures';

/** A copy of the build in its own folder, with `version` in its manifest. */
function copyBuild(from: string, dir: string, version: string): void {
  rmSync(dir, { recursive: true, force: true });
  cpSync(from, dir, { recursive: true });
  const file = path.join(dir, 'manifest.json');
  const manifest = JSON.parse(readFileSync(file, 'utf8')) as { version: string };
  manifest.version = version;
  writeFileSync(file, `${JSON.stringify(manifest, null, 2)}\n`);
}

const test = base.extend<{ folder: string }>({
  // eslint-disable-next-line no-empty-pattern -- Playwright reads fixture dependencies from the pattern.
  folder: async ({}, use) => {
    const dir = mkdtempSync(path.join(tmpdir(), 'picket-unpacked-'));
    await use(dir);
    rmSync(dir, { recursive: true, force: true });
  },
  extensionDir: async ({ kind, folder }, use) => {
    const dir = path.join(folder, 'picket');
    copyBuild(distOf(kind), dir, '0.1.0');
    await use(dir);
  },
});

test('installs with its fixed ID and updates in place, keeping its settings', async ({ ext, edge, targets, kind, folder, extensionDir }) => {
  const info = (): Promise<{ id: string; version: string; edgeUrl: unknown; access: boolean }> =>
    ext.observer.run(async () => {
      const c = (globalThis as unknown as ExtGlobal).chrome;
      return {
        id: c.runtime.id,
        version: c.runtime.getManifest().version,
        edgeUrl: (await c.storage.local.get(null)).edgeUrl,
        access: await c.permissions.contains({ origins: ['https://127.0.0.1/*'] }),
      };
    }, null);
  if (extensionDir === null) {
    throw new Error('no unpacked folder');
  }
  const before = await info();
  expect(before.id).toBe(kind === 'chromium' ? CHROMIUM_ID : GECKO_ID);
  expect(before.version).toBe('0.1.0');
  await setUp(ext, edge);

  if (kind === 'chromium') {
    // Replace the folder's contents, then press Reload.
    copyBuild(distOf(kind), extensionDir, '0.1.1');
    await ext.update(extensionDir);
  } else {
    const next = path.join(folder, 'next');
    copyBuild(distOf(kind), next, '0.1.1');
    await ext.update(next);
  }
  await eventually('the new version', async () => (await info()).version === '0.1.1');
  const after = await info();
  expect(after).toEqual({ id: before.id, version: '0.1.1', edgeUrl: edge.origin, access: true });

  // And it works: a block still gets the block page.
  edge.block('after-update.test', { mode: { type: 'nxdomain' } });
  const tab = await ext.newTab();
  await tab.goto(targets.url('after-update.test', '/'));
  await tab.waitForUrl((u) => u.startsWith(`${ext.base}block.html`));
});
