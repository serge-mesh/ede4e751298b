// Playwright fixtures for the browser tests: per test, a fake edge, the local targets and a
// fresh browser profile with the built extension; per worker, the test certificates.

import { rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { expect, test as base } from '@playwright/test';

import { DETECTION_ON, DETECTION_ON_AFTER_RESTART } from '../../../src/shared/permissions';

import { launch, type BrowserKind, type Session, type Surface, type Tab } from './browsers';
import { makeCerts, type TestCerts } from './certs';
import { FakeEdge } from './edge';
import { localIpv4, Targets } from './targets';
import { WAIT_MS } from './time';

export { expect };
export type { Session, Surface, Tab };

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

/** The build a browser loads (`npm run build` makes both). */
export function distOf(kind: BrowserKind): string {
  return path.join(root, 'dist', kind === 'chromium' ? 'brave' : 'firefox');
}

interface TestFixtures {
  kind: BrowserKind;
  edge: FakeEdge;
  targets: Targets;
  ext: Session;
  /** Extra Firefox prefs for a test (`test.use`). */
  firefoxPrefs: Record<string, string | number | boolean>;
  /** The unpacked extension to load (default: the build for the browser). */
  extensionDir: string | null;
}

interface WorkerFixtures {
  certs: TestCerts;
}

export const test = base.extend<TestFixtures, WorkerFixtures>({
  certs: [
    // eslint-disable-next-line no-empty-pattern -- Playwright reads fixture dependencies from the pattern.
    async ({}, use) => {
      const ip = localIpv4();
      const certs = makeCerts(ip === null ? [] : [ip]);
      await use(certs);
      rmSync(certs.dir, { recursive: true, force: true });
    },
    { scope: 'worker' },
  ],
  firefoxPrefs: [{}, { option: true }],
  extensionDir: [null, { option: true }],
  kind: async ({ browserName }, use) => {
    await use(browserName === 'chromium' ? 'chromium' : 'firefox');
  },
  edge: async ({ certs }, use) => {
    const edge = await new FakeEdge(certs.edge).start();
    await use(edge);
    await edge.close();
  },
  targets: async ({ certs, edge }, use) => {
    const targets = await new Targets(certs, (ip) => edge.ipAllowed(ip)).start();
    edge.onAllowsChanged = () => {
      void targets.syncGate();
    };
    await use(targets);
    await targets.close();
  },
  ext: async ({ kind, certs, edge, targets, firefoxPrefs, extensionDir }, use, testInfo) => {
    const session = await launch({
      kind,
      extensionDir: extensionDir ?? distOf(kind),
      certs,
      dohUrl: edge.dohUrl,
      markerUrl: targets.url('marker.test', '/marker'),
      firefoxPrefs,
    });
    testInfo.annotations.push({ type: 'browser', description: `${kind} ${session.version}` });
    await use(session);
    await session.close();
  },
});

/**
 * Sets the extension up as a user does: options → edge URL → Save and test; with `detection`,
 * turns blocked sub-resource detection on, and on Chromium restarts the browser as the options
 * page then asks (`restart: false` leaves that to the test).
 */
export async function setUp(ext: Session, edge: FakeEdge, opts: { coreUrl?: string; detection?: boolean; restart?: boolean } = {}): Promise<void> {
  await ext.preGrant('https://127.0.0.1/*');
  const options = await ext.openExtensionTab('options.html');
  const page = options.surface();
  // Initial getState populates these inputs asynchronously after navigation completes.
  // Wait for it before typing so it cannot replace the URL before Save.
  await page.waitFor(() => document.querySelector('#settings-status')?.textContent || false, null);
  await page.fill('#edge-url', edge.origin);
  await page.fill('#core-url', opts.coreUrl ?? '');
  await page.click('#save');
  await page.waitFor(() => document.querySelector('#settings-status')?.textContent.startsWith('Connected.') === true && document.querySelector('#settings-status')?.textContent, null);
  if (opts.detection === true) {
    await ext.preGrant('<all_urls>');
    await page.click('#detection');
    const status = await page.waitFor(() => document.querySelector('#detection-status')?.textContent.startsWith('On') === true && document.querySelector('#detection-status')?.textContent, null);
    if (ext.kind === 'chromium') {
      // Chromium passes webRequest events for access granted at run time only after a restart.
      expect(status).toBe(DETECTION_ON_AFTER_RESTART);
      if (opts.restart !== false) {
        await ext.restart();
      } else {
        await ext.reopenObserver();
      }
    } else {
      expect(status).toBe(DETECTION_ON);
      // The observer gets the webRequest namespace the permission added.
      await ext.reopenObserver();
    }
  }
}

/** Polls `fn` until it returns a truthy value. */
export async function eventually<R>(what: string, fn: () => R | Promise<R>, timeoutMs = WAIT_MS): Promise<R> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const v = await fn();
    if (v) {
      return v;
    }
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${what}`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
}
