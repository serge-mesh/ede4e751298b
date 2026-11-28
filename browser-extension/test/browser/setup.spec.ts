// Setup (browser-extension.md §2): the options page the extension opens on install, the edge URL
// checks, the host permission request and the test `GET /v1/temporary-allows`.

import { request } from 'node:https';

import { expect, test } from './harness/fixtures';

/** A request to the fake edge from this process (not a browser), with the headers given. */
function call(url: string, method: string, headers: Record<string, string>, ca: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const r = request(url, { method, headers, ca }, (res) => {
      res.resume();
      resolve(res.statusCode ?? 0);
    });
    r.on('error', reject);
    r.end(method === 'PATCH' ? '[]' : undefined);
  });
}

test('the fake edge refuses what the edge refuses: no extension header, a web Origin, a preflight', async ({ edge, certs }) => {
  const url = `${edge.origin}/v1/temporary-allows`;
  const ext = { 'X-Picket-Client': 'extension' };
  expect(await call(url, 'GET', ext, certs.caPem)).toBe(200);
  expect(await call(url, 'GET', { ...ext, Origin: 'chrome-extension://abc' }, certs.caPem)).toBe(200);
  expect(await call(url, 'GET', {}, certs.caPem)).toBe(403);
  expect(await call(url, 'PATCH', { ...ext, Origin: 'https://site.test', 'Content-Type': 'application/json' }, certs.caPem)).toBe(403);
  expect(await call(url, 'OPTIONS', { ...ext, Origin: 'moz-extension://abc' }, certs.caPem)).toBe(403);
});

test('setup asks for the edge URL, gets access to it and tests the bypass API', async ({ ext, edge }) => {
  const options = await ext.installTab();
  const page = options.surface();
  await page.waitFor(() => document.querySelector('#settings-status')?.textContent ?? '', null);
  expect(await page.text('#settings-status')).toBe('Enter the edge API URL to set up the extension.');

  // Only an https: origin is accepted.
  await page.fill('#edge-url', edge.origin.replace('https:', 'http:'));
  await page.click('#save');
  await expect.poll(() => page.text('#settings-status')).toBe('The edge API is served over HTTPS: use an https:// URL.');
  expect(edge.apiCalls()).toHaveLength(0);

  await ext.preGrant('https://127.0.0.1/*');
  await page.fill('#edge-url', edge.origin);
  await page.fill('#core-url', 'https://core.test:8443');
  await page.click('#save');
  await expect.poll(() => page.text('#settings-status')).toBe('Connected. The edge lists 0 active temporary allows for this device.');

  const [call] = edge.apiCalls('GET');
  expect(call?.client).toBe('extension');
  expect(call?.cookie).toBeUndefined();
  const state = await ext.observer.run(async (pattern) => {
    const c = (globalThis as unknown as { chrome: { permissions: { contains(p: { origins: string[] }): Promise<boolean> }; storage: { local: { get(k: null): Promise<Record<string, unknown>> } } } }).chrome;
    return { granted: await c.permissions.contains({ origins: [pattern] }), stored: await c.storage.local.get(null) };
  }, 'https://127.0.0.1/*');
  expect(state.granted).toBe(true);
  // Only the two URLs are stored (browser-extension.md §4).
  expect(state.stored).toEqual({ edgeUrl: edge.origin, coreUrl: 'https://core.test:8443/' });
});
