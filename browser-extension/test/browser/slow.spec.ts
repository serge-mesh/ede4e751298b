// Opt-in slow tests (`npm run test:browser:slow`; not in CI), each a minute or more:
//
// - Edge-style timing (X1): the block's TTL and `retry_after_s` as the edge sets them
//   (retry_after_s = block time + max(60 s, TTL + 5 s) − now; apps/picket-edge bypass `retry_after`),
//   with no stale answer faked: the browser's own cache must not serve the blocked answer once
//   the block page has waited retry_after_s, so the page works by retry_after_s + 2 s (the
//   extension's second attempt) at the latest. Negative answers with the default TTL (10 s) and
//   a long one (90 s), and a custom_ip sinkhole's positive answer (127.0.0.2, where nothing
//   listens) with a long TTL.
// - An idle background (X2): the background script unloads after ~30 s idle (Brave's worker,
//   Firefox's event page); a blocked load must wake it and still get the block page.

import type { BlockMode } from './harness/edge';
import { expect, setUp, test } from './harness/fixtures';
import { scaled } from './harness/time';

test.describe.configure({ mode: 'parallel' });

const isBlockPage = (base: string) => (url: string): boolean => url.startsWith(`${base}block.html`);

const cases: { name: string; mode: BlockMode; ttl: number }[] = [
  { name: 'nx10.test', mode: { type: 'nxdomain' }, ttl: 10 },
  { name: 'nx90.test', mode: { type: 'nxdomain' }, ttl: 90 },
  { name: 'sink10.test', mode: { type: 'custom_ip', ip: '127.0.0.2' }, ttl: 10 },
  { name: 'sink90.test', mode: { type: 'custom_ip', ip: '127.0.0.2' }, ttl: 90 },
];

for (const c of cases) {
  test(`with the edge's TTL and retry_after_s (${c.mode.type}, TTL ${String(c.ttl)} s) the page works by retry_after_s + 2 s`, { tag: '@slow' }, async ({ ext, edge, targets }) => {
    test.setTimeout(scaled(240_000));
    await setUp(ext, edge);
    edge.blockTtl = c.ttl;
    edge.edgeRetry = true;
    edge.block(c.name, { mode: c.mode, bundle: 'slow' });
    const tab = await ext.newTab();
    // After the allow the name resolves to the site (127.0.0.1).
    const url = targets.url(c.name, '/');
    await tab.goto(url);
    await tab.waitForUrl(isBlockPage(ext.base));
    const page = tab.surface();
    await page.click('#durations button');
    // Recorded either way, so a failure shows what the browser did.
    const loaded = await tab
      .waitForUrl((u) => u === url, 200_000)
      .then(() => tab.surface().waitFor((want) => document.querySelector('#loaded')?.textContent === want, `${c.name}/`, 15_000))
      .then(() => true, () => false);
    const done = Date.now();

    const patch = edge.apiCalls('PATCH')[0];
    const t0 = patch?.at ?? 0;
    // As the fake edge served it: block time (its last blocked answer, HTTPS-record queries
    // included) + max(60 s, TTL + 5 s) − now.
    const retryAfter = (patch?.reply as { retry_after_s?: number }[] | undefined)?.find((a) => a.retry_after_s !== undefined)?.retry_after_s ?? -1;
    expect(retryAfter).toBeGreaterThan(50);
    const s = (at: number): string => `${((at - t0) / 1000).toFixed(1)} s`;
    const loads = (await ext.navEvents()).filter((e) => e.tabId === tab.id && e.frameId === 0 && e.url === url && e.at > t0 && e.event !== 'onCommitted');
    // When the browser first asked the edge again and got the unblocked answer.
    const fresh = edge.lookups(c.name).find((h) => h.at > t0 && h.qtype === 1 && h.blocked === false)?.at;
    const note =
      `${ext.kind}: retry_after_s ${String(retryAfter)} s; ` +
      loads.map((e) => `${e.event.replace(/^on/, '')} ${s(e.at)}${e.error === undefined ? '' : ` (${e.error})`}`).join(', ') +
      `; fresh answer ${fresh === undefined ? 'none' : s(fresh)}; page ${s(done)}`;
    test.info().annotations.push({ type: 'edge timing', description: note });
    console.log(note);
    // The block page waited retry_after_s before reloading; the browser's cache then let it ask the
    // edge again by retry_after_s + 2 s (the extension's second attempt), plus a load's slack.
    expect(loaded, note).toBe(true);
    const firstLoad = loads.find((e) => e.event === 'onBeforeNavigate')?.at ?? 0;
    expect((firstLoad - t0) / 1000).toBeGreaterThanOrEqual(retryAfter - 1);
    expect(fresh).toBeDefined();
    expect(((fresh ?? 0) - firstLoad) / 1000).toBeLessThanOrEqual(2 + 1.5);
  });
}

test('a blocked load after the background went idle wakes it and gets the block page', { tag: '@slow' }, async ({ ext, edge, targets }) => {
  test.setTimeout(scaled(240_000));
  await setUp(ext, edge);
  const tab = await ext.newTab();
  for (let i = 0; i < 2; i++) {
    await ext.idleBackground(35_000);
    const name = `idle${String(i)}.test`;
    edge.block(name, { mode: { type: 'nxdomain' }, bundle: 'idle' });
    const url = targets.url(name, '/');
    const start = Date.now();
    await tab.goto(url);
    await tab.waitForUrl((u) => isBlockPage(ext.base)(u) && decodeURIComponent(u).includes(url), 20_000);
    const note = `${ext.kind}: block page ${String(Date.now() - start)} ms after a load with the background stopped`;
    test.info().annotations.push({ type: 'idle wake-up', description: note });
    console.log(note);
  }
});
