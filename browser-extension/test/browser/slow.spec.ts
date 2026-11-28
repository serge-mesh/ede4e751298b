// Opt-in slow tests (`npm run test:browser:slow`; not in CI), each a minute or more:
//
// - Edge-style timing (X1): the block's TTL and `retry_after_s` as the edge sets them
//   (retry_after_s = block time + max(65 s, TTL + 5 s) − now; apps/picket-edge bypass `retry_after`),
//   with no stale answer faked: the browser's own cache must not serve the blocked answer once
//   the block page has waited retry_after_s, so the page works by retry_after_s + 2 s (the
//   extension's second attempt) at the latest. Negative answers with the default TTL (10 s) and
//   a long one (90 s), and the sinkholes' positive answers (null_ip's 0.0.0.0, and custom_ip's
//   127.0.0.2, where nothing listens) with both. The page must show its content, not only its URL.
// - The same with Firefox resolving natively (TRR off, issue #51): the system resolver asks the
//   fake edge's plain DNS, so Firefox caches what getaddrinfo gives it, without the wire TTL, for
//   its own fixed lifetime (`network.dnsCacheExpiration`, 60 s, then a grace period in which it
//   serves the old entry while refreshing it). Linux and root only: Firefox runs in a private
//   mount namespace with its own /etc/resolv.conf; skipped elsewhere.
// - An idle background (X2): the background script unloads after ~30 s idle (Brave's worker,
//   Firefox's event page); a blocked load must wake it and still get the block page.

import type { BlockMode, FakeEdge } from './harness/edge';
import { expect, setUp, test, type Session } from './harness/fixtures';
import type { Targets } from './harness/targets';
import { scaled } from './harness/time';

test.describe.configure({ mode: 'parallel' });

const isBlockPage = (base: string) => (url: string): boolean => url.startsWith(`${base}block.html`);

interface Case { name: string; mode: BlockMode; ttl: number }

const cases: Case[] = [
  { name: 'nx10.test', mode: { type: 'nxdomain' }, ttl: 10 },
  { name: 'nx90.test', mode: { type: 'nxdomain' }, ttl: 90 },
  { name: 'null10.test', mode: { type: 'null_ip' }, ttl: 10 },
  { name: 'null90.test', mode: { type: 'null_ip' }, ttl: 90 },
  { name: 'sink10.test', mode: { type: 'custom_ip', ip: '127.0.0.2' }, ttl: 10 },
  { name: 'sink90.test', mode: { type: 'custom_ip', ip: '127.0.0.2' }, ttl: 90 },
];

/** Block, allow at the block page, and check the page loads by retry_after_s + 2 s. */
async function allowRecovers(c: Case, resolver: string, { ext, edge, targets }: { ext: Session; edge: FakeEdge; targets: Targets }): Promise<void> {
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
  // Recorded either way, so a failure shows what the browser did. The site's own content, not
  // only its URL: an error page keeps the URL.
  const loaded = await tab
    .waitForUrl((u) => u === url, 200_000)
    .then(() => tab.surface().waitFor((want) => document.querySelector('#loaded')?.textContent === want, `${c.name}/`, 15_000))
    .then(() => true, () => false);
  const done = Date.now();

  const patch = edge.apiCalls('PATCH')[0];
  const t0 = patch?.at ?? 0;
  // As the fake edge served it: block time (its last blocked answer, HTTPS-record queries
  // included) + max(65 s, TTL + 5 s) − now.
  const retryAfter = (patch?.reply as { retry_after_s?: number }[] | undefined)?.find((a) => a.retry_after_s !== undefined)?.retry_after_s ?? -1;
  expect(retryAfter).toBeGreaterThan(50);
  const s = (at: number): string => `${((at - t0) / 1000).toFixed(1)} s`;
  const loads = (await ext.navEvents()).filter((e) => e.tabId === tab.id && e.frameId === 0 && e.url === url && e.at > t0 && e.event !== 'onCommitted');
  // The browser's queries for the name after the allow, and when it first got the unblocked answer.
  const asked = edge.lookups(c.name).filter((h) => h.at > t0 && h.qtype === 1);
  const fresh = asked.find((h) => h.blocked === false)?.at;
  const note =
    `${ext.kind} (${resolver}): retry_after_s ${String(retryAfter)} s; ` +
    loads.map((e) => `${e.event.replace(/^on/, '')} ${s(e.at)}${e.error === undefined ? '' : ` (${e.error})`}`).join(', ') +
    `; A queries ${asked.map((h) => `${s(h.at)}${h.blocked === true ? ' blocked' : ''}`).join(', ') || 'none'}` +
    `; fresh answer ${fresh === undefined ? 'none' : s(fresh)}; page ${s(done)}`;
  test.info().annotations.push({ type: 'edge timing', description: note });
  console.log(note);
  // The block page waited retry_after_s before reloading; the browser's cache then let it ask the
  // edge again by retry_after_s + 2 s (the extension's second attempt), plus a load's slack.
  expect(loaded, note).toBe(true);
  if (resolver === 'native DNS') {
    // Every lookup went through the system resolver to the plain-DNS listener, none over DoH.
    expect(edge.lookups().every((h) => h.method === 'UDP')).toBe(true);
    expect(edge.lookups().length).toBeGreaterThan(0);
  }
  const firstLoad = loads.find((e) => e.event === 'onBeforeNavigate')?.at ?? 0;
  // The reload comes at retry_after_s, not before and not much after.
  expect((firstLoad - t0) / 1000, note).toBeGreaterThanOrEqual(retryAfter - 1);
  expect((firstLoad - t0) / 1000, note).toBeLessThanOrEqual(retryAfter + 1.5);
  expect(fresh, note).toBeDefined();
  expect(((fresh ?? 0) - firstLoad) / 1000, note).toBeLessThanOrEqual(2 + 1.5);
  // The page works by retry_after_s + 2 s (the second attempt), plus a load's slack.
  expect((done - t0) / 1000, note).toBeLessThanOrEqual(retryAfter + 2 + 3);
}

for (const c of cases) {
  test(`with the edge's TTL and retry_after_s (${c.mode.type}, TTL ${String(c.ttl)} s) the page works by retry_after_s + 2 s`, { tag: '@slow' }, async ({ ext, edge, targets }) => {
    await allowRecovers(c, ext.kind === 'firefox' ? 'TRR' : 'secure DNS', { ext, edge, targets });
  });
}

test.describe('Firefox resolving natively', () => {
  test.use({ nativeDns: true });
  test.skip(({ browserName }) => browserName !== 'firefox', 'Firefox only');
  test.skip(process.platform !== 'linux' || process.getuid?.() !== 0, 'needs Linux and root (a private mount namespace and port 53)');
  for (const c of cases) {
    test(`native DNS: with the edge's TTL and retry_after_s (${c.mode.type}, TTL ${String(c.ttl)} s) the page works by retry_after_s + 2 s`, { tag: '@slow' }, async ({ ext, edge, targets }) => {
      await allowRecovers(c, 'native DNS', { ext, edge, targets });
    });
  }
});

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
