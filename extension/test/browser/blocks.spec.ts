// Block detection and the block page (browser-extension.md §3 steps 1–4, §5): a blocked page
// load is probed over DoH (a PTR probe for an IP literal), the block page opens in the tab with
// what the EDE says, an allow is a PATCH of the bypass API, and the page reloads once the edge's
// retry_after_s has passed (and once more 2 s later if that fails). Also: refusals and other
// errors, failures that aren't blocks, history, the time from allow to a working page, and the
// share of blocked loads that get the block page.

import type { BlockMode, FakeEdge, Hit } from './harness/edge';
import { eventually, expect, setUp, test, type Session, type Tab } from './harness/fixtures';
import type { Targets } from './harness/targets';
import { scaled } from './harness/time';

const isBlockPage = (ext: Session) => (url: string): boolean => url.startsWith(`${ext.base}block.html`);

/** The block page's detail rows, as [term, value] pairs. */
async function details(tab: Tab): Promise<[string, string][]> {
  return tab.surface().run(() => {
    const dts = [...document.querySelectorAll('#details dt')];
    return dts.map((dt): [string, string] => [dt.textContent, dt.nextElementSibling?.textContent ?? '']);
  }, null);
}

/** Waits for the original page to load in the tab after an allow. */
async function waitForPage(tab: Tab, url: string, timeoutMs = scaled(20_000)): Promise<void> {
  await tab.waitForUrl((u) => u === url, timeoutMs);
  await tab.surface().waitFor((want) => document.readyState === 'complete' && document.querySelector('#loaded')?.textContent === want, `${new URL(url).hostname}${new URL(url).pathname}`, timeoutMs);
}

/**
 * How far an allow's `expires_at` is from the edge's time at its PATCH plus `seconds`: the
 * extension computes it from the edge's clock just before sending (this machine's clock is the
 * edge's here), so it's compared with when the PATCH arrived, not with a later clock.
 */
function expiryError(patch: Hit | undefined, expiresAt: number | undefined, seconds: number): number {
  return Math.abs((expiresAt ?? 0) - (Math.floor((patch?.at ?? 0) / 1000) + seconds));
}

/** The Origin each browser's background sends: its extension origin. */
const extensionOrigin = (ext: Session): string => ext.base.replace(/\/$/, '');

test.describe('block page', () => {
  test('a DNS block: probe, block page, 15 min allow, reload', async ({ ext, edge, targets }) => {
    await setUp(ext, edge, { coreUrl: 'https://core.test:8443' });
    edge.block('ads.test', { mode: { type: 'nxdomain' }, bundle: 'ads & trackers', head: '42' });
    const tab = await ext.newTab();
    const url = targets.url('ads.test', '/page?q=1');
    await tab.goto(url);
    await tab.waitForUrl(isBlockPage(ext));

    // The probe: DoH from the background with the extension header, for the name, type A.
    const probe = edge.probes().find((p) => p.name === 'ads.test');
    expect(probe?.qtype).toBe(1);
    expect(probe?.blocked).toBe(true);
    expect(probe?.cookie).toBeUndefined();

    const page = tab.surface();
    await page.waitFor(() => document.querySelector('#durations button') !== null, null);
    expect(await page.text('#title')).toBe('Picket blocked this site');
    const rows = await details(tab);
    expect(rows.slice(0, 2)).toEqual([
      ['Name', 'ads.test'],
      ['Bundle', 'ads & trackers (version 42)'],
    ]);
    expect(rows[2]?.[0]).toBe('Block ID');
    const blockId = rows[2]?.[1] ?? '';
    expect(blockId).toMatch(/^[a-z2-7]{8}$/);
    expect(await page.run(() => [...document.querySelectorAll('#durations button')].map((b) => b.textContent), null)).toEqual(['15 min', '1 hour', '8 hours', '24 hours']);
    expect(await page.visible('#core')).toBe(true);
    expect(await page.text('#subdomains-label')).toBe('Also allow subdomains of ads.test');

    const clicked = Date.now();
    await page.click('#durations button');
    await waitForPage(tab, url);
    const ms = Date.now() - clicked;
    test.info().annotations.push({ type: 'allow → working page', description: `${String(ms)} ms (retry_after_s ${String(edge.retryAfterS)} s)` });
    console.log(`${ext.kind} ${ext.version}: allow → working page in ${String(ms)} ms (retry_after_s ${String(edge.retryAfterS)} s)`);

    const [patch] = edge.apiCalls('PATCH');
    expect(patch?.client).toBe('extension');
    // The edge refuses any Origin but an extension's; each browser sends its own.
    expect(patch?.origin).toBe(extensionOrigin(ext));
    const body = patch?.body as { block_id: string; expires_at: number }[];
    expect(body).toHaveLength(1);
    expect(body[0]?.block_id).toBe(blockId);
    // expires_at = the edge's now + 15 min.
    expect(expiryError(patch, body[0]?.expires_at, 900)).toBeLessThanOrEqual(2);
    expect(body[0]).not.toHaveProperty('subdomains');
    expect(edge.activeAllows().map((a) => a.target)).toEqual(['ads.test']);
  });

  test('the second attempt 2 s later when the first reload still gets the blocked answer', async ({ ext, edge, targets }) => {
    await setUp(ext, edge);
    // One more blocked answer after the allow, as a browser's stale cached answer would be.
    edge.block('stale.test', { mode: { type: 'nxdomain' }, bundle: 'ads', staleAfterAllow: 1 });
    const tab = await ext.newTab();
    const url = targets.url('stale.test', '/');
    await tab.goto(url);
    await tab.waitForUrl(isBlockPage(ext));
    const page = tab.surface();
    await page.click('#subdomains');
    const clicked = Date.now();
    await page.click('#durations button:nth-child(2)');
    await waitForPage(tab, url);
    const ms = Date.now() - clicked;
    console.log(`${ext.kind}: allow → working page with one stale answer in ${String(ms)} ms`);
    // The reload got the blocked answer, then a second load the page; no second block page.
    // On Firefox the second load is the extension's attempt 2 s after the failure. On Chromium
    // the error page starts the failed URL again by itself about 1 s after it, which loads the
    // page first (this test passes on Chromium without the extension's attempt; not on Firefox).
    const after = edge.lookups('stale.test').filter((h) => h.at > clicked && h.qtype === 1);
    expect(after.map((h) => h.blocked)).toEqual([true, false]);
    const gap = (after[1]?.at ?? 0) - (after[0]?.at ?? 0);
    if (ext.kind === 'firefox') {
      expect(gap).toBeGreaterThanOrEqual(1900);
    }
    const blockPages = (await ext.navEvents()).filter((e) => e.tabId === tab.id && e.frameId === 0 && e.event === 'onCommitted' && isBlockPage(ext)(e.url) && e.at > clicked);
    expect(blockPages).toEqual([]);
    const patch = edge.apiCalls('PATCH')[0];
    const body = patch?.body as { subdomains?: boolean; expires_at: number }[];
    expect(body[0]?.subdomains).toBe(true);
    expect(expiryError(patch, body[0]?.expires_at, 3600)).toBeLessThanOrEqual(2);
  });

  test('an IP literal blocked by the firewall: PTR probe, block page, allow, reload', async ({ ext, edge, targets }) => {
    const ipt = targets.ipTargets;
    test.skip(ipt === null, 'needs a non-loopback IPv4 address on this machine');
    if (ipt === null) {
      return;
    }
    await setUp(ext, edge);
    edge.firewall.add(ipt.ip);
    const tab = await ext.newTab();
    const url = `http://${ipt.ip}:${String(ipt.gate)}/admin`;
    await tab.goto(url);
    await tab.waitForUrl(isBlockPage(ext));
    const probe = edge.probes().find((p) => p.qtype === 12);
    expect(probe?.name).toBe(ipt.ip.split('.').reverse().join('.') + '.in-addr.arpa');
    const page = tab.surface();
    await page.waitFor(() => document.querySelector('#durations button') !== null, null);
    expect(await page.text('#title')).toBe("Picket's firewall blocked this address");
    expect(await details(tab)).toEqual([
      ['IP', ipt.ip],
      ['Stage', 'firewall'],
    ]);
    expect(await page.visible('#note')).toBe(true);
    expect(await page.visible('#subdomains-row')).toBe(false);
    // No core URL set: no "Allow permanently…".
    expect(await page.visible('#core')).toBe(false);
    await page.click('#durations button:nth-child(2)');
    await waitForPage(tab, url);
    const patch = edge.apiCalls('PATCH')[0];
    const body = patch?.body as { ip: string; expires_at: number }[];
    expect(body.map((e) => e.ip)).toEqual([ipt.ip]);
    expect(expiryError(patch, body[0]?.expires_at, 3600)).toBeLessThanOrEqual(2);
    expect(patch?.origin).toBe(extensionOrigin(ext));
  });

  test('a refused allow offers only an admin or core UI; another error offers Retry', async ({ ext, edge, targets }) => {
    await setUp(ext, edge, { coreUrl: 'https://core.test:8443/ui' });
    edge.block('kids.test', { mode: { type: 'nxdomain' }, lookup: 'safe-browsing', verdict: 'adult' });
    edge.block('busy.test', { mode: { type: 'refused' }, bundle: 'misc' });
    edge.patchErrors.push({ status: 403, code: 'forbidden', message: 'bypass is off for this profile' });

    const tab = await ext.newTab();
    await tab.goto(targets.url('kids.test', '/'));
    await tab.waitForUrl(isBlockPage(ext));
    let page = tab.surface();
    await page.waitFor(() => document.querySelector('#durations button') !== null, null);
    expect((await details(tab)).slice(0, 3)).toEqual([
      ['Name', 'kids.test'],
      ['Lookup provider', 'safe-browsing'],
      ['Verdict', 'adult'],
    ]);
    await page.click('#durations button');
    await expect.poll(() => page.text('#status')).toBe('The edge refused: bypass is off for this profile. Ask an admin, or open core’s UI.');
    expect(await page.visible('#choose')).toBe(false);
    expect(await page.visible('#retry')).toBe(false);
    expect(await page.text('#core')).toBe('Open core UI');

    edge.patchErrors.push({ status: 503, code: 'clock', message: 'clock not synchronised' });
    const url = targets.url('busy.test', '/');
    await tab.goto(url);
    await tab.waitForUrl((u) => isBlockPage(ext)(u) && u.includes('busy.test'));
    page = tab.surface();
    await page.waitFor(() => document.querySelector('#durations button') !== null, null);
    await page.click('#durations button');
    await expect.poll(() => page.text('#status')).toBe("The edge's clock isn't synchronised yet; try again shortly.");
    await page.click('#retry');
    await waitForPage(tab, url);
    expect(edge.apiCalls('PATCH').map((c) => c.status)).toEqual([403, 503, 200]);
  });

  test('failures that are not blocks get no block page', async ({ ext, edge, targets }) => {
    await setUp(ext, edge);
    const tab = await ext.newTab();
    // A name that doesn't exist (no block): probed, the edge has no block for it.
    const gone = targets.url('gone.example', '/');
    await tab.goto(gone);
    await eventually('the probe of gone.example', () => edge.probes().some((p) => p.name === 'gone.example'));
    // A redirect loop: no block mode causes it, so no probe either.
    const loop = targets.url('loop.test', '/loop');
    await tab.goto(loop);
    await eventually('the redirect loop to fail', async () => (await ext.navEvents()).some((e) => e.tabId === tab.id && e.url.includes('loop.test') && e.event === 'onErrorOccurred'));
    await new Promise((r) => setTimeout(r, 1500));
    // The browser's error page stays (Chromium shows it as chrome-error://chromewebdata/).
    expect(isBlockPage(ext)(await tab.url())).toBe(false);
    expect((await ext.navEvents()).some((e) => e.tabId === tab.id && isBlockPage(ext)(e.url))).toBe(false);
    expect(edge.probes().map((p) => p.name)).toEqual(['gone.example']);
  });

  test("Go back skips the failed load (Firefox replaces it, Chromium goes back two)", async ({ ext, edge, targets }) => {
    await setUp(ext, edge);
    edge.block('back.test', { mode: { type: 'nxdomain' } });
    const tab = await ext.newTab();
    const before = await tab.url();
    const entries = await tab.surface().run(() => history.length, null);
    await tab.goto(targets.url('back.test', '/'));
    await tab.waitForUrl(isBlockPage(ext));
    const page = tab.surface();
    expect(await page.waitFor(() => new URLSearchParams(location.search).get('replaced') ?? 'absent', null)).toBe(ext.kind === 'firefox' ? '1' : 'absent');
    // The page before is still in history: on Firefox right before the block page (the failed load
    // left no entry), on Chromium two back, behind the failed entry. (Firefox lost it when the
    // probe beat the error page's commit, and kept the failed entry when its commit came late.)
    expect(await page.run(() => history.length, null)).toBe(entries + (ext.kind === 'firefox' ? 1 : 2));
    await page.click('#back');
    await tab.waitForUrl((u) => u === before);
  });
});

/** The block modes the rate test cycles through, with the URL each fails on. */
function modes(t: Targets): { mode: BlockMode; url: (name: string) => string }[] {
  const l = t.local;
  const http = (port: number) => (name: string): string => `http://${name}:${String(port)}/`;
  const https = (port: number) => (name: string): string => `https://${name}:${String(port)}/`;
  const cip = { type: 'custom_ip', ip: '127.0.0.1' } as const;
  return [
    { mode: { type: 'nxdomain' }, url: http(l.web) },
    { mode: { type: 'nodata' }, url: http(l.web) },
    { mode: { type: 'refused' }, url: http(l.web) },
    { mode: { type: 'null_ip' }, url: http(l.refused) },
    { mode: cip, url: http(l.reset) },
    { mode: cip, url: http(l.close) },
    { mode: cip, url: https(l.tlsAbort) },
    { mode: cip, url: https(l.tlsUntrusted) },
  ];
}

function blockNames(edge: FakeEdge, t: Targets, n: number): string[] {
  const list = modes(t);
  const urls: string[] = [];
  for (let i = 0; i < n; i++) {
    const m = list[i % list.length];
    if (m === undefined) {
      continue;
    }
    const name = `load${String(i)}.test`;
    edge.block(name, { mode: m.mode, bundle: 'rate' });
    urls.push(m.url(name));
  }
  return urls;
}

// Every one of `PICKET_BROWSER_LOADS` (24) blocked loads must get the block page. 24 of 24
// bounds the miss rate below about 12 % (95 % confidence), not 1 %: that takes about 300 loads.
test('the block page appears for every blocked page load that fails', async ({ ext, edge, targets }) => {
  const n = Number(process.env.PICKET_BROWSER_LOADS ?? '24');
  test.setTimeout(scaled(60_000 + n * 6_000));
  await setUp(ext, edge);
  const urls = blockNames(edge, targets, n);
  const ipt = targets.ipTargets;
  if (ipt !== null) {
    edge.firewall.add(ipt.ip);
  }
  const tab = await ext.newTab();
  let shown = 0;
  const missed: string[] = [];
  for (const [i, url] of urls.entries()) {
    // Every eighth load is an IP literal behind the firewall, when this machine has one.
    const target = ipt !== null && i % 8 === 7 ? `http://${ipt.ip}:${String(ipt.gate)}/n${String(i)}` : url;
    await tab.goto(target);
    const ok = await tab
      .waitForUrl((u) => isBlockPage(ext)(u) && decodeURIComponent(u).includes(target), scaled(10_000))
      .then(() => true, () => false);
    if (ok) {
      shown += 1;
    } else {
      missed.push(target);
    }
  }
  test.info().annotations.push({ type: 'block page shown', description: `${String(shown)}/${String(urls.length)}` });
  console.log(`${ext.kind}: block page for ${String(shown)}/${String(urls.length)} blocked loads${missed.length > 0 ? `; missed ${missed.join(', ')}` : ''}`);
  expect(missed).toEqual([]);
});
