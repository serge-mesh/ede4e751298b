// The popup (browser-extension.md §3 step 5): with blocked sub-resource detection on, this tab's
// blocked hosts (DNS and firewall), allowed together for a chosen time, and the device's active
// allows, each with End now. On Brave the detection works from the browser's next start (the
// options page says so), so the Chromium run restarts the browser after turning it on.
//
// The popup page opens in a background tab next to the page, so it reads the page's tab as the
// active one, as the toolbar popup does (Playwright can't open the toolbar popup in either browser).

import type { ExtGlobal } from './harness/browsers';
import { DETECTION_ON_AFTER_RESTART } from '../../src/shared/permissions';
import { eventually, expect, setUp, test, type Session, type Surface, type Tab } from './harness/fixtures';

function badge(ext: Session, tab: Tab): Promise<string> {
  return ext.observer.run((tabId) => (globalThis as unknown as ExtGlobal).chrome.action.getBadgeText({ tabId }), tab.id);
}

/** The rows of a popup list: each row's target and muted text. */
function rows(popup: Surface, list: string): Promise<[string, string][]> {
  return popup.run(
    (sel) => [...document.querySelectorAll(`${sel} li`)].filter((li) => !li.classList.contains('empty')).map((li): [string, string] => [li.querySelector('.target')?.textContent ?? '', li.querySelector('.muted')?.textContent ?? '']),
    list,
  );
}

test('the popup lists blocked sub-resources, allows them, and ends allows', async ({ ext, edge, targets }) => {
  await setUp(ext, edge, { detection: true });
  const news = edge.addAllow({ kind: 'dns', target: 'news.test', expires_at: Math.floor(Date.now() / 1000) + 3600 });
  edge.block('tracker.test', { mode: { type: 'nxdomain' }, bundle: 'trackers' });
  const ipt = targets.ipTargets;
  const srcs = [targets.url('tracker.test', '/pixel.png'), targets.url('cdn.test', '/pixel.png')];
  if (ipt !== null) {
    edge.firewall.add(ipt.ip);
    srcs.push(`http://${ipt.ip}:${String(ipt.gate)}/pixel.png`);
  }
  const tab = await ext.newTab();
  const pageUrl = targets.url('site.test', `/subresources?${srcs.map((u) => `src=${encodeURIComponent(u)}`).join('&')}`);
  await tab.goto(pageUrl);
  const blocked = ipt === null ? 1 : 2;
  await eventually('the badge to count the blocked hosts', async () => (await badge(ext, tab)) === String(blocked));

  const popup = await ext.openPopup(tab);
  await popup.waitFor((n) => document.querySelectorAll('#blocks li').length === n, blocked);
  const listed = await rows(popup, '#blocks');
  expect(listed).toContainEqual(['tracker.test', 'bundle trackers']);
  if (ipt !== null) {
    expect(listed).toContainEqual([ipt.ip, 'firewall']);
  }
  await popup.waitFor(() => document.querySelector('#allows .target') !== null, null);
  expect((await rows(popup, '#allows')).map((r) => r[0])).toEqual(['news.test']);

  // Allow the tracker for 1 hour.
  const index = listed.findIndex((r) => r[0] === 'tracker.test') + 1;
  await popup.click(`#blocks li:nth-child(${String(index)}) input[type=checkbox]`);
  await popup.select('#duration', '3600');
  await popup.click('#allow-selected');
  await expect.poll(() => popup.text('#blocks-status')).toMatch(/^Allowed\. Reload the page in 1 s/);
  const call = edge.apiCalls('PATCH')[0];
  const patch = call?.body as { block_id?: string; expires_at: number }[];
  expect(patch).toHaveLength(1);
  expect(patch[0]?.block_id).toMatch(/^[a-z2-7]{8}$/);
  // From the edge's time at the PATCH (this machine's clock is the edge's here).
  expect(Math.abs((patch[0]?.expires_at ?? 0) - (Math.floor((call?.at ?? 0) / 1000) + 3600))).toBeLessThanOrEqual(2);
  expect(call?.origin).toBe(ext.base.replace(/\/$/, ''));
  await expect.poll(async () => (await rows(popup, '#allows')).map((r) => r[0]).sort()).toEqual(['news.test', 'tracker.test']);

  // End the older allow now.
  const allows = await rows(popup, '#allows');
  const newsRow = allows.findIndex((r) => r[0] === 'news.test') + 1;
  await popup.click(`#allows li:nth-child(${String(newsRow)}) button`);
  await expect.poll(async () => (await rows(popup, '#allows')).map((r) => r[0])).toEqual(['tracker.test']);
  expect(edge.apiCalls('PATCH')[1]?.body).toEqual([{ allow_id: news.allow_id, expires_at: 0 }]);

  // Reload the page once the browser dropped the blocked answer (retry_after_s, as the popup
  // says): the tracker loads now; only the firewall block is listed again.
  await new Promise((r) => setTimeout(r, edge.retryAfterS * 1000 + 500));
  const since = Date.now();
  await popup.click('#blocks-status button');
  await eventually('the page to reload', async () => (await ext.navEvents()).some((e) => e.tabId === tab.id && e.event === 'onCompleted' && e.frameId === 0 && e.url === pageUrl && e.at >= since));
  await eventually('the badge to count what is still blocked', async () => (await badge(ext, tab)) === (ipt === null ? '' : '1'));
  expect(await tab.surface().run(() => [...document.images].map((i) => i.naturalWidth), null)).toEqual(ipt === null ? [1, 1] : [1, 1, 0]);
});

test('until Brave restarts, detection sees nothing and the popup says so; Firefox detects at once', async ({ ext, edge, targets, kind }) => {
  await setUp(ext, edge, { detection: true, restart: false });
  edge.block('tracker.test', { mode: { type: 'nxdomain' }, bundle: 'trackers' });
  const load = async (): Promise<Tab> => {
    const tab = await ext.newTab();
    await tab.goto(targets.url('site.test', `/subresources?src=${encodeURIComponent(targets.url('tracker.test', '/pixel.png'))}`));
    await tab.surface().waitFor(() => document.readyState === 'complete' && document.images[0]?.complete === true, null);
    return tab;
  };
  let tab = await load();
  if (kind === 'firefox') {
    await eventually('the badge', async () => (await badge(ext, tab)) === '1');
    const popup = await ext.openPopup(tab);
    expect(await rows(popup, '#blocks')).toEqual([['tracker.test', 'bundle trackers']]);
    expect(await popup.visible('#blocks-hint')).toBe(false);
    return;
  }
  // Chromium reports no webRequest events for access granted at run time: nothing is detected,
  // and the popup gives the options page's reason rather than an empty list.
  await new Promise((r) => setTimeout(r, 1500));
  expect(await badge(ext, tab)).toBe('');
  expect(edge.probes().filter((p) => p.name === 'tracker.test')).toEqual([]);
  let popup = await ext.openPopup(tab);
  expect(await popup.text('#blocks-hint')).toBe(DETECTION_ON_AFTER_RESTART);
  expect(await rows(popup, '#blocks')).toEqual([]);
  // After the restart it detects, and the popup lists the block.
  await ext.restart();
  tab = await load();
  await eventually('the badge after the restart', async () => (await badge(ext, tab)) === '1');
  popup = await ext.openPopup(tab);
  expect(await rows(popup, '#blocks')).toEqual([['tracker.test', 'bundle trackers']]);
});
