import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { startBlockPage, type BlockPageEnv } from '../src/pages/block';
import { keptUrl, MAX_URL, newRef, serializeKeptUrls, toQuery, type BlockInfo } from '../src/shared/block-info';
import { clockTime } from '../src/pages/dom';
import fake, { BASE, resetFakeBrowser } from './fake-browser';
import { $, background, button, loadPage, state } from './page-kit';

const DNS: BlockInfo = {
  kind: 'dns',
  url: 'https://ads.example/page',
  name: 'ads.example',
  blockId: 'abcdefgh',
  bundle: 'block-common',
  head: '3f2a9c0d11aa22bb',
};
const IP: BlockInfo = { kind: 'ip', url: 'https://100.100.100.100/test', ip: '100.100.100.100' };

/** Monotonic ms the page's countdown reads (moved by tests apart from the timers). */
let mono = 0;

function env(info: BlockInfo | string, over: Partial<BlockPageEnv> = {}) {
  return {
    search: typeof info === 'string' ? info : `?${toQuery(info)}`,
    replace: vi.fn<(url: string) => void>(),
    back: vi.fn<(steps: number) => void>(),
    historyIndex: 5,
    openTab: vi.fn<(url: string) => Promise<void>>(async () => undefined),
    keptUrl: (id: string) => keptUrl(fake.storage.session, id),
    now: () => mono,
    ...over,
  } satisfies BlockPageEnv;
}

const allowed = (over: Record<string, unknown> = {}, skewMs = 0) => {
  const a = { allow_id: 'a-1', kind: 'dns', target: 'ads.example', expires_at: Math.floor(Date.now() / 1000) + 3600, retry_after_s: 3, ...over };
  return { ok: true, value: { allows: [a], created: [a], requestedUntil: Math.floor(Date.now() / 1000) + 3600, skewMs } };
};

beforeEach(() => {
  resetFakeBrowser();
  fake.sender = { url: `${BASE}block.html`, tabId: 12 };
  loadPage('block');
  vi.useFakeTimers();
  mono = 0;
});
afterEach(() => {
  vi.useRealTimers();
});

const status = (): string => $('status').textContent;

describe('the block page', () => {
  it('shows a DNS block: name, bundle and version, as text', async () => {
    background({ getState: () => state() });
    await startBlockPage(env(DNS));
    expect(document.title).toBe('Blocked: ads.example');
    const details = [...document.querySelectorAll('#details dt, #details dd')].map((e) => e.textContent);
    expect(details).toEqual(['Name', 'ads.example', 'Bundle', 'block-common (version 3f2a9c0d11aa22bb)', 'Block ID', 'abcdefgh']);
    expect([...document.querySelectorAll('#durations button')].map((b) => b.textContent)).toEqual(['15 min', '1 hour', '8 hours', '24 hours']);
    expect($('subdomains-row').hidden).toBe(false);
    expect($('core').hidden).toBe(false);
  });

  it('shows a lookup block with provider and verdict', async () => {
    background({ getState: () => state() });
    await startBlockPage(env({ kind: 'dns', url: 'https://x.example/', name: 'x.example', blockId: 'qrstuvwx', lookup: 'quad9', verdict: 'timeout' }));
    const details = [...document.querySelectorAll('#details dd')].map((e) => e.textContent);
    expect(details).toEqual(['x.example', 'quad9', 'timeout', 'qrstuvwx']);
  });

  it('shows names and EXTRA-TEXT values only as text', async () => {
    background({ getState: () => state() });
    await startBlockPage(
      env({ ...DNS, name: '<img src=x onerror=alert(1)>.example', bundle: '<script>alert(1)</script>', head: 'a‮b' }),
    );
    expect(document.querySelector('img[src=x]')).toBeNull();
    expect(document.querySelector('#details script')).toBeNull();
    expect($('details').textContent).toContain('<img src=x onerror=alert(1)>.example');
    expect($('details').textContent).toContain('a\\u{202e}b');
  });

  it('shows an IP block: the IP and the stage firewall', async () => {
    const got = background({ getState: () => state(), createAllows: () => ({ ...allowed({ kind: 'ip', target: '100.100.100.100', retry_after_s: 0 }) }), reloadAfterAllow: () => ({ ok: true, value: null }) });
    await startBlockPage(env(IP));
    const details = [...document.querySelectorAll('#details dt, #details dd')].map((e) => e.textContent);
    expect(details).toEqual(['IP', '100.100.100.100', 'Stage', 'firewall']);
    expect($('note').hidden).toBe(false);
    expect($('subdomains-row').hidden).toBe(true);
    button('15 min').click();
    await vi.waitFor(() => {
      expect(got.map((r) => r.type)).toContain('reloadAfterAllow');
    });
    expect(got.find((r) => r.type === 'createAllows')).toEqual({ type: 'createAllows', durationS: 900, entries: [{ kind: 'ip', ip: '100.100.100.100' }] });
  });

  it('allows for the chosen time, counts down retry_after_s, then reloads the original URL', async () => {
    const got = background({ getState: () => state(), createAllows: () => allowed(), reloadAfterAllow: () => ({ ok: true, value: null }) });
    await startBlockPage(env(DNS));
    $<HTMLInputElement>('subdomains').checked = true;
    button('1 hour').click();
    await vi.waitFor(() => {
      expect(status()).toContain('reloading in 3 s');
    });
    expect(got.find((r) => r.type === 'createAllows')).toEqual({
      type: 'createAllows',
      durationS: 3600,
      entries: [{ kind: 'dns', blockId: 'abcdefgh', name: 'ads.example', subdomains: true }],
    });
    expect($('choose').hidden).toBe(true);
    expect($('lead').textContent).toMatch(/^Allowed until /);
    mono += 2000;
    await vi.advanceTimersByTimeAsync(2000);
    expect(got.some((r) => r.type === 'reloadAfterAllow')).toBe(false);
    mono += 1000;
    await vi.advanceTimersByTimeAsync(1000);
    await vi.waitFor(() => {
      expect(got.at(-1)).toEqual({ type: 'reloadAfterAllow', url: 'https://ads.example/page' });
    });
  });

  it("says when the edge shortened the allow to the profile's limit", async () => {
    const now = Math.floor(Date.now() / 1000);
    background({
      getState: () => state(),
      createAllows: () => {
        const a = { allow_id: 'a-1', kind: 'dns', target: 'ads.example', expires_at: now + 3600, retry_after_s: 0 };
        return { ok: true, value: { allows: [a], created: [a], requestedUntil: now + 86_400, skewMs: 0 } };
      },
      reloadAfterAllow: () => ({ ok: true, value: null }),
    });
    await startBlockPage(env(DNS));
    button('24 hours').click();
    await vi.waitFor(() => {
      expect($('lead').textContent).toContain('shortened');
    });
  });

  it('leaves the page itself when the background cannot reload the tab', async () => {
    background({ getState: () => state(), createAllows: () => allowed({ retry_after_s: 0 }), reloadAfterAllow: () => ({ ok: false, error: { kind: 'request', message: 'x' } }) });
    const e = env(DNS);
    await startBlockPage(e);
    button('15 min').click();
    await vi.waitFor(() => {
      expect(e.replace).toHaveBeenCalledWith('https://ads.example/page');
    });
  });

  it('on 403 offers only "Ask an admin / open core UI"', async () => {
    background({
      getState: () => state(),
      createAllows: () => ({ ok: false, error: { kind: 'forbidden', status: 403, code: 'rate_limited', message: 'rate_per_hour reached' } }),
    });
    const e = env(DNS);
    await startBlockPage(e);
    button('8 hours').click();
    await vi.waitFor(() => {
      expect(status()).toContain('Ask an admin');
    });
    expect(status()).toContain('too many temporary allows');
    expect($('choose').hidden).toBe(true);
    expect($('retry').hidden).toBe(true);
    expect($('core').textContent).toBe('Open core UI');
    $('core').click();
    expect(e.openTab).toHaveBeenCalledWith('https://core.home.arpa:8443/');
  });

  it('on any other error shows it and offers Retry', async () => {
    let calls = 0;
    const got = background({
      getState: () => state(),
      createAllows: () =>
        ++calls === 1
          ? { ok: false, error: { kind: 'unavailable', status: 503, code: 'firewall', message: 'no ack', index: 0 } }
          : allowed({ retry_after_s: 0 }),
      reloadAfterAllow: () => ({ ok: true, value: null }),
    });
    await startBlockPage(env(DNS));
    button('15 min').click();
    await vi.waitFor(() => {
      expect($('retry').hidden).toBe(false);
    });
    expect(status()).toContain("firewall didn't take the allow");
    expect($('choose').hidden).toBe(false);
    $('retry').click();
    await vi.waitFor(() => {
      expect(got.some((r) => r.type === 'reloadAfterAllow')).toBe(true);
    });
    expect(got.filter((r) => r.type === 'createAllows')).toHaveLength(2);
  });

  it('hides "Allow permanently…" without a core URL, and refuses to act when not set up', async () => {
    background({ getState: () => state({ coreUrl: null, edgeUrl: null }) });
    await startBlockPage(env(DNS));
    expect($('core').hidden).toBe(true);
    expect(button('1 hour').disabled).toBe(true);
    expect(status()).toContain('not set up');
  });

  it('refuses a malformed link', async () => {
    background({ getState: () => state() });
    await startBlockPage(env('?kind=dns&url=javascript:alert(1)&name=x&block=abcdefgh'));
    expect($('title').textContent).toBe('Invalid block page');
    expect(document.querySelectorAll('#durations button')).toHaveLength(0);
  });

  it('counts down to a fixed deadline, so a throttled hidden tab still reloads on time', async () => {
    const got = background({ getState: () => state(), createAllows: () => allowed({ retry_after_s: 60 }), reloadAfterAllow: () => ({ ok: true, value: null }) });
    await startBlockPage(env(DNS));
    button('1 hour').click();
    await vi.waitFor(() => {
      expect(status()).toContain('reloading in 1 min');
    });
    // Hidden: 61 s pass while the throttled timers fire just once.
    mono += 61_000;
    await vi.advanceTimersByTimeAsync(500);
    await vi.waitFor(() => {
      expect(got.at(-1)).toEqual({ type: 'reloadAfterAllow', url: 'https://ads.example/page' });
    });
  });

  it('checks the deadline again as soon as the tab is shown', async () => {
    const got = background({ getState: () => state(), createAllows: () => allowed({ retry_after_s: 30 }), reloadAfterAllow: () => ({ ok: true, value: null }) });
    await startBlockPage(env(DNS));
    button('15 min').click();
    await vi.waitFor(() => {
      expect(status()).toContain('reloading in 30 s');
    });
    mono += 31_000;
    document.dispatchEvent(new Event('visibilitychange'));
    // No timer has run: the event alone found the deadline passed.
    expect(status()).toBe('Loading the page…');
    await vi.advanceTimersByTimeAsync(0);
    expect(got.some((r) => r.type === 'reloadAfterAllow')).toBe(true);
  });

  it("shows the allow's end by this device's clock", async () => {
    // The edge's clock is an hour ahead of this device's.
    const edgeEnd = Math.floor(Date.now() / 1000) + 3600 + 3600;
    background({
      getState: () => state(),
      createAllows: () => {
        const a = { allow_id: 'a-1', kind: 'dns', target: 'ads.example', expires_at: edgeEnd, retry_after_s: 0 };
        return { ok: true, value: { allows: [a], created: [a], requestedUntil: edgeEnd, skewMs: 3_600_000 } };
      },
      reloadAfterAllow: () => ({ ok: true, value: null }),
    });
    await startBlockPage(env(DNS));
    button('1 hour').click();
    await vi.waitFor(() => {
      expect($('lead').textContent).toBe(`Allowed until ${clockTime(edgeEnd - 3600)}.`);
    });
  });

  it('shows the error when the edge lists no allow for the block', async () => {
    background({
      getState: () => state(),
      createAllows: () => ({ ok: false, error: { kind: 'not_applied', index: 0, message: 'The edge lists no allow for ads.example, so it is still blocked.' } }),
    });
    await startBlockPage(env(DNS));
    button('15 min').click();
    await vi.waitFor(() => {
      expect(status()).toContain('still blocked');
    });
    expect($('lead').textContent).not.toMatch(/^Allowed/);
    expect($('retry').hidden).toBe(false);
  });

  it('"Go back" skips the failed entry before it (Chromium), or goes one back where it replaced it (Firefox)', async () => {
    background({ getState: () => state() });
    const chromium = env(DNS);
    await startBlockPage(chromium);
    expect($('back').hidden).toBe(false);
    $('back').click();
    expect(chromium.back).toHaveBeenCalledWith(2);

    loadPage('block');
    const firefox = env(`?${toQuery(DNS, { replaced: true })}`, { historyIndex: 1 });
    await startBlockPage(firefox);
    $('back').click();
    expect(firefox.back).toHaveBeenCalledWith(1);

    // Nothing before the failed entry: no "Go back".
    loadPage('block');
    await startBlockPage(env(DNS, { historyIndex: 1 }));
    expect($('back').hidden).toBe(true);
  });

  it('works for a long URL kept by the background, and reloads it after the allow', async () => {
    const long = `https://sso.example/saml?SAMLRequest=${'A'.repeat(20_000)}`;
    const ref = newRef();
    fake.storage.session.data.set('blockUrls', serializeKeptUrls([[4, { id: ref, url: long }]]));
    const got = background({ getState: () => state(), createAllows: () => allowed({ retry_after_s: 0 }), reloadAfterAllow: () => ({ ok: true, value: null }) });
    await startBlockPage(env(`?${toQuery({ ...DNS, url: long }, { ref })}`));
    expect($('title').textContent).toBe('Picket blocked this site');
    button('15 min').click();
    await vi.waitFor(() => {
      expect(got.at(-1)).toEqual({ type: 'reloadAfterAllow', url: long });
    });
  });

  it('still offers the allow for a URL too long to keep, and says to load the page again', async () => {
    const got = background({ getState: () => state(), createAllows: () => allowed({ retry_after_s: 0 }), reloadAfterAllow: () => ({ ok: true, value: null }) });
    await startBlockPage(env(`?${toQuery({ ...DNS, url: `https://x.example/?${'a'.repeat(MAX_URL)}` })}`));
    expect(document.body.textContent).toContain('too long to keep');
    button('15 min').click();
    await vi.waitFor(() => {
      expect(status()).toBe('Allowed. Load the page again.');
    });
    expect(got.some((r) => r.type === 'reloadAfterAllow')).toBe(false);
    // A kept URL dropped since (the tab left its block page) reads the same way.
    loadPage('block');
    background({ getState: () => state() });
    await startBlockPage(env(`?${toQuery({ ...DNS, url: `https://x.example/?${'a'.repeat(5000)}` }, { ref: 'f'.repeat(32) })}`));
    expect(document.body.textContent).toContain('no longer kept');
    expect(document.querySelectorAll('#durations button')).toHaveLength(4);
  });
});
