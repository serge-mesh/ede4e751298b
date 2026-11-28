// The background script wired to the (fake) browser: a failed page load becomes a probe and the
// block page, end to end.

import { afterEach, describe, expect, it, vi } from 'vitest';

import { fromQuery, keptUrl } from '../src/shared/block-info';
import { dnsResponse, qname, queryOf, reply } from './dns-writer';
import { BASE, FakeEvent, type FakeBrowser } from './fake-browser';

const EDGE = 'https://dns.home.arpa:9853';

/**
 * Starts a fresh background script on a fresh fake browser (modules reset, so the script's
 * state starts empty). `before` runs on the fake before the script loads.
 */
async function start(
  respond: (url: string, init: RequestInit) => Response,
  before: (fake: FakeBrowser) => void = () => undefined,
): Promise<{ fake: FakeBrowser; fetch: ReturnType<typeof vi.fn<(url: string, init: RequestInit) => Promise<Response>>> }> {
  const fetch = vi.fn(async (url: string, init: RequestInit) => respond(url, init));
  vi.stubGlobal('fetch', fetch);
  vi.resetModules();
  const fake = (await import('./fake-browser')).default;
  before(fake);
  await import('../src/background/index');
  return { fake, fetch };
}

function configure(fake: FakeBrowser): void {
  fake.storage.local.data.set('edgeUrl', EDGE);
  fake.granted.origins.add('https://dns.home.arpa/*');
}

function grantDetection(fake: FakeBrowser): void {
  fake.granted.permissions.add('webRequest');
  fake.granted.origins.add('<all_urls>');
}

/** The browser's state that outlives the background script (storage, permissions). */
function carryOver(from: FakeBrowser): (to: FakeBrowser) => void {
  return (to) => {
    to.storage.local.data = new Map(from.storage.local.data);
    to.storage.session.data = new Map(from.storage.session.data);
    for (const o of from.granted.origins) {
      to.granted.origins.add(o);
    }
    for (const p of from.granted.permissions) {
      to.granted.permissions.add(p);
    }
  };
}

const blockPageQuery = (fake: FakeBrowser, call = 0): URLSearchParams => {
  const props = fake.tabs.update.mock.calls[call]?.[1] as { url?: string } | undefined;
  return new URL(props?.url ?? '').searchParams;
};

const blocked = (url: string): Response => {
  const q = queryOf(url);
  return dnsResponse(
    reply(
      q,
      qname(q) === 'ads.example'
        ? { answers: [{ type: 1, rdata: [0, 0, 0, 0] }], ede: [{ code: 15, text: 'bundle=block-common@3f2a block=abcdefgh' }, { code: 4, text: '' }] }
        : {},
    ),
  );
};

/** Configures the edge on a fake that reports a Firefox extension URL. */
function firefoxEdge(fake: FakeBrowser): void {
  configure(fake);
  fake.runtime.getURL = (p: string) => `moz-extension://test-uuid/${p.replace(/^\//, '')}`;
}

/**
 * A top-frame load of ads.example that fails on Firefox (its error page not yet committed);
 * `documentId`: the document the failure left, as Firefox reports it.
 */
function failOnFirefox(fake: FakeBrowser, documentId?: string): void {
  fake.webNavigation.onBeforeNavigate.emit({ tabId: 4, frameId: 0, url: 'https://ads.example/page' } as never);
  fake.webNavigation.onErrorOccurred.emit({ tabId: 4, frameId: 0, url: 'https://ads.example/page', error: 'Error code 2152398861', documentId } as never);
}

/** Starts a Firefox background whose tab's top frame shows `frame`, fails a load, and runs out the commit wait. */
async function failAndWait(frame: Parameters<FakeBrowser['webNavigation']['getFrame']['mockResolvedValue']>[0] | Error, documentId?: string): Promise<FakeBrowser> {
  const { fake, fetch } = await start(blocked, (f) => {
    firefoxEdge(f);
    if (frame instanceof Error) {
      f.webNavigation.getFrame.mockRejectedValue(frame);
    } else {
      f.webNavigation.getFrame.mockResolvedValue(frame);
    }
  });
  failOnFirefox(fake, documentId);
  await vi.waitFor(() => {
    expect(fetch).toHaveBeenCalled();
  });
  await vi.advanceTimersByTimeAsync(2_100);
  await vi.waitFor(() => {
    expect(fake.tabs.update).toHaveBeenCalledTimes(1);
  });
  return fake;
}

/** Whether the block page load replaced the tab's entry; asserts it still says Go back goes back one. */
function replacedEntry(fake: FakeBrowser): boolean {
  const [, props] = fake.tabs.update.mock.calls[0]!;
  expect(fromQuery(new URL(props.url ?? '').search)?.replaced).toBe(true);
  return (props as { loadReplace?: boolean }).loadReplace === true;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('background', () => {
  it('opens the setup page on install', async () => {
    const { fake } = await start(() => new Response(''));
    fake.runtime.onInstalled.emit({ reason: 'install' });
    fake.runtime.onInstalled.emit({ reason: 'update' });
    expect(fake.runtime.openOptionsPage).toHaveBeenCalledTimes(1);
  });

  it("on Firefox, waits for the failed load's error page to commit, then replaces it", async () => {
    // The probe answers before the error page commits (and before this script hears of it): the
    // block page waits, then replaces the error page, not the page before it.
    const late = await start(blocked, firefoxEdge);
    failOnFirefox(late.fake);
    await new Promise((r) => setTimeout(r, 100));
    expect(late.fetch).toHaveBeenCalled();
    expect(late.fake.tabs.update).not.toHaveBeenCalled();
    late.fake.webNavigation.onCommitted.emit({ tabId: 4, frameId: 0, url: 'https://ads.example/page' } as never);
    await vi.waitFor(() => {
      expect(late.fake.tabs.update).toHaveBeenCalledTimes(1);
    });
    const [, replace] = late.fake.tabs.update.mock.calls[0]!;
    expect(replace).toMatchObject({ loadReplace: true });
    expect(fromQuery(new URL(replace.url ?? '').search)?.replaced).toBe(true);
    expect(late.fake.webNavigation.getFrame).not.toHaveBeenCalled();
  });

  it("on Firefox, without the commit event, asks the tab's top frame whether the error page committed", async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      // The frame still shows the page before: a plain load, which ends the pending error page,
      // so the failed load leaves no entry either; Go back still goes back one.
      const none = await start(blocked, firefoxEdge);
      failOnFirefox(none.fake);
      await vi.waitFor(() => {
        expect(none.fetch).toHaveBeenCalled();
      });
      await vi.advanceTimersByTimeAsync(1_900);
      expect(none.fake.tabs.update).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(200);
      await vi.waitFor(() => {
        expect(none.fake.tabs.update).toHaveBeenCalledTimes(1);
      });
      expect(none.fake.webNavigation.getFrame).toHaveBeenCalledWith({ tabId: 4, frameId: 0 });
      const [, plain] = none.fake.tabs.update.mock.calls[0]!;
      expect(plain).not.toHaveProperty('loadReplace');
      expect(fromQuery(new URL(plain.url ?? '').search)?.replaced).toBe(true);

      // The frame shows the failed URL in another document than the failure left: the error page
      // committed but its event is late, so the block page replaces it (a plain load would leave
      // the failed entry behind Go back).
      expect(replacedEntry(await failAndWait({ url: 'https://ads.example/page', documentId: 'error-page', errorOccurred: false, parentFrameId: -1 }, 'before'))).toBe(true);
      // The same document: not committed (a failed same-URL POST shares the URL), a plain load.
      expect(replacedEntry(await failAndWait({ url: 'https://ads.example/page', documentId: 'before', errorOccurred: false, parentFrameId: -1 }, 'before'))).toBe(false);
      // Another document at another URL (Back restored a page from the cache): a plain load.
      expect(replacedEntry(await failAndWait({ url: 'https://earlier.example/', documentId: 'earlier', errorOccurred: false, parentFrameId: -1 }, 'before'))).toBe(false);
      // Without document IDs, a plain load: it never drops an entry.
      expect(replacedEntry(await failAndWait({ url: 'https://ads.example/page', errorOccurred: false, parentFrameId: -1 }))).toBe(false);
      expect(replacedEntry(await failAndWait({ url: 'https://ads.example/page', documentId: 'error-page', errorOccurred: false, parentFrameId: -1 }))).toBe(false);
      // A repeated failure event (a process switch) with the error page already current: the
      // first record decides.
      const repeated = await start(blocked, (f) => {
        firefoxEdge(f);
        f.webNavigation.getFrame.mockResolvedValue({ url: 'https://ads.example/page', documentId: 'error-page', errorOccurred: false, parentFrameId: -1 });
      });
      failOnFirefox(repeated.fake, 'before');
      repeated.fake.webNavigation.onErrorOccurred.emit({ tabId: 4, frameId: 0, url: 'https://ads.example/page', error: 'Error code 2152398861', documentId: 'error-page' } as never);
      await vi.waitFor(() => {
        expect(repeated.fetch).toHaveBeenCalled();
      });
      await vi.advanceTimersByTimeAsync(2_100);
      await vi.waitFor(() => {
        expect(repeated.fake.tabs.update).toHaveBeenCalledTimes(1);
      });
      expect(replacedEntry(repeated.fake)).toBe(true);
      // The frame unknown: a plain load.
      expect(replacedEntry(await failAndWait(null, 'before'))).toBe(false);
      expect(replacedEntry(await failAndWait(new Error('No frame found with frameId: 0'), 'before'))).toBe(false);

      // A new navigation during the wait ends it: no block page, and the frame isn't asked.
      const moved = await start(blocked, firefoxEdge);
      failOnFirefox(moved.fake);
      await vi.waitFor(() => {
        expect(moved.fetch).toHaveBeenCalled();
      });
      await vi.advanceTimersByTimeAsync(100);
      moved.fake.webNavigation.onBeforeNavigate.emit({ tabId: 4, frameId: 0, url: 'https://next.example/' } as never);
      await vi.advanceTimersByTimeAsync(2_100);
      expect(moved.fake.tabs.update).not.toHaveBeenCalled();
      expect(moved.fake.webNavigation.getFrame).not.toHaveBeenCalled();

      // So does closing the tab.
      const closed = await start(blocked, firefoxEdge);
      failOnFirefox(closed.fake);
      await vi.waitFor(() => {
        expect(closed.fetch).toHaveBeenCalled();
      });
      await vi.advanceTimersByTimeAsync(100);
      closed.fake.tabs.onRemoved.emit(4);
      await vi.advanceTimersByTimeAsync(2_100);
      expect(closed.fake.tabs.update).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it('registers the commit listener on Firefox only', async () => {
    const chromium = await start(blocked, configure);
    expect(chromium.fake.webNavigation.onCommitted.listeners).toHaveLength(0);
    const firefox = await start(blocked, firefoxEdge);
    expect(firefox.fake.webNavigation.onCommitted.listeners).toHaveLength(1);
  });

  it('turns a blocked page load into the block page', async () => {
    const { fake, fetch } = await start(blocked, configure);
    fake.webNavigation.onBeforeNavigate.emit({ tabId: 4, frameId: 0, url: 'https://ads.example/page' } as never);
    fake.webNavigation.onErrorOccurred.emit({ tabId: 4, frameId: 0, url: 'https://ads.example/page', error: 'net::ERR_CONNECTION_REFUSED' } as never);
    await vi.waitFor(() => {
      expect(fake.tabs.update).toHaveBeenCalledTimes(1);
    });
    const [tabId, props] = fake.tabs.update.mock.calls[0]!;
    expect(tabId).toBe(4);
    const url = new URL(props.url ?? '');
    expect(`${url.protocol}//${url.host}/`).toBe(BASE);
    expect(url.pathname).toBe('/block.html');
    expect(fromQuery(url.search)?.info).toEqual({
      kind: 'dns',
      url: 'https://ads.example/page',
      name: 'ads.example',
      blockId: 'abcdefgh',
      bundle: 'block-common',
      head: '3f2a',
    });
    const [probeUrl, init] = fetch.mock.calls[0]!;
    expect(probeUrl.startsWith(`${EDGE}/dns-query?dns=`)).toBe(true);
    expect(new Headers(init.headers).get('x-picket-client')).toBe('extension');
  });

  it('does nothing before setup, or for a page the edge did not block', async () => {
    const { fake, fetch } = await start(blocked);
    fake.webNavigation.onErrorOccurred.emit({ tabId: 4, frameId: 0, url: 'https://ads.example/', error: 'net::ERR_NAME_NOT_RESOLVED' } as never);
    await new Promise((r) => setTimeout(r, 10));
    expect(fetch).not.toHaveBeenCalled();
    configure(fake);
    fake.webNavigation.onErrorOccurred.emit({ tabId: 4, frameId: 0, url: 'https://fine.example/', error: 'net::ERR_NAME_NOT_RESOLVED' } as never);
    await vi.waitFor(() => {
      expect(fetch).toHaveBeenCalledTimes(1);
    });
    await new Promise((r) => setTimeout(r, 10));
    expect(fake.tabs.update).not.toHaveBeenCalled();
  });

  it('lists sub-resource blocks for the popup once detection is granted', async () => {
    const webRequest = { onErrorOccurred: new FakeEvent() };
    const { fake } = await start(blocked, (f) => {
      configure(f);
      grantDetection(f);
      (f as unknown as { webRequest: unknown }).webRequest = webRequest;
    });
    expect(webRequest.onErrorOccurred.listeners).toHaveLength(1);
    webRequest.onErrorOccurred.emit({ tabId: 9, url: 'https://ads.example/ad.js', error: 'net::ERR_NAME_NOT_RESOLVED', type: 'script' } as never);
    fake.sender = { url: `${BASE}popup.html`, tabId: undefined };
    const listed = async (): Promise<string[]> => {
      const r = (await fake.runtime.sendMessage({ type: 'tabBlocks', tabId: 9 })) as { value: { host: string }[] };
      return r.value.map((b) => b.host);
    };
    await vi.waitFor(async () => {
      expect(await listed()).toEqual(['ads.example']);
    });
    expect(fake.action.setBadgeText).toHaveBeenCalledWith({ tabId: 9, text: '1' });
    // A new page in the tab starts a new list.
    fake.webNavigation.onBeforeNavigate.emit({ tabId: 9, frameId: 0, url: 'https://next.example/' } as never);
    await vi.waitFor(async () => {
      expect(await listed()).toEqual([]);
    });
  });

  it('starts and stops detection with its permission, whatever the API object says', async () => {
    const { fake } = await start(blocked, configure);
    const webRequest = { onErrorOccurred: new FakeEvent() };
    (fake as unknown as { webRequest: unknown }).webRequest = webRequest;
    // The namespace is there (as webextension-polyfill keeps it), but not the permission.
    fake.permissions.onAdded.emit();
    await new Promise((r) => setTimeout(r, 5));
    expect(webRequest.onErrorOccurred.listeners).toHaveLength(0);
    grantDetection(fake);
    fake.permissions.onAdded.emit();
    await vi.waitFor(() => {
      expect(webRequest.onErrorOccurred.listeners).toHaveLength(1);
    });
    // Removed: the polyfill still has `browser.webRequest`, so only the permission check can tell.
    fake.granted.permissions.delete('webRequest');
    fake.granted.origins.delete('<all_urls>');
    fake.permissions.onRemoved.emit();
    await vi.waitFor(() => {
      expect(webRequest.onErrorOccurred.listeners).toHaveLength(0);
    });
  });

  it('notes a detection grant on Brave until the browser restarts, and drops the note with the permission', async () => {
    const { fake } = await start(blocked, configure);
    grantDetection(fake);
    fake.permissions.onAdded.emit({ permissions: ['webRequest'], origins: ['<all_urls>'] } as never);
    await vi.waitFor(async () => {
      expect(await fake.runtime.sendMessage({ type: 'getState' })).toMatchObject({ value: { detection: true, detectionAfterRestart: true } });
    });
    // The browser's next start begins with an empty storage.session.
    const next = await start(blocked, (f) => {
      configure(f);
      grantDetection(f);
    });
    expect(await next.fake.runtime.sendMessage({ type: 'getState' })).toMatchObject({ value: { detection: true, detectionAfterRestart: false } });
    fake.granted.permissions.delete('webRequest');
    fake.permissions.onRemoved.emit({ permissions: ['webRequest'], origins: ['<all_urls>'] } as never);
    await vi.waitFor(() => {
      expect(fake.storage.session.data.has('detectionAfterRestart')).toBe(false);
    });
  });

  it("drops the restart note at Brave's first request, which shows no restart is needed (issue #61)", async () => {
    const webRequest = { onErrorOccurred: new FakeEvent() };
    const { fake } = await start(blocked, (f) => {
      configure(f);
      (f as unknown as { webRequest: unknown }).webRequest = webRequest;
    });
    grantDetection(fake);
    fake.permissions.onAdded.emit({ permissions: ['webRequest'], origins: ['<all_urls>'] } as never);
    await vi.waitFor(() => {
      expect(fake.storage.session.data.get('detectionAfterRestart')).toBe(true);
      expect(webRequest.onErrorOccurred.listeners).toHaveLength(1);
    });
    webRequest.onErrorOccurred.emit({ tabId: 9, url: 'https://ads.example/ad.js', error: 'net::ERR_NAME_NOT_RESOLVED', type: 'script' } as never);
    await vi.waitFor(async () => {
      expect(await fake.runtime.sendMessage({ type: 'getState' })).toMatchObject({ value: { detection: true, detectionAfterRestart: false } });
    });
    // A later grant notes it again until the next request.
    fake.granted.permissions.delete('webRequest');
    fake.permissions.onRemoved.emit({ permissions: ['webRequest'], origins: ['<all_urls>'] } as never);
    grantDetection(fake);
    fake.permissions.onAdded.emit({ permissions: ['webRequest'], origins: ['<all_urls>'] } as never);
    await vi.waitFor(() => {
      expect(fake.storage.session.data.get('detectionAfterRestart')).toBe(true);
    });
  });

  it('withdraws a listener added at start when the permission turns out not to be granted', async () => {
    const webRequest = { onErrorOccurred: new FakeEvent() };
    await start(blocked, (f) => {
      configure(f);
      (f as unknown as { webRequest: unknown }).webRequest = webRequest;
    });
    await vi.waitFor(() => {
      expect(webRequest.onErrorOccurred.listeners).toHaveLength(0);
    });
  });

  it("doesn't list a late sub-resource probe against the tab's next page", async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => (release = r));
    const webRequest = { onErrorOccurred: new FakeEvent() };
    const { fake, fetch } = await start(
      (url) => blocked(url),
      (f) => {
        configure(f);
        grantDetection(f);
        (f as unknown as { webRequest: unknown }).webRequest = webRequest;
      },
    );
    fetch.mockImplementation(async (url: string) => {
      await gate;
      return blocked(url);
    });
    webRequest.onErrorOccurred.emit({ tabId: 9, url: 'https://ads.example/ad.js', error: 'net::ERR_NAME_NOT_RESOLVED', type: 'script' } as never);
    await vi.waitFor(() => {
      expect(fetch).toHaveBeenCalled();
    });
    fake.webNavigation.onBeforeNavigate.emit({ tabId: 9, frameId: 0, url: 'https://next.example/' } as never);
    release();
    await new Promise((r) => setTimeout(r, 20));
    fake.sender = { url: `${BASE}popup.html`, tabId: undefined };
    const r = (await fake.runtime.sendMessage({ type: 'tabBlocks', tabId: 9 })) as { value: unknown[] };
    expect(r.value).toEqual([]);
  });

  it("allows for the chosen time by the edge's clock after a restart between the probe and the allow", async () => {
    // The edge's clock is 2 h ahead of this device's; the probe's reply says so.
    const edgeNow = () => Date.now() + 2 * 3_600_000;
    const dated = (r: Response): Response => {
      r.headers.set('date', new Date(edgeNow()).toUTCString());
      return r;
    };
    const created = { allow_id: 'a-1', kind: 'dns', target: 'ads.example', expires_at: 0, retry_after_s: 0 };
    const respond = (url: string, init: RequestInit): Response =>
      dated(url.includes('/dns-query') ? blocked(url) : Response.json(init.method === 'PATCH' ? [{ ...created, expires_at: Math.floor(edgeNow() / 1000) + 900 }] : []));
    const first = await start(respond, configure);
    first.fake.webNavigation.onErrorOccurred.emit({ tabId: 4, frameId: 0, url: 'https://ads.example/page', error: 'net::ERR_NAME_NOT_RESOLVED' } as never);
    await vi.waitFor(() => {
      expect(first.fake.tabs.update).toHaveBeenCalledTimes(1);
    });
    // The background unloads while the block page waits; the user's choice wakes a new one.
    const second = await start(respond, carryOver(first.fake));
    second.fake.sender = { url: `${BASE}block.html`, tabId: 4 };
    const r = (await second.fake.runtime.sendMessage({
      type: 'createAllows',
      durationS: 900,
      entries: [{ kind: 'dns', blockId: 'abcdefgh', name: 'ads.example', subdomains: false }],
    })) as { ok: boolean; value?: { created: { allow_id: string }[] } };
    expect(second.fetch.mock.calls.map((c) => c[1].method)).toEqual(['PATCH']);
    const body = JSON.parse(second.fetch.mock.calls[0]?.[1].body as string) as { expires_at: number }[];
    expect(Math.abs((body[0]?.expires_at ?? 0) - (Math.floor(edgeNow() / 1000) + 900))).toBeLessThanOrEqual(2);
    expect(r.ok).toBe(true);
    expect(r.value?.created[0]?.allow_id).toBe('a-1');
  });

  it('learns the edge clock again when the kept one is stale', async () => {
    const edgeNow = () => Date.now() + 2 * 3_600_000;
    const respond = (_url: string, init: RequestInit): Response => {
      const r = Response.json(init.method === 'PATCH' ? [{ allow_id: 'a-1', kind: 'ip', target: '100.100.100.100', expires_at: 1, retry_after_s: 0 }] : []);
      r.headers.set('date', new Date(edgeNow()).toUTCString());
      return r;
    };
    const { fake, fetch } = await start(respond, (f) => {
      configure(f);
      // Learnt 10 minutes ago, with another skew.
      f.storage.session.data.set('edgeClock', { origin: EDGE, skewMs: 0, at: Date.now() - 600_000 });
    });
    fake.sender = { url: `${BASE}block.html`, tabId: 4 };
    await fake.runtime.sendMessage({ type: 'createAllows', durationS: 3600, entries: [{ kind: 'ip', ip: '100.100.100.100' }] });
    expect(fetch.mock.calls.map((c) => c[1].method)).toEqual(['GET', 'PATCH']);
    const body = JSON.parse(fetch.mock.calls[1]?.[1].body as string) as { expires_at: number }[];
    expect(Math.abs((body[0]?.expires_at ?? 0) - (Math.floor(edgeNow() / 1000) + 3600))).toBeLessThanOrEqual(2);
  });

  it("keeps a reload's pending retry across a restart", async () => {
    const first = await start(blocked, configure);
    first.fake.sender = { url: `${BASE}block.html`, tabId: 4 };
    await first.fake.runtime.sendMessage({ type: 'reloadAfterAllow', url: 'https://ads.example/page' });
    first.fake.webNavigation.onBeforeNavigate.emit({ tabId: 4, frameId: 0, url: 'https://ads.example/page' } as never);
    await vi.waitFor(() => {
      expect(first.fake.storage.session.data.get('retries')).toMatchObject([{ tab: 4, phase: 'loading', left: 1, url: 'https://ads.example/page' }]);
    });
    const second = await start(blocked, carryOver(first.fake));
    second.fake.webNavigation.onErrorOccurred.emit({ tabId: 4, frameId: 0, url: 'https://ads.example/page', error: 'net::ERR_NAME_NOT_RESOLVED' } as never);
    await vi.waitFor(
      () => {
        expect(second.fake.tabs.update).toHaveBeenCalledWith(4, { url: 'https://ads.example/page' });
      },
      { timeout: 4000 },
    );
    expect(second.fetch).not.toHaveBeenCalled(); // retried, not probed
  });

  it('replaces the failed entry with the block page on Firefox, and pushes it on Chromium', async () => {
    const chromium = await start(blocked, configure);
    chromium.fake.webNavigation.onErrorOccurred.emit({ tabId: 4, frameId: 0, url: 'https://ads.example/page', error: 'net::ERR_NAME_NOT_RESOLVED' } as never);
    await vi.waitFor(() => {
      expect(chromium.fake.tabs.update).toHaveBeenCalledTimes(1);
    });
    expect(Object.keys(chromium.fake.tabs.update.mock.calls[0]?.[1] ?? {})).toEqual(['url']);
    expect(blockPageQuery(chromium.fake).has('replaced')).toBe(false);

    const firefox = await start(blocked, (f) => {
      configure(f);
      f.runtime.getURL = (p: string) => `moz-extension://0b1c2d3e/${p.replace(/^\//, '')}`;
    });
    firefox.fake.webNavigation.onErrorOccurred.emit({ tabId: 4, frameId: 0, url: 'https://ads.example/page', error: 'Error code 2152398878' } as never);
    // Firefox commits the error page after the failure.
    firefox.fake.webNavigation.onCommitted.emit({ tabId: 4, frameId: 0, url: 'https://ads.example/page' } as never);
    await vi.waitFor(() => {
      expect(firefox.fake.tabs.update).toHaveBeenCalledTimes(1);
    });
    expect(firefox.fake.tabs.update.mock.calls[0]?.[1]).toMatchObject({ loadReplace: true });
    expect(blockPageQuery(firefox.fake).get('replaced')).toBe('1');
    // The reload after an allow replaces the block page too.
    firefox.fake.sender = { url: 'moz-extension://0b1c2d3e/block.html', tabId: 4 };
    expect(await firefox.fake.runtime.sendMessage({ type: 'reloadAfterAllow', url: 'https://ads.example/page' })).toEqual({ ok: true, value: null });
    expect(firefox.fake.tabs.update).toHaveBeenLastCalledWith(4, { url: 'https://ads.example/page', loadReplace: true });
  });

  it('keeps a long URL for the block page in storage.session', async () => {
    const long = `https://sso.example/saml?SAMLRequest=${'A'.repeat(20_000)}`;
    const { fake } = await start(
      (url) => {
        const q = queryOf(url);
        return dnsResponse(reply(q, { ede: [{ code: 15, text: 'block=abcdefgh' }] }));
      },
      configure,
    );
    fake.webNavigation.onErrorOccurred.emit({ tabId: 4, frameId: 0, url: long, error: 'net::ERR_NAME_NOT_RESOLVED' } as never);
    await vi.waitFor(() => {
      expect(fake.tabs.update).toHaveBeenCalledTimes(1);
    });
    const q = blockPageQuery(fake);
    expect(q.has('url')).toBe(false);
    const parsed = fromQuery(q.toString());
    expect(parsed?.ref).toMatch(/^[0-9a-f]{32}$/);
    expect(await keptUrl(fake.storage.session, parsed?.ref ?? '')).toBe(long);
  });

  it('keeps a long URL only while its block page is open (recheck R9)', async () => {
    const long = `https://sso.example/saml?SAMLResponse=${'A'.repeat(20_000)}`;
    const { fake } = await start((url) => dnsResponse(reply(queryOf(url), { ede: [{ code: 15, text: 'block=abcdefgh' }] })), configure);
    const kept = (): unknown => fake.storage.session.data.get('blockUrls');
    const blockPage = async (tabId: number): Promise<string> => {
      fake.tabs.update.mockClear();
      fake.webNavigation.onErrorOccurred.emit({ tabId, frameId: 0, url: long, error: 'net::ERR_NAME_NOT_RESOLVED' } as never);
      await vi.waitFor(() => {
        expect(fake.tabs.update).toHaveBeenCalledTimes(1);
      });
      const page = (fake.tabs.update.mock.calls[0]?.[1] as { url: string }).url;
      // The block page's own load (and a reload of it) keeps it.
      fake.webNavigation.onBeforeNavigate.emit({ tabId, frameId: 0, url: page } as never);
      await new Promise((r) => setTimeout(r, 5));
      expect(kept()).toMatchObject([{ tab: tabId, url: long }]);
      return page;
    };
    // The tab leaves the block page (here, the reload after an allow).
    await blockPage(4);
    fake.webNavigation.onBeforeNavigate.emit({ tabId: 4, frameId: 0, url: long } as never);
    await vi.waitFor(() => {
      expect(kept()).toBeUndefined();
    });
    // The tab closes.
    await blockPage(5);
    fake.tabs.onRemoved.emit(5);
    await vi.waitFor(() => {
      expect(kept()).toBeUndefined();
    });
  });

  it("doesn't replace a page the user went to while a long URL was being kept (recheck R3)", async () => {
    const long = `https://ads.example/?q=${'a'.repeat(10_000)}`;
    const write: { release: () => void; started: boolean } = { release: () => undefined, started: false };
    const { fake } = await start((url) => dnsResponse(reply(queryOf(url), { ede: [{ code: 15, text: 'block=abcdefgh' }] })), (f) => {
      configure(f);
      const set = f.storage.session.set.getMockImplementation();
      f.storage.session.set.mockImplementation(async (items) => {
        if ('blockUrls' in items) {
          write.started = true;
          await new Promise<void>((r) => (write.release = r));
        }
        await set?.(items);
      });
    });
    fake.webNavigation.onErrorOccurred.emit({ tabId: 3, frameId: 0, url: long, error: 'net::ERR_NAME_NOT_RESOLVED' } as never);
    await vi.waitFor(() => {
      expect(write.started).toBe(true);
    });
    fake.webNavigation.onBeforeNavigate.emit({ tabId: 3, frameId: 0, url: 'https://new.example/' } as never);
    write.release();
    await new Promise((r) => setTimeout(r, 20));
    expect(fake.tabs.update).not.toHaveBeenCalled();
    // Nor is the URL kept for a block page that never opened.
    expect(fake.storage.session.data.get('blockUrls')).toBeUndefined();
  });

  it("drops a long URL kept for a block page that allows changing kept from opening", async () => {
    const long = `https://ads.example/?q=${'a'.repeat(10_000)}`;
    const write: { release: () => void; started: boolean } = { release: () => undefined, started: false };
    const respond = (url: string): Response => {
      if (url.includes('/dns-query')) {
        return dnsResponse(reply(queryOf(url), { ede: [{ code: 15, text: 'block=abcdefgh' }] }));
      }
      const r = Response.json([]);
      r.headers.set('date', new Date().toUTCString());
      return r;
    };
    const { fake } = await start(respond, (f) => {
      configure(f);
      const set = f.storage.session.set.getMockImplementation();
      f.storage.session.set.mockImplementation(async (items) => {
        if ('blockUrls' in items && !write.started) {
          write.started = true;
          await new Promise<void>((r) => (write.release = r));
        }
        await set?.(items);
      });
    });
    fake.webNavigation.onErrorOccurred.emit({ tabId: 3, frameId: 0, url: long, error: 'net::ERR_NAME_NOT_RESOLVED' } as never);
    await vi.waitFor(() => {
      expect(write.started).toBe(true);
    });
    // The popup ends an allow meanwhile: the probe's answer may no longer hold.
    fake.sender = { url: `${BASE}popup.html`, tabId: undefined };
    expect(await fake.runtime.sendMessage({ type: 'endAllow', allowId: 'a-1' })).toMatchObject({ ok: true });
    write.release();
    // The kept URL is written, then dropped: no block page will read it.
    await vi.waitFor(() => {
      expect(fake.storage.session.set.mock.calls.some(([items]) => 'blockUrls' in items)).toBe(true);
      expect(fake.storage.session.remove).toHaveBeenCalledWith('blockUrls');
    });
    await new Promise((r) => setTimeout(r, 10));
    expect(fake.storage.session.data.get('blockUrls')).toBeUndefined();
    expect(fake.tabs.update).not.toHaveBeenCalled();
  });

  it("keeps the newer block page's long URL when an earlier opening in the tab is abandoned late (final check of G1)", async () => {
    const longA = `https://ads.example/?q=${'a'.repeat(10_000)}`;
    const longB = `https://other.example/?q=${'b'.repeat(10_000)}`;
    const write: { release: () => void; started: boolean } = { release: () => undefined, started: false };
    const { fake } = await start((url) => dnsResponse(reply(queryOf(url), { ede: [{ code: 15, text: 'block=abcdefgh' }] })), (f) => {
      configure(f);
      const set = f.storage.session.set.getMockImplementation();
      f.storage.session.set.mockImplementation(async (items) => {
        if ('blockUrls' in items && !write.started) {
          write.started = true;
          await new Promise<void>((r) => (write.release = r));
        }
        await set?.(items);
      });
    });
    fake.webNavigation.onErrorOccurred.emit({ tabId: 3, frameId: 0, url: longA, error: 'net::ERR_NAME_NOT_RESOLVED' } as never);
    await vi.waitFor(() => {
      expect(write.started).toBe(true);
    });
    // The tab goes to another blocked page while A's URL is still being kept.
    fake.webNavigation.onBeforeNavigate.emit({ tabId: 3, frameId: 0, url: longB } as never);
    fake.webNavigation.onErrorOccurred.emit({ tabId: 3, frameId: 0, url: longB, error: 'net::ERR_NAME_NOT_RESOLVED' } as never);
    await new Promise((r) => setTimeout(r, 10));
    write.release();
    await vi.waitFor(() => {
      expect(fake.tabs.update).toHaveBeenCalledTimes(1);
    });
    await new Promise((r) => setTimeout(r, 10));
    // A's late drop left B's URL alone: B's block page can still read it.
    expect(JSON.stringify(fake.storage.session.data.get('blockUrls') ?? null)).toContain('other.example');
    expect(JSON.stringify(fake.storage.session.data.get('blockUrls') ?? null)).not.toContain('ads.example');
  });

  it('on Firefox, checks again before the plain load that follows a refused loadReplace', async () => {
    const { fake } = await start(blocked, (f) => {
      configure(f);
      f.runtime.getURL = (p: string) => `moz-extension://0b1c2d3e/${p.replace(/^\//, '')}`;
    });
    let refuse: (e: Error) => void = () => undefined;
    fake.tabs.update.mockImplementationOnce(() => new Promise((_, rej) => (refuse = rej)));
    fake.webNavigation.onErrorOccurred.emit({ tabId: 4, frameId: 0, url: 'https://ads.example/page', error: 'Error code 2152398878' } as never);
    fake.webNavigation.onCommitted.emit({ tabId: 4, frameId: 0, url: 'https://ads.example/page' } as never);
    await vi.waitFor(() => {
      expect(fake.tabs.update).toHaveBeenCalledTimes(1);
    });
    fake.webNavigation.onBeforeNavigate.emit({ tabId: 4, frameId: 0, url: 'https://new.example/' } as never);
    refuse(new Error('loadReplace is not supported'));
    await new Promise((r) => setTimeout(r, 10));
    expect(fake.tabs.update).toHaveBeenCalledTimes(1);
  });

  it('holds one failure per tab while a long URL is kept for its block page, and opens it for the newest (recheck G1)', async () => {
    vi.resetModules();
    const fake = (await import('./fake-browser')).default;
    configure(fake);
    const { NavigationFlow } = await import('../src/background/navigation');
    const handle = NavigationFlow.prototype.onErrorOccurred;
    let held = 0;
    vi.spyOn(NavigationFlow.prototype, 'onErrorOccurred').mockImplementation(function (this: InstanceType<typeof NavigationFlow>, d) {
      held += 1;
      return handle.call(this, d).finally(() => {
        held -= 1;
      });
    });
    const fetch = vi.fn(async (url: string) => dnsResponse(reply(queryOf(url), { ede: [{ code: 15, text: 'block=abcdefgh' }] })));
    vi.stubGlobal('fetch', fetch);
    vi.spyOn(console, 'debug').mockImplementation(() => undefined);
    const write: { release: () => void; started: boolean } = { release: () => undefined, started: false };
    const set = fake.storage.session.set.getMockImplementation();
    fake.storage.session.set.mockImplementation(async (items) => {
      if ('blockUrls' in items && !write.started) {
        write.started = true;
        await new Promise<void>((r) => (write.release = r));
      }
      await set?.(items);
    });
    await import('../src/background/index');
    const url = (i: number): string => `https://sso.example/auth?SAMLRequest=${'A'.repeat(6000)}&n=${String(i)}`;
    fake.webNavigation.onErrorOccurred.emit({ tabId: 3, frameId: 0, url: url(0), error: 'net::ERR_NAME_NOT_RESOLVED' } as never);
    await vi.waitFor(() => {
      expect(write.started).toBe(true);
    });
    for (let i = 1; i < 1000; i++) {
      fake.webNavigation.onErrorOccurred.emit({ tabId: 3, frameId: 0, url: url(i), error: 'net::ERR_NAME_NOT_RESOLVED' } as never);
    }
    await new Promise((r) => setTimeout(r, 10));
    expect(held).toBe(1);
    expect(fetch).toHaveBeenCalledTimes(1);
    write.release();
    await vi.waitFor(() => {
      expect(fake.tabs.update).toHaveBeenCalledTimes(1);
    });
    expect(held).toBe(0);
    const ref = fromQuery(blockPageQuery(fake).toString())?.ref ?? '';
    expect(await keptUrl(fake.storage.session, ref)).toBe(url(999));
    expect(fake.storage.session.data.get('blockUrls')).toHaveLength(1);
  });

  it("doesn't turn a TLS error at an IP-literal URL into a firewall block page (recheck R7)", async () => {
    const fw = (url: string): Response => dnsResponse(reply(queryOf(url), { rcode: 3, ede: [{ code: 15, text: 'cause=firewall' }] }));
    const { fake, fetch } = await start(fw, configure);
    // A LAN appliance with a self-signed certificate: the TCP connection worked.
    fake.webNavigation.onErrorOccurred.emit({ tabId: 4, frameId: 0, url: 'https://192.168.10.5:8006/', error: 'net::ERR_CERT_AUTHORITY_INVALID' } as never);
    await new Promise((r) => setTimeout(r, 20));
    expect(fetch).not.toHaveBeenCalled();
    expect(fake.tabs.update).not.toHaveBeenCalled();
    // A refused connection to it is probed, and the edge's answer decides.
    fake.webNavigation.onErrorOccurred.emit({ tabId: 4, frameId: 0, url: 'https://192.168.10.5:8006/', error: 'net::ERR_CONNECTION_REFUSED' } as never);
    await vi.waitFor(() => {
      expect(fake.tabs.update).toHaveBeenCalledTimes(1);
    });
    expect(blockPageQuery(fake).get('ip')).toBe('192.168.10.5');
  });
});
