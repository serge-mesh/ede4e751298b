import { beforeEach, describe, expect, it, vi } from 'vitest';

import { EdgeClient, sessionClockStore, type FetchLike } from '../src/background/edge-client';
import { allowForEntry, Router, type RouterDeps } from '../src/background/router';
import { describeError } from '../src/shared/api';
import { send } from '../src/shared/messages';
import { DETECTION_PERMISSIONS } from '../src/shared/permissions';
import { loadSettings, saveSettings } from '../src/shared/settings';
import fake, { BASE, EXTENSION_ID, resetFakeBrowser } from './fake-browser';

const EDGE = 'https://dns.home.arpa:9853';

/** Replies carry the edge's `Date`, as the edge's do (this device's time, unless set). */
function dated(r: Response): Response {
  if (!r.headers.has('date')) {
    r.headers.set('date', new Date().toUTCString());
  }
  return r;
}

function setup(respond: (url: string, init: RequestInit) => Response = () => Response.json([])) {
  const fetch = vi.fn<FetchLike>(async (url, init) => dated(respond(url, init)));
  const client = new EdgeClient({ origin: EDGE, fetch, clockStore: sessionClockStore(fake.storage.session, EDGE) });
  const deps: RouterDeps = {
    extensionId: EXTENSION_ID,
    extensionBase: BASE,
    loadSettings,
    saveSettings,
    hasPermissions: (p) => fake.permissions.contains(p),
    detectionAfterRestart: async () => fake.storage.session.data.get('detectionAfterRestart') === true,
    client: vi.fn(() => client),
    tabBlocks: vi.fn(async () => [{ host: 'ads.example', kind: 'dns' as const, blockId: 'abcdefgh', at: 1 }]),
    reloadAfterAllow: vi.fn(async () => undefined),
    allowsChanged: vi.fn(),
  };
  const router = new Router(deps);
  fake.runtime.onMessage.addListener((m, s) => router.handle(m, s));
  return { router, deps, fetch, client };
}

async function configure(): Promise<void> {
  await saveSettings({ edgeUrl: EDGE, coreUrl: 'https://core.home.arpa:8443/' });
  fake.granted.origins.add('https://dns.home.arpa/*');
}

beforeEach(resetFakeBrowser);

describe('who may send', () => {
  it("answers only this extension's pages, and only known requests", async () => {
    const { router } = setup();
    const req = { type: 'getState' };
    expect(await router.handle(req, { id: 'other-extension', url: `${BASE}popup.html` })).toMatchObject({ ok: false });
    expect(await router.handle(req, { id: EXTENSION_ID, url: 'https://evil.example/' })).toMatchObject({ ok: false });
    expect(await router.handle(req, { id: EXTENSION_ID })).toMatchObject({ ok: false });
    expect(await router.handle({ type: 'drop tables' }, { id: EXTENSION_ID, url: `${BASE}popup.html` })).toMatchObject({
      ok: false,
      error: { kind: 'request' },
    });
    expect(await router.handle(req, { id: EXTENSION_ID, url: `${BASE}popup.html` })).toMatchObject({ ok: true });
  });
});

describe('message passing from a page', () => {
  it('reports state: settings, edge access and detection', async () => {
    setup();
    expect(await send({ type: 'getState' })).toEqual({
      ok: true,
      value: { edgeUrl: null, coreUrl: null, edgeAccess: false, detection: false, detectionAfterRestart: false },
    });
    await configure();
    fake.granted.permissions.add('webRequest');
    fake.granted.origins.add('<all_urls>');
    expect(await send({ type: 'getState' })).toEqual({
      ok: true,
      value: { edgeUrl: EDGE, coreUrl: 'https://core.home.arpa:8443/', edgeAccess: true, detection: true, detectionAfterRestart: false },
    });
    // Granted on Brave since its last start: detection waits for the next one.
    fake.storage.session.data.set('detectionAfterRestart', true);
    expect(await send({ type: 'getState' })).toMatchObject({ ok: true, value: { detection: true, detectionAfterRestart: true } });
    expect(DETECTION_PERMISSIONS).toEqual({ permissions: ['webRequest'], origins: ['<all_urls>'] });
  });

  it('saves settings after checking them', async () => {
    setup();
    expect(await send({ type: 'saveSettings', edgeUrl: 'http://dns.home.arpa', coreUrl: '' })).toMatchObject({
      ok: false,
      error: { kind: 'request' },
    });
    expect(fake.storage.local.data.size).toBe(0);
    const r = await send({ type: 'saveSettings', edgeUrl: 'dns.home.arpa:9853', coreUrl: '' });
    expect(r).toMatchObject({ ok: true, value: { edgeUrl: EDGE, coreUrl: null, edgeAccess: false } });
  });

  it('needs an edge URL and its host permission before calling the edge', async () => {
    const { fetch } = setup();
    expect(await send({ type: 'listAllows' })).toMatchObject({ ok: false, error: { kind: 'not_configured' } });
    await saveSettings({ edgeUrl: EDGE, coreUrl: null });
    expect(await send({ type: 'testEdge' })).toMatchObject({ ok: false, error: { kind: 'permission' } });
    expect(fetch).not.toHaveBeenCalled();
    fake.granted.origins.add('https://dns.home.arpa/*');
    expect(await send({ type: 'testEdge' })).toEqual({ ok: true, value: { allows: [], skewMs: 0 } });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("creates allows ending the chosen time from the edge's now, learnt first when unknown", async () => {
    // This device's clock is an hour behind the edge's.
    const edgeNow = () => Date.now() + 3_600_000;
    const created = [
      { allow_id: 'a-1', kind: 'dns', target: 'ads.example', expires_at: 2, retry_after_s: 30 },
      { allow_id: 'a-2', kind: 'dns', target: 'CDN.example.', subdomains: true, expires_at: 2, retry_after_s: 0 },
      { allow_id: 'a-3', kind: 'ip', target: '100.100.100.100', expires_at: 2, retry_after_s: 0 },
      { allow_id: 'a-0', kind: 'dns', target: 'older.example', expires_at: 2 },
    ];
    const { fetch, deps } = setup((_url, init) =>
      Response.json(init.method === 'GET' ? [] : created, { headers: { date: new Date(edgeNow()).toUTCString() } }),
    );
    await configure();
    const r = await send({
      type: 'createAllows',
      durationS: 3600,
      entries: [
        { kind: 'dns', blockId: 'abcdefgh', name: 'ads.example', subdomains: false },
        { kind: 'dns', blockId: 'ijklmnop', name: 'cdn.example', subdomains: true },
        { kind: 'ip', ip: '100.100.100.100' },
      ],
    });
    // A GET learnt the edge's clock before the PATCH computed expires_at from it.
    expect(fetch.mock.calls.map((c) => c[1].method)).toEqual(['GET', 'PATCH']);
    const until = Math.floor(edgeNow() / 1000) + 3600;
    const body = JSON.parse(fetch.mock.calls[1]?.[1].body as string) as { expires_at: number }[];
    expect(body.map((e) => Object.fromEntries(Object.entries(e).filter(([k]) => k !== 'expires_at')))).toEqual([
      { block_id: 'abcdefgh' },
      { block_id: 'ijklmnop', subdomains: true },
      { ip: '100.100.100.100' },
    ]);
    for (const e of body) {
      expect(Math.abs(e.expires_at - until)).toBeLessThanOrEqual(2);
    }
    expect(r).toMatchObject({ ok: true, value: { allows: created, created: created.slice(0, 3) } });
    if (r.ok) {
      expect(Math.abs(r.value.skewMs - 3_600_000)).toBeLessThanOrEqual(1500);
      expect(r.value.requestedUntil).toBe(body[0]?.expires_at);
    }
    expect(deps.allowsChanged).toHaveBeenCalledTimes(1);
    // While the learnt skew is fresh, the next allow needs no GET.
    await send({ type: 'createAllows', durationS: 900, entries: [{ kind: 'ip', ip: '100.100.100.100' }] });
    expect(fetch.mock.calls.map((c) => c[1].method)).toEqual(['GET', 'PATCH', 'PATCH']);
  });

  it('after a background restart, a device clock 2 h behind no longer sends a past expires_at shown as success', async () => {
    // The review's EX1 scenario (target-review-ext-opus zz-review.test.ts): a fresh client, the
    // edge's Date 2 h ahead, and an edge that answers a past expires_at with the other allows.
    const edgeNowMs = () => Date.now() + 2 * 3600 * 1000;
    const { fetch } = setup(() => new Response('[]', { headers: { 'content-type': 'application/json', date: new Date(edgeNowMs()).toUTCString() } }));
    await configure();
    fake.sender = { url: `${BASE}block.html`, tabId: 1 };
    const r = await send({ type: 'createAllows', durationS: 900, entries: [{ kind: 'dns', blockId: 'abcdefgh', name: 'ads.example', subdomains: false }] });
    expect(fetch.mock.calls.map((c) => c[1].method)).toEqual(['GET', 'PATCH']);
    const sent = JSON.parse(fetch.mock.calls[1]?.[1].body as string) as { expires_at: number }[];
    expect(Math.abs((sent[0]?.expires_at ?? 0) - (Math.floor(edgeNowMs() / 1000) + 900))).toBeLessThanOrEqual(2);
    // This edge still lists no allow for it: an error, never "Allowed until …".
    expect(r).toMatchObject({ ok: false, error: { kind: 'not_applied', index: 0 } });
  });

  it("uses the edge's time however far this device's clock is off (8 days ahead)", async () => {
    // Recheck R1: a skew past a week was ignored, and the device's clock used instead.
    const edgeNowMs = () => Date.now() - 8 * 86_400_000;
    const { fetch } = setup((_url, init) => {
      const date = new Date(edgeNowMs()).toUTCString();
      if (init.method === 'GET') {
        return Response.json([], { headers: { date } });
      }
      const sent = (JSON.parse(init.body as string) as { expires_at: number }[])[0]?.expires_at ?? 0;
      // An edge clamps to the profile's max_duration (24 h here) by its own clock.
      const until = Math.min(sent, Math.floor(edgeNowMs() / 1000) + 86_400);
      return Response.json([{ allow_id: 'a-1', kind: 'dns', target: 'ads.example', expires_at: until, retry_after_s: 0 }], { headers: { date } });
    });
    await configure();
    const r = await send({ type: 'createAllows', durationS: 900, entries: [{ kind: 'dns', blockId: 'abcdefgh', name: 'ads.example', subdomains: false }] });
    expect(fetch.mock.calls.map((c) => c[1].method)).toEqual(['GET', 'PATCH']);
    const body = JSON.parse(fetch.mock.calls[1]?.[1].body as string) as { expires_at: number }[];
    expect(Math.abs((body[0]?.expires_at ?? 0) - (Math.floor(edgeNowMs() / 1000) + 900))).toBeLessThanOrEqual(2);
    expect(r).toMatchObject({ ok: true, value: { created: [{ allow_id: 'a-1' }] } });
  });

  it("refuses an allow when the edge's time can't be learned, rather than use this device's clock", async () => {
    const { fetch } = setup(() => {
      const r = Response.json([]);
      r.headers.set('date', 'not a date');
      return r;
    });
    await configure();
    const r = await send({ type: 'createAllows', durationS: 900, entries: [{ kind: 'ip', ip: '100.100.100.100' }] });
    expect(r).toMatchObject({ ok: false, error: { kind: 'no_edge_time' } });
    if (!r.ok) {
      expect(describeError(r.error)).toContain('Nothing was changed');
    }
    expect(fetch.mock.calls.map((c) => c[1].method)).toEqual(['GET']);
  });

  it('treats a 200 without an allow for a requested entry as an error', async () => {
    // As when expires_at was already past on the edge: that only revokes, and the reply lists
    // the device's other allows.
    const { deps } = setup((_url, init) =>
      Response.json(init.method === 'GET' ? [] : [{ allow_id: 'a-9', kind: 'dns', target: 'other.example', expires_at: 2 }]),
    );
    await configure();
    const one = await send({ type: 'createAllows', durationS: 900, entries: [{ kind: 'dns', blockId: 'abcdefgh', name: 'ads.example', subdomains: false }] });
    expect(one).toMatchObject({ ok: false, error: { kind: 'not_applied', index: 0 } });
    if (!one.ok) {
      expect(one.error.message).toBe('The edge lists no allow for ads.example, so it is still blocked.');
      expect(describeError(one.error)).toContain("check this device's clock");
    }
    const two = await send({
      type: 'createAllows',
      durationS: 900,
      entries: [
        { kind: 'dns', blockId: 'ijklmnop', name: 'other.example', subdomains: false },
        { kind: 'ip', ip: '100.100.100.100' },
      ],
    });
    expect(two).toMatchObject({ ok: false, error: { kind: 'not_applied', index: 1 } });
    if (!two.ok) {
      expect(two.error.message).toContain('The other entries were allowed.');
    }
    expect(deps.allowsChanged).toHaveBeenCalledTimes(2);
  });

  it('matches allows to entries by kind and canonical target', () => {
    const a = (kind: string, target: string, retry?: number) => ({ allow_id: target, kind, target, expires_at: 1, ...(retry === undefined ? {} : { retry_after_s: retry }) });
    expect(allowForEntry([a('dns', 'Ads.Example.')], { kind: 'dns', blockId: 'x', name: 'ads.example', subdomains: false })?.target).toBe('Ads.Example.');
    expect(allowForEntry([a('ip', 'ads.example')], { kind: 'dns', blockId: 'x', name: 'ads.example', subdomains: false })).toBeUndefined();
    expect(allowForEntry([a('ip', '2001:db8::1')], { kind: 'ip', ip: '2001:0db8:0:0::1' })?.target).toBe('2001:db8::1');
    // The one the request created or re-timed comes first.
    expect(allowForEntry([a('ip', '1.2.3.4'), { ...a('ip', '1.2.3.4', 0), allow_id: 'new' }], { kind: 'ip', ip: '1.2.3.4' })?.allow_id).toBe('new');
  });

  it('passes edge errors through, with the entry index', async () => {
    const { deps } = setup((_url, init) =>
      init.method === 'GET' ? Response.json([]) : Response.json({ error: { code: 'no_block', message: 'nothing to lift', index: 0 } }, { status: 409 }),
    );
    await configure();
    const r = await send({ type: 'createAllows', durationS: 900, entries: [{ kind: 'ip', ip: '1.2.3.4' }] });
    expect(r).toEqual({ ok: false, error: { kind: 'conflict', status: 409, code: 'no_block', message: 'nothing to lift', index: 0 } });
    expect(deps.allowsChanged).not.toHaveBeenCalled();
  });

  it('ends an allow with a past expires_at', async () => {
    const { fetch } = setup(() => Response.json([]));
    await configure();
    expect(await send({ type: 'endAllow', allowId: 'a-0123' })).toEqual({ ok: true, value: { allows: [], skewMs: 0 } });
    expect(fetch.mock.calls[0]?.[1].method).toBe('PATCH');
    expect(JSON.parse(fetch.mock.calls[0]?.[1].body as string)).toEqual([{ allow_id: 'a-0123', expires_at: 0 }]);
  });

  it("lists a tab's blocked hosts", async () => {
    const { deps } = setup();
    expect(await send({ type: 'tabBlocks', tabId: 4 })).toEqual({
      ok: true,
      value: [{ host: 'ads.example', kind: 'dns', blockId: 'abcdefgh', at: 1 }],
    });
    expect(deps.tabBlocks).toHaveBeenCalledWith(4);
  });

  it("reloads the sending tab's original URL", async () => {
    const { deps } = setup();
    expect(await send({ type: 'reloadAfterAllow', url: 'https://ads.example/x' })).toMatchObject({ ok: false });
    fake.sender = { url: `${BASE}block.html?kind=dns`, tabId: 12 };
    expect(await send({ type: 'reloadAfterAllow', url: 'javascript:alert(1)' })).toMatchObject({ ok: false });
    expect(await send({ type: 'reloadAfterAllow', url: 'https://ads.example/x' })).toEqual({ ok: true, value: null });
    expect(deps.reloadAfterAllow).toHaveBeenCalledWith(12, 'https://ads.example/x');
  });

  it('turns a missing background into an error result', async () => {
    // No listener: the message has no receiver.
    expect(await send({ type: 'getState' })).toMatchObject({ ok: false, error: { kind: 'request' } });
  });
});
