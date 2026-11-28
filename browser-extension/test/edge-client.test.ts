import { describe, expect, it, vi } from 'vitest';

import {
  CLOCK_FRESH_MS,
  EdgeClient,
  EdgeClock,
  errorFromResponse,
  parseAllows,
  sessionClockStore,
  type ClockSample,
  type FetchLike,
} from '../src/background/edge-client';
import { FakeArea } from './fake-browser';
import type { AllowEntry } from '../src/shared/api';
import { QTYPE_A } from '../src/shared/dns';
import { dnsResponse, qname, qtype, queryOf, reply } from './dns-writer';

const ORIGIN = 'https://dns.home.arpa:9853';

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
}

function client(respond: (url: string, init: RequestInit) => Response | Promise<Response>, opts: Partial<ConstructorParameters<typeof EdgeClient>[0]> = {}) {
  const fetch = vi.fn<FetchLike>(async (url, init) => respond(url, init));
  return { fetch, c: new EdgeClient({ origin: ORIGIN, fetch, ...opts }) };
}

const sent = (fetch: ReturnType<typeof vi.fn<FetchLike>>, i = 0): { url: string; init: RequestInit; headers: Headers } => {
  const call = fetch.mock.calls[i];
  if (call === undefined) {
    throw new Error('no request');
  }
  return { url: call[0], init: call[1], headers: new Headers(call[1].headers) };
};

const allow = { allow_id: 'a-1', kind: 'dns', target: 'ads.example', expires_at: 1_900_000_000 };

describe('requests', () => {
  it('GET carries X-Picket-Client, no credentials, no cache, no redirects, and no Origin of its own', async () => {
    const { c, fetch } = client(() => json([allow]));
    expect(await c.listAllows()).toEqual({ ok: true, value: [allow] });
    const { url, init, headers } = sent(fetch);
    expect(url).toBe(`${ORIGIN}/v1/temporary-allows`);
    expect(init.method).toBe('GET');
    expect(headers.get('x-picket-client')).toBe('extension');
    expect(headers.get('accept')).toBe('application/json');
    // The browser sets Origin (chrome-extension:// or moz-extension://); the client never does.
    expect(headers.has('origin')).toBe(false);
    expect(init.credentials).toBe('omit');
    expect(init.cache).toBe('no-store');
    expect(init.redirect).toBe('error');
    expect(init.referrerPolicy).toBe('no-referrer');
    expect(init.body).toBeUndefined();
  });

  it('PATCH sends the entries as JSON', async () => {
    const { c, fetch } = client(() => json([{ ...allow, retry_after_s: 42 }]));
    const entries: AllowEntry[] = [
      { block_id: 'abcdefgh', expires_at: 1_900_000_000, subdomains: true },
      { ip: '100.100.100.100', expires_at: 1_900_000_000 },
      { allow_id: 'a-2', expires_at: 0 },
    ];
    const r = await c.patch(entries);
    expect(r).toEqual({ ok: true, value: [{ ...allow, retry_after_s: 42 }] });
    const { init, headers } = sent(fetch);
    expect(init.method).toBe('PATCH');
    expect(headers.get('x-picket-client')).toBe('extension');
    expect(headers.get('content-type')).toBe('application/json');
    expect(headers.has('origin')).toBe(false);
    expect(JSON.parse(init.body as string)).toEqual(entries);
  });

  it('only talks to the configured origin', () => {
    expect(new EdgeClient({ origin: 'https://dns.home.arpa:9853/some/path' }).origin).toBe(ORIGIN);
  });
});

describe('limits', () => {
  it('refuses requests the edge would refuse, without sending them', async () => {
    const { c, fetch } = client(() => json([]));
    const e = (x: number) => ({ ip: `10.0.${String(x >> 8)}.${String(x & 255)}`, expires_at: 1 });
    const cases: [AllowEntry[], number | undefined][] = [
      [[], undefined],
      [Array.from({ length: 257 }, (_, i) => e(i)), undefined],
      [[{ block_id: 'b'.repeat(65), expires_at: 1 }], 0],
      [[{ ip: '1.2.3.4', expires_at: 1 }, { block_id: '', expires_at: 1 }], 1],
      [[{ ip: '1.2.3.4', expires_at: 1.5 }], 0],
      [[{ ip: '1.2.3.4', expires_at: -1 }], 0],
      [[{ ip: '1.2.3.4', block_id: 'abcdefgh', expires_at: 1 }], 0],
    ];
    for (const [entries, index] of cases) {
      const r = await c.patch(entries);
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.error.kind).toBe('request');
        expect(r.error.index).toBe(index);
      }
    }
    // 256 entries is the edge's MAX_ENTRIES: allowed.
    expect((await c.patch(Array.from({ length: 256 }, (_, i) => e(i)))).ok).toBe(true);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('counts identifier length in bytes, as the edge does', async () => {
    const { c, fetch } = client(() => json([]));
    expect((await c.patch([{ block_id: 'é'.repeat(33), expires_at: 1 }])).ok).toBe(false);
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe('errors', () => {
  const failWith = async (res: Response, entries = 1) => {
    const { c } = client(() => res);
    const r = await c.patch(Array.from({ length: entries }, () => ({ allow_id: 'a-1', expires_at: 5 })));
    if (r.ok) {
      throw new Error('expected an error');
    }
    return r.error;
  };
  const body = (code: string, message: string, index?: number) => ({ error: { code, message, ...(index === undefined ? {} : { index }) } });

  it('maps 403 (bypass off, limits) with the edge code', async () => {
    expect(await failWith(json(body('forbidden', 'bypass is off in a governing profile', 0), 403))).toEqual({
      kind: 'forbidden',
      status: 403,
      code: 'forbidden',
      message: 'bypass is off in a governing profile',
      index: 0,
    });
    expect(await failWith(json(body('rate_limited', 'rate_per_hour reached'), 403))).toMatchObject({ kind: 'forbidden', code: 'rate_limited' });
    expect(await failWith(json(body('max_active', 'max_active reached', 0), 403))).toMatchObject({ kind: 'forbidden', code: 'max_active' });
    expect(await failWith(json(body('forbidden', 'origin refused'), 403))).toMatchObject({ kind: 'forbidden', message: 'origin refused' });
  });

  it('maps 409 and 503, keeping the index of the entry they name', async () => {
    expect(await failWith(json(body('no_block', 'nothing to lift', 2), 409), 3)).toMatchObject({ kind: 'conflict', code: 'no_block', index: 2 });
    // An index past the entries sent isn't trusted.
    expect((await failWith(json(body('no_block', 'x', 5), 409), 3)).index).toBeUndefined();
    expect(await failWith(json(body('firewall', "the firewall didn't take the allow: timeout", 0), 503))).toMatchObject({
      kind: 'unavailable',
      code: 'firewall',
      index: 0,
    });
    expect(await failWith(json(body('clock', 'not synchronised'), 503))).toMatchObject({ kind: 'unavailable', code: 'clock' });
  });

  it('maps 429 with Retry-After, 400, 404 and others', async () => {
    expect(await failWith(json(body('busy', "over this device's limits"), 429, { 'retry-after': '1' }))).toMatchObject({ kind: 'busy', retryAfterS: 1 });
    expect(await failWith(json(body('invalid', 'two entries name the same allow differently', 1), 400), 2)).toMatchObject({ kind: 'invalid', index: 1 });
    expect(await failWith(new Response('', { status: 404 }))).toEqual({ kind: 'not_found', status: 404, message: 'HTTP 404' });
    expect(await failWith(new Response('<html>oops</html>', { status: 502 }))).toEqual({ kind: 'http', status: 502, message: 'HTTP 502' });
  });

  it('checks error bodies field by field', () => {
    const e = errorFromResponse(403, { error: { code: 'Bad Code!', message: 7, index: -1 } }, 'soon', 1);
    expect(e).toEqual({ kind: 'forbidden', status: 403, message: 'HTTP 403' });
    expect(errorFromResponse(403, { error: { code: 'x', message: 'm'.repeat(2000) } }, null).message).toHaveLength(512);
  });

  it('reports network failures and timeouts', async () => {
    const down = client(() => {
      throw new TypeError('Failed to fetch');
    });
    expect(await down.c.listAllows()).toEqual({ ok: false, error: { kind: 'network', message: 'Failed to fetch' } });

    const hang = client(
      (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          init.signal?.addEventListener('abort', () => {
            reject(new DOMException('aborted', 'AbortError'));
          });
        }),
      { timeoutMs: 20 },
    );
    expect(await hang.c.listAllows()).toEqual({ ok: false, error: { kind: 'timeout', message: 'timed out' } });

    // A reply whose body never ends times out too.
    const slow = client(
      (_url, init) => {
        const stream = new ReadableStream<Uint8Array>({
          start(ctl) {
            ctl.enqueue(new TextEncoder().encode('['));
            init.signal?.addEventListener('abort', () => {
              ctl.error(new DOMException('aborted', 'AbortError'));
            });
          },
        });
        return new Response(stream, { status: 200 });
      },
      { timeoutMs: 20 },
    );
    expect(await slow.c.listAllows()).toEqual({ ok: false, error: { kind: 'timeout', message: 'timed out' } });
  });
});

describe('replies', () => {
  it('checks the allow list and skips malformed items', () => {
    expect(parseAllows({})).toBeNull();
    expect(
      parseAllows([
        allow,
        { ...allow, allow_id: 'a-2', kind: 'ip', target: '100.100.100.100', subdomains: 'yes', retry_after_s: -1 },
        { allow_id: 'a-3' },
        { ...allow, expires_at: '1900000000' },
        { ...allow, target: '' },
        'junk',
        { ...allow, allow_id: 'a-4', kind: 'future-kind', extra: true },
      ]),
    ).toEqual([
      allow,
      { allow_id: 'a-2', kind: 'ip', target: '100.100.100.100', expires_at: 1_900_000_000 },
      { allow_id: 'a-4', kind: 'future-kind', target: 'ads.example', expires_at: 1_900_000_000 },
    ]);
  });

  it('refuses replies that are not an allow list or too large', async () => {
    expect(await client(() => json({ not: 'a list' })).c.listAllows()).toMatchObject({ ok: false, error: { kind: 'bad_response' } });
    expect(await client(() => new Response('not json')).c.listAllows()).toMatchObject({ ok: false, error: { kind: 'bad_response' } });
    const big = new Response('[]', { headers: { 'content-length': String(2 << 20) } });
    expect(await client(() => big).c.listAllows()).toMatchObject({ ok: false, error: { kind: 'bad_response', message: 'reply too large' } });
    const stream = new ReadableStream<Uint8Array>({
      pull(ctl) {
        ctl.enqueue(new Uint8Array(256 * 1024).fill(0x20));
      },
    });
    expect(await client(() => new Response(stream)).c.listAllows()).toMatchObject({ ok: false, error: { message: 'reply too large' } });
  });
});

describe('DoH probe', () => {
  it('sends an uncached GET with OPT and X-Picket-Client to /dns-query on the same origin', async () => {
    const { c, fetch } = client((url) => dnsResponse(reply(queryOf(url), { ede: [{ code: 15, text: 'block=abcdefgh' }] })), {
      randomId: () => 0x4242,
    });
    const r = await c.probe('Ads.Example.com', QTYPE_A);
    expect(r).toMatchObject({ ok: true, value: { id: 0x4242, rcode: 0, ede: [{ code: 15, text: 'block=abcdefgh' }] } });
    const { url, init, headers } = sent(fetch);
    expect(url.startsWith(`${ORIGIN}/dns-query?dns=`)).toBe(true);
    expect(url).not.toMatch(/[=+/]$/);
    expect(init.method).toBe('GET');
    expect(init.cache).toBe('no-store');
    expect(headers.get('x-picket-client')).toBe('extension');
    expect(headers.get('accept')).toBe('application/dns-message');
    expect(headers.has('origin')).toBe(false);
    const q = queryOf(url);
    expect(qname(q)).toBe('Ads.Example.com');
    expect(qtype(q)).toBe(QTYPE_A);
    expect(q[11]).toBe(1); // ARCOUNT: the OPT record
  });

  it('refuses replies that are not DNS answers to the probe', async () => {
    const notDns = client(() => new Response('<html>', { headers: { 'content-type': 'text/html' } }));
    expect(await notDns.c.probe('a.example', QTYPE_A)).toMatchObject({ ok: false, error: { kind: 'bad_response', message: 'not a DNS message' } });
    const wrongId = client((url) => dnsResponse(reply(queryOf(url), { id: 7 })), { randomId: () => 8 });
    expect(await wrongId.c.probe('a.example', QTYPE_A)).toMatchObject({ ok: false, error: { kind: 'bad_response', message: 'id mismatch' } });
    const refused = client(() => new Response('profile not permitted from this address', { status: 403 }));
    expect(await refused.c.probe('a.example', QTYPE_A)).toMatchObject({ ok: false, error: { kind: 'forbidden', status: 403 } });
    const huge = client(() => new Response(new Uint8Array(70_000), { headers: { 'content-type': 'application/dns-message' } }));
    expect(await huge.c.probe('a.example', QTYPE_A)).toMatchObject({ ok: false, error: { message: 'DNS message too large' } });
    expect(await notDns.c.probe('bad name.example', QTYPE_A)).toMatchObject({ ok: false, error: { kind: 'request' } });
  });
});

describe('EdgeClock', () => {
  it("follows the edge's Date header past small skews", () => {
    let now = Date.parse('2026-11-23T12:00:00Z');
    const clock = new EdgeClock(() => now);
    clock.observe('Mon, 23 Nov 2026 12:00:01 GMT', now, now);
    expect(clock.nowS()).toBe(now / 1000); // within 2 s: ignored
    clock.observe('Mon, 23 Nov 2026 12:10:00 GMT', now, now);
    expect(clock.nowS()).toBe(Math.floor((now + 600_500) / 1000));
    clock.observe('garbage', now, now);
    clock.observe(null, now, now);
    expect(clock.nowS()).toBe(Math.floor((now + 600_500) / 1000));
    // However far off: the edge's own Date is its clock (recheck R1: a week's limit fell back to this device's).
    clock.observe('Fri, 13 Nov 2026 12:00:00 GMT', now, now);
    now += 1000;
    expect(clock.nowS()).toBe(Math.floor((now - 10 * 86_400_000 + 500) / 1000));
  });

  it('is fed by every reply', async () => {
    const now = Date.now();
    const date = new Date(now + 3_600_000).toUTCString();
    const { c } = client(() => json([], 200, { date }));
    await c.listAllows();
    expect(Math.abs(c.clock.nowS() - Math.floor((now + 3_600_000) / 1000))).toBeLessThanOrEqual(2);
  });

  it('keeps the skew in storage.session with its age, so a restarted background still knows it', async () => {
    let now = Date.parse('2026-11-23T12:00:00Z');
    const area = new FakeArea();
    const first = new EdgeClock(() => now, sessionClockStore(area, ORIGIN));
    expect(await first.fresh()).toBe(false);
    first.observe(new Date(now + 3_600_000).toUTCString(), now, now);
    await vi.waitFor(() => {
      expect(area.data.get('edgeClock')).toEqual({ origin: ORIGIN, skewMs: 3_600_500, at: now });
    });
    now += 20_000;
    // A new background script: the stored sample, 20 s old, is fresh.
    const second = new EdgeClock(() => now, sessionClockStore(area, ORIGIN));
    expect(second.nowS()).toBe(Math.floor(now / 1000)); // not loaded yet
    expect(await second.fresh()).toBe(true);
    expect(second.nowS()).toBe(Math.floor((now + 3_600_500) / 1000));
    expect(second.skewMs).toBe(3_600_500);
    // Another edge's sample is never used.
    expect(await new EdgeClock(() => now, sessionClockStore(area, 'https://other.home.arpa')).fresh()).toBe(false);
  });

  it('calls a sample stale after CLOCK_FRESH_MS, or when this device stepped its clock back', async () => {
    let now = 1_800_000_000_000;
    const stored: ClockSample[] = [{ skewMs: 5000, at: now }];
    const store = { load: async () => stored[0] ?? null, save: async (s: ClockSample) => void stored.unshift(s) };
    const clock = new EdgeClock(() => now, store);
    expect(await clock.fresh()).toBe(true);
    now += CLOCK_FRESH_MS + 1;
    expect(await clock.fresh()).toBe(false);
    now -= CLOCK_FRESH_MS + 10_000; // stepped back: the sample is from "the future"
    expect(await clock.fresh()).toBe(false);
  });

  it('writes an unchanged skew at most every 10 s, and a changed one at once', () => {
    let now = 1_800_000_000_000;
    const saves: ClockSample[] = [];
    const clock = new EdgeClock(() => now, { load: async () => null, save: async (s) => void saves.push(s) });
    const date = (skew: number) => new Date(now + skew).toUTCString();
    clock.observe(date(60_000), now, now);
    now += 1000;
    clock.observe(date(60_000), now, now);
    expect(saves).toHaveLength(1);
    clock.observe(date(120_000), now, now);
    expect(saves).toHaveLength(2);
    now += 10_000;
    clock.observe(date(120_000), now, now);
    expect(saves).toHaveLength(3);
  });

  it('ignores a malformed stored sample', async () => {
    const area = new FakeArea();
    for (const bad of [null, 'x', { origin: ORIGIN, skewMs: 'x', at: 1 }, { origin: ORIGIN, skewMs: 1e17, at: 1 }, { origin: ORIGIN, skewMs: 1 }]) {
      area.data.set('edgeClock', bad);
      expect(await sessionClockStore(area, ORIGIN).load()).toBeNull();
    }
  });
});

describe("the edge's time for an expires_at", () => {
  it('learns it with a GET first when unknown or stale, and not again while fresh', async () => {
    const edgeAhead = 2 * 3_600_000;
    const { c, fetch } = client(() => json([], 200, { date: new Date(Date.now() + edgeAhead).toUTCString() }));
    const r = await c.edgeNowS();
    expect(sent(fetch).init.method).toBe('GET');
    expect(r.ok && Math.abs(r.value - Math.floor((Date.now() + edgeAhead) / 1000))).toBeLessThanOrEqual(2);
    await c.edgeNowS();
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("passes the GET's failure on rather than guess", async () => {
    const { c } = client(() => json({ error: { code: 'forbidden', message: 'no' } }, 403));
    expect(await c.edgeNowS()).toMatchObject({ ok: false, error: { kind: 'forbidden' } });
  });

  it("is an error, never this device's clock, when the edge sends no usable Date", async () => {
    const { c, fetch } = client(() => json([]));
    expect(await c.edgeNowS()).toMatchObject({ ok: false, error: { kind: 'no_edge_time' } });
    expect(fetch).toHaveBeenCalledTimes(1);
    const garbled = client(() => json([], 200, { date: 'yesterday' }));
    expect(await garbled.c.edgeNowS()).toMatchObject({ ok: false, error: { kind: 'no_edge_time' } });
  });

  it("uses a Date far from this device's clock as it is", async () => {
    const edgeBehind = 8 * 86_400_000;
    const { c } = client(() => json([], 200, { date: new Date(Date.now() - edgeBehind).toUTCString() }));
    const r = await c.edgeNowS();
    expect(r.ok && Math.abs(r.value - Math.floor((Date.now() - edgeBehind) / 1000))).toBeLessThanOrEqual(2);
  });
});
