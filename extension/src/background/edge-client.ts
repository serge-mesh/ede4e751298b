// The edge client: the bypass API (api.md §6) and the DoH probe (edge.md §12). Only the
// background script uses it (browser-extension.md §4).
//
// - Every request carries `X-Picket-Client: extension`. The browser sets `Origin` itself
//   (`chrome-extension://…` or `moz-extension://…`, or none on some GETs), which the edge
//   accepts; the client never sets or forges it, sends no credentials, follows no redirect and
//   bypasses the HTTP cache.
// - Requests are checked against the edge's limits before they are sent, every call has a
//   timeout, and reply bodies are read up to a cap.
// - Replies are untrusted: the allow list and error bodies are checked field by field.

import {
  ALLOWS_PATH,
  CLIENT_HEADER,
  CLIENT_HEADER_VALUE,
  DOH_PATH,
  fail,
  MAX_BODY,
  MAX_ENTRIES,
  MAX_ID_LENGTH,
  ok,
  type AllowEntry,
  type AllowView,
  type ApiError,
  type ErrorKind,
  type Result,
} from '../shared/api';
import { base64url, buildQuery, DnsError, MAX_MESSAGE, parseReply, type DnsReply } from '../shared/dns';
import { isObj, type SessionArea } from './session';

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

/** Largest allow list read (max_active is 50 by default; this leaves ample room). */
export const MAX_RESPONSE = 1 << 20;
/** Largest error body read. */
const MAX_ERROR_BODY = 16 * 1024;
/** Most allows kept from one reply. */
const MAX_ALLOWS = 10_000;
export const API_TIMEOUT_MS = 10_000;
export const PROBE_TIMEOUT_MS = 5_000;

/** How long a learned skew is trusted before a request learns it again (README §2 "Clocks"). */
export const CLOCK_FRESH_MS = 60_000;
/** Least time between writes of an unchanged skew to `storage.session`. */
const CLOCK_SAVE_EVERY_MS = 10_000;
/** Largest skew a stored sample may hold: the span of JavaScript dates. */
const MAX_SKEW_MS = 8.64e15;

/** A learned skew: the edge's clock minus this device's, and when (device ms) it was learned. */
export interface ClockSample {
  skewMs: number;
  at: number;
}

/** Where a sample outlives the background script (Brave's worker and Firefox's event page unload when idle). */
export interface ClockStore {
  load(): Promise<ClockSample | null>;
  save(s: ClockSample): Promise<void>;
}

/** A `ClockStore` in `storage.session`, per edge origin (another edge's skew is never used). */
export function sessionClockStore(area: SessionArea, origin: string): ClockStore {
  const key = 'edgeClock';
  return {
    load: async () => {
      const v = (await area.get(key))[key];
      if (!isObj(v) || v.origin !== origin) {
        return null;
      }
      const { skewMs, at } = v;
      return typeof skewMs === 'number' && Number.isFinite(skewMs) && Math.abs(skewMs) <= MAX_SKEW_MS && typeof at === 'number' && Number.isFinite(at)
        ? { skewMs, at }
        : null;
    },
    save: (s) => area.set({ [key]: { origin, skewMs: s.skewMs, at: s.at } }),
  };
}

/**
 * The edge's wall clock as seen through its `Date` header, so `expires_at` (Unix seconds on the
 * edge) means the duration the user picked however far this device's clock is off: the header
 * is the edge's own, over TLS, and the edge applies `expires_at` by that clock. The skew is
 * kept in `storage.session` with when it was learned, since the background script may unload
 * between the probe that opened a block page and the allow chosen there (README §2 "Restarts").
 *
 * A sample is fresh for CLOCK_FRESH_MS by this device's clock: a clock step after it makes it
 * look older (forward) or from the future (backward), and either way stale, so a skew is never
 * off by more than CLOCK_FRESH_MS plus the header's 1 s resolution.
 */
export class EdgeClock {
  private sample: ClockSample | null = null;
  private loaded = false;
  private saved: ClockSample | null = null;

  constructor(
    private readonly now: () => number = Date.now,
    private readonly store: ClockStore | null = null,
  ) {}

  /** Learns the skew from a reply's `Date` header (1 s resolution, so small skews are ignored). */
  observe(dateHeader: string | null, sentAt: number, receivedAt: number): void {
    if (dateHeader === null) {
      return;
    }
    const server = Date.parse(dateHeader);
    if (Number.isNaN(server)) {
      return;
    }
    const skew = server + 500 - (sentAt + receivedAt) / 2;
    const sample = { skewMs: Math.abs(skew) < 2000 ? 0 : Math.round(skew), at: receivedAt };
    this.sample = sample;
    this.loaded = true;
    const last = this.saved;
    if (
      this.store !== null &&
      (last === null || Math.abs(last.skewMs - sample.skewMs) >= 1000 || sample.at - last.at >= CLOCK_SAVE_EVERY_MS || sample.at < last.at)
    ) {
      this.saved = sample;
      void this.store.save(sample).catch(() => undefined);
    }
  }

  /** True when the skew was learned recently enough to compute an `expires_at` from (loads a stored one first). */
  async fresh(): Promise<boolean> {
    if (!this.loaded) {
      this.loaded = true;
      const stored = this.store === null ? null : await this.store.load().catch(() => null);
      if (this.sample === null && stored !== null) {
        this.sample = stored;
        this.saved = stored;
      }
    }
    if (this.sample === null) {
      return false;
    }
    const age = this.now() - this.sample.at;
    return age >= 0 && age <= CLOCK_FRESH_MS;
  }

  /** The edge's clock minus this device's, in ms (0 until learned). */
  get skewMs(): number {
    return this.sample?.skewMs ?? 0;
  }

  /** The edge's time, in Unix seconds. */
  nowS(): number {
    return Math.floor(this.nowMs() / 1000);
  }

  /** The edge's time, in ms since the epoch. */
  nowMs(): number {
    return this.now() + this.skewMs;
  }
}

export interface EdgeClientOptions {
  origin: string;
  fetch?: FetchLike;
  clock?: EdgeClock;
  /** Where the clock keeps its skew across background restarts (when `clock` isn't given). */
  clockStore?: ClockStore;
  timeoutMs?: number;
  probeTimeoutMs?: number;
  /** A random DNS message id. */
  randomId?: () => number;
}

const isInt = (x: unknown): x is number => typeof x === 'number' && Number.isSafeInteger(x);

/** The allows a reply lists; null when the reply isn't an array. Malformed items are skipped. */
export function parseAllows(x: unknown): AllowView[] | null {
  if (!Array.isArray(x)) {
    return null;
  }
  const out: AllowView[] = [];
  for (const item of x.slice(0, MAX_ALLOWS)) {
    if (!isObj(item)) {
      continue;
    }
    const { allow_id: id, kind, target, subdomains, expires_at: exp, retry_after_s: retry } = item;
    if (typeof id !== 'string' || id.length === 0 || id.length > MAX_ID_LENGTH * 2) {
      continue;
    }
    if (typeof kind !== 'string' || kind.length === 0 || kind.length > 32) {
      continue;
    }
    if (typeof target !== 'string' || target.length === 0 || target.length > 1024 || !isInt(exp)) {
      continue;
    }
    const a: AllowView = { allow_id: id, kind, target, expires_at: exp };
    if (typeof subdomains === 'boolean') {
      a.subdomains = subdomains;
    }
    if (isInt(retry) && retry >= 0) {
      a.retry_after_s = Math.min(retry, 86_400);
    }
    out.push(a);
  }
  return out;
}

function kindOf(status: number): ErrorKind {
  switch (status) {
    case 403:
      return 'forbidden';
    case 409:
      return 'conflict';
    case 503:
      return 'unavailable';
    case 429:
      return 'busy';
    case 400:
    case 408:
    case 413:
      return 'invalid';
    case 404:
      return 'not_found';
    default:
      return 'http';
  }
}

/** An error reply as an `ApiError`: `{"error": {"code", "message", "index"?}}` (api.md §6). */
export function errorFromResponse(
  status: number,
  body: unknown,
  retryAfter: string | null,
  entries = 0,
): ApiError {
  const e: ApiError = { kind: kindOf(status), status, message: `HTTP ${String(status)}` };
  const detail = isObj(body) ? body.error : undefined;
  if (isObj(detail)) {
    const { code, message, index } = detail;
    if (typeof code === 'string' && /^[a-z0-9_]{1,64}$/.test(code)) {
      e.code = code;
    }
    if (typeof message === 'string' && message.length > 0) {
      e.message = message.slice(0, 512);
    }
    // `index` names the entry the error is about; one past what was sent is ignored.
    if (isInt(index) && index >= 0 && index < entries) {
      e.index = index;
    }
  }
  if (retryAfter !== null && /^\d{1,4}$/.test(retryAfter.trim())) {
    e.retryAfterS = Math.min(Number(retryAfter.trim()), 3600);
  }
  return e;
}

/** Checks entries against the edge's limits; null when they fit. */
export function checkEntries(entries: readonly AllowEntry[]): ApiError | null {
  const bad = (message: string, index?: number): ApiError =>
    index === undefined ? { kind: 'request', message } : { kind: 'request', message, index };
  if (entries.length === 0) {
    return bad('No allows to change.');
  }
  if (entries.length > MAX_ENTRIES) {
    return bad(`At most ${String(MAX_ENTRIES)} allows can change at once.`);
  }
  for (const [i, e] of entries.entries()) {
    const ids = [
      'block_id' in e ? e.block_id : undefined,
      'ip' in e ? e.ip : undefined,
      'allow_id' in e ? e.allow_id : undefined,
    ].filter((v) => v !== undefined);
    if (ids.length !== 1) {
      return bad('An entry names exactly one of block_id, ip and allow_id.', i);
    }
    const id = ids[0] ?? '';
    if (id.length === 0 || new TextEncoder().encode(id).length > MAX_ID_LENGTH) {
      return bad('An identifier is empty or longer than the edge accepts.', i);
    }
    if (!isInt(e.expires_at) || e.expires_at < 0) {
      return bad('expires_at must be Unix seconds.', i);
    }
  }
  return null;
}

async function readCapped(res: Response, max: number): Promise<Uint8Array | null> {
  const declared = res.headers.get('content-length');
  if (declared !== null && Number(declared) > max) {
    await res.body?.cancel().catch(() => undefined);
    return null;
  }
  if (res.body === null) {
    return new Uint8Array(0);
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.byteLength;
  }
  return out;
}

function jsonOf(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    return undefined;
  }
}

export class EdgeClient {
  readonly origin: string;
  readonly clock: EdgeClock;
  private readonly fetchFn: FetchLike;
  private readonly timeoutMs: number;
  private readonly probeTimeoutMs: number;
  private readonly randomId: () => number;

  constructor(opts: EdgeClientOptions) {
    this.origin = new URL(opts.origin).origin;
    this.fetchFn = opts.fetch ?? ((input, init) => fetch(input, init));
    this.clock = opts.clock ?? new EdgeClock(Date.now, opts.clockStore ?? null);
    this.timeoutMs = opts.timeoutMs ?? API_TIMEOUT_MS;
    this.probeTimeoutMs = opts.probeTimeoutMs ?? PROBE_TIMEOUT_MS;
    this.randomId = opts.randomId ?? (() => crypto.getRandomValues(new Uint16Array(1))[0] ?? 0);
  }

  /** `GET /v1/temporary-allows`: this device's active allows. */
  listAllows(): Promise<Result<AllowView[]>> {
    return this.api('GET', null);
  }

  /**
   * The edge's time in Unix seconds, to compute an `expires_at` from. When the clock has no fresh
   * sample (a new background script, or the last reply too long ago), a `GET` learns it first.
   * If even that reply carries no usable `Date`, the edge's time is unknown: an error, never this
   * device's clock, which may be off by any amount (the edge would then clamp or reject the allow).
   */
  async edgeNowS(): Promise<Result<number>> {
    if (!(await this.clock.fresh())) {
      const r = await this.listAllows();
      if (!r.ok) {
        return r;
      }
      if (!(await this.clock.fresh())) {
        return fail({ kind: 'no_edge_time', message: "the edge's reply had no usable Date header" });
      }
    }
    return ok(this.clock.nowS());
  }

  /** `PATCH /v1/temporary-allows`: creates or re-times the entries given; a past `expires_at` revokes. */
  patch(entries: readonly AllowEntry[]): Promise<Result<AllowView[]>> {
    const bad = checkEntries(entries);
    return bad === null ? this.api('PATCH', entries) : Promise.resolve(fail(bad));
  }

  /** Sends one DoH probe (a GET, uncached, with OPT and the extension header). */
  async probe(name: string, qtype: number): Promise<Result<DnsReply>> {
    let query: Uint8Array;
    try {
      query = buildQuery(name, qtype, this.randomId() & 0xffff);
    } catch (e) {
      return fail({ kind: 'request', message: e instanceof Error ? e.message : 'bad name' });
    }
    const url = `${this.origin}${DOH_PATH}?dns=${base64url(query)}`;
    const init: RequestInit = { method: 'GET', headers: { Accept: 'application/dns-message' } };
    return this.exchange(url, init, this.probeTimeoutMs, async (r) => {
      if (r.status !== 200) {
        const body = await readCapped(r, MAX_ERROR_BODY);
        return fail(errorFromResponse(r.status, body === null ? undefined : jsonOf(body), r.headers.get('retry-after')));
      }
      const type = r.headers.get('content-type');
      if (type !== null && type.split(';')[0]?.trim().toLowerCase() !== 'application/dns-message') {
        await r.body?.cancel().catch(() => undefined);
        return fail({ kind: 'bad_response', status: 200, message: 'not a DNS message' });
      }
      const body = await readCapped(r, MAX_MESSAGE);
      if (body === null) {
        return fail({ kind: 'bad_response', status: 200, message: 'DNS message too large' });
      }
      try {
        return ok(parseReply(body, query));
      } catch (e) {
        return fail({
          kind: 'bad_response',
          status: 200,
          message: e instanceof DnsError ? e.message : 'malformed DNS message',
        });
      }
    });
  }

  private api(method: 'GET' | 'PATCH', entries: readonly AllowEntry[] | null): Promise<Result<AllowView[]>> {
    const headers: Record<string, string> = { Accept: 'application/json' };
    const init: RequestInit = { method, headers };
    if (entries !== null) {
      const body = JSON.stringify(entries);
      if (new TextEncoder().encode(body).length > MAX_BODY) {
        return Promise.resolve(fail({ kind: 'request', message: 'The request is larger than the edge accepts.' }));
      }
      headers['Content-Type'] = 'application/json';
      init.body = body;
    }
    return this.exchange(`${this.origin}${ALLOWS_PATH}`, init, this.timeoutMs, async (r) => {
      if (r.status !== 200) {
        const raw = await readCapped(r, MAX_ERROR_BODY);
        const body = raw === null ? undefined : jsonOf(raw);
        return fail(errorFromResponse(r.status, body, r.headers.get('retry-after'), entries?.length ?? 0));
      }
      const raw = await readCapped(r, MAX_RESPONSE);
      if (raw === null) {
        return fail({ kind: 'bad_response', status: 200, message: 'reply too large' });
      }
      const allows = parseAllows(jsonOf(raw));
      return allows === null ? fail({ kind: 'bad_response', status: 200, message: 'not an allow list' }) : ok(allows);
    });
  }

  /**
   * One request with the extension header, no credentials, cache or redirects, and a timeout
   * that covers reading the reply in `handle`.
   */
  private async exchange<T>(
    url: string,
    init: RequestInit,
    timeoutMs: number,
    handle: (r: Response) => Promise<Result<T>>,
  ): Promise<Result<T>> {
    const ctl = new AbortController();
    const timer = setTimeout(() => {
      ctl.abort();
    }, timeoutMs);
    const headers = new Headers(init.headers);
    headers.set(CLIENT_HEADER, CLIENT_HEADER_VALUE);
    const sentAt = Date.now();
    try {
      const r = await this.fetchFn(url, {
        ...init,
        headers,
        cache: 'no-store',
        credentials: 'omit',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        signal: ctl.signal,
      });
      this.clock.observe(r.headers.get('date'), sentAt, Date.now());
      return await handle(r);
    } catch (e) {
      if (ctl.signal.aborted) {
        return fail({ kind: 'timeout', message: 'timed out' });
      }
      return fail({ kind: 'network', message: e instanceof Error ? e.message : String(e) });
    } finally {
      clearTimeout(timer);
    }
  }
}
