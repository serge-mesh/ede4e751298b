// What the block page shows (browser-extension.md §3 step 3), carried in its URL's query so a
// reload of the block page keeps working. The block page isn't web-accessible, so only the
// extension can open it; its parameters are still checked like any input.
//
// Long page URLs (SAML and OAuth redirects run past 8 KB): up to MAX_INLINE_URL characters ride
// in the query; longer ones, up to MAX_URL, are kept in `storage.session` under a random id and
// the query names the id. Such URLs can carry assertions and codes, so one is kept only while
// its block page can use it (browser-extension.md §4): per tab, until the tab leaves the block
// page or closes, and at most MAX_KEPT_URLS at once. A longer URL, or one no longer kept, still
// gets a working block page: the allow works, and the user loads the page again.

import type { DnsBlock } from './ede';

export type BlockOf<U> = ({ kind: 'dns'; url: U; name: string } & DnsBlock) | { kind: 'ip'; url: U; ip: string };
/** A block as the background found it: `url` is the page load that failed. */
export type BlockInfo = BlockOf<string>;
/** A block as the block page reads it: `url` is null when it was too long to keep. */
export type PageBlock = BlockOf<string | null>;

/** Longest page URL the extension keeps and reloads (browsers accept up to ~2 MB). */
export const MAX_URL = 65_536;
/** Longest page URL carried in the block page's own query. */
export const MAX_INLINE_URL = 4096;
/** Most long URLs kept at once (one per tab); the oldest goes first. */
export const MAX_KEPT_URLS = 16;
/** The `storage.session` key long URLs are kept under. */
export const KEPT_KEY = 'blockUrls';

const MAX_FIELD = 255;
const BLOCK_ID = /^[A-Za-z0-9._~-]{1,64}$/;
const REF = /^[0-9a-f]{32}$/;

export interface QueryOptions {
  /** The id a long URL is kept under (`keepUrl`). */
  ref?: string | null;
  /** The block page replaced the failed page's history entry (Firefox `loadReplace`). */
  replaced?: boolean;
}

export interface ParsedQuery {
  info: PageBlock;
  /** The id of a kept long URL to read (`keptUrl`); `info.url` is null until then. */
  ref: string | null;
  replaced: boolean;
}

function field(p: URLSearchParams, key: string): string | undefined {
  const v = p.get(key);
  return v !== null && v.length > 0 && v.length <= MAX_FIELD ? v : undefined;
}

/** A page URL the extension may load again: `http:` or `https:`, at most MAX_URL characters. */
export function pageUrl(raw: string | null): string | null {
  if (raw === null || raw.length > MAX_URL) {
    return null;
  }
  try {
    const u = new URL(raw);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null;
  } catch {
    return null;
  }
}

/** The block page's query string for a block. */
export function toQuery(info: BlockInfo, opts: QueryOptions = {}): string {
  const p = new URLSearchParams();
  p.set('kind', info.kind);
  if (info.url.length <= MAX_INLINE_URL) {
    p.set('url', info.url);
  } else if (opts.ref !== undefined && opts.ref !== null) {
    p.set('ref', opts.ref);
  } else {
    p.set('long', '1');
  }
  if (opts.replaced === true) {
    p.set('replaced', '1');
  }
  if (info.kind === 'ip') {
    p.set('ip', info.ip);
  } else {
    p.set('name', info.name);
    p.set('block', info.blockId);
    for (const k of ['bundle', 'head', 'lookup', 'verdict'] as const) {
      const v = info[k];
      if (v !== undefined) {
        p.set(k, v);
      }
    }
  }
  return p.toString();
}

/** The block a block page's query string describes, or null if it is malformed. */
export function fromQuery(search: string): ParsedQuery | null {
  const p = new URLSearchParams(search);
  let url: string | null = null;
  let ref: string | null = null;
  if (p.has('url')) {
    url = pageUrl(p.get('url'));
    if (url === null) {
      return null;
    }
  } else if (p.has('ref')) {
    ref = p.get('ref');
    if (ref === null || !REF.test(ref)) {
      return null;
    }
  } else if (p.get('long') !== '1') {
    return null;
  }
  const replaced = p.get('replaced') === '1';
  const kind = p.get('kind');
  if (kind === 'ip') {
    const ip = field(p, 'ip');
    return ip !== undefined && /^[0-9a-f.:]+$/i.test(ip) ? { info: { kind: 'ip', url, ip }, ref, replaced } : null;
  }
  if (kind !== 'dns') {
    return null;
  }
  const name = field(p, 'name');
  const blockId = field(p, 'block');
  if (name === undefined || blockId === undefined || !BLOCK_ID.test(blockId)) {
    return null;
  }
  const info: PageBlock = { kind: 'dns', url, name, blockId };
  for (const k of ['bundle', 'head', 'lookup', 'verdict'] as const) {
    const v = field(p, k);
    if (v !== undefined) {
      info[k] = v;
    }
  }
  return { info, ref, replaced };
}

/** A long URL kept for a tab's block page, under the id its query names. */
export interface KeptUrl {
  id: string;
  url: string;
}

/** A new random id for a kept URL. */
export function newRef(): string {
  return [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Kept URLs as stored (`[{tab, id, url}]`, oldest first), checked; malformed entries are skipped. */
export function parseKeptUrls(x: unknown): [number, KeptUrl][] {
  if (!Array.isArray(x)) {
    return [];
  }
  const out: [number, KeptUrl][] = [];
  for (const e of x.slice(-MAX_KEPT_URLS) as unknown[]) {
    if (typeof e !== 'object' || e === null) {
      continue;
    }
    const { tab, id, url } = e as Record<string, unknown>;
    if (typeof tab === 'number' && Number.isSafeInteger(tab) && tab >= 0 && typeof id === 'string' && REF.test(id) && typeof url === 'string' && url.length <= MAX_URL) {
      out.push([tab, { id, url }]);
    }
  }
  return out;
}

/** What is stored for kept URLs. */
export function serializeKeptUrls(entries: readonly [number, KeptUrl][]): unknown {
  return entries.map(([tab, k]) => ({ tab, id: k.id, url: k.url }));
}

/** The part of `storage.session` the block page reads kept URLs from. */
export interface UrlArea {
  get(keys: string): Promise<Record<string, unknown>>;
}

/** A kept URL by its id, or null when it is no longer kept. */
export async function keptUrl(area: UrlArea, id: string): Promise<string | null> {
  const hit = parseKeptUrls((await area.get(KEPT_KEY))[KEPT_KEY]).find(([, k]) => k.id === id);
  return hit === undefined ? null : pageUrl(hit[1].url);
}
