// Settings (browser-extension.md §2, §4): the extension stores only the edge API URL and,
// optionally, core's UI URL, in `storage.local`.

import browser from 'webextension-polyfill';

export interface Settings {
  /** The edge API origin, e.g. `https://dns.home.arpa:9853`; null until set up. */
  edgeUrl: string | null;
  /** Core's UI URL; null when not set. */
  coreUrl: string | null;
}

export type UrlCheck = { ok: true; url: string } | { ok: false; reason: string };

const MAX_URL = 2048;
const KEYS = ['edgeUrl', 'coreUrl'] as const;

/**
 * Adds `scheme` to an input typed without one (`dns.home.arpa:9853`). A scheme is `x://`, or
 * `x:` followed by something other than a port number (`javascript:…`, kept and refused later).
 */
function withScheme(input: string, scheme: string): string {
  const hasScheme = /^[a-z][a-z0-9+.-]*:(\/\/|(?!\d))/i.test(input);
  return hasScheme ? input : `${scheme}//${input}`;
}

/**
 * Checks an edge API URL and returns its origin. The bypass API and the DoH probe are served by
 * the edge's DoH listeners (api.md §6; edge.md §5), so only `https:` origins are accepted.
 */
export function parseEdgeUrl(raw: string): UrlCheck {
  const input = raw.trim();
  if (input.length === 0) {
    return { ok: false, reason: 'Enter the edge API URL, e.g. https://dns.home.arpa:9853.' };
  }
  if (input.length > MAX_URL) {
    return { ok: false, reason: 'The URL is too long.' };
  }
  let u: URL;
  try {
    u = new URL(withScheme(input, 'https:'));
  } catch {
    return { ok: false, reason: 'That is not a valid URL.' };
  }
  if (u.protocol !== 'https:') {
    return { ok: false, reason: 'The edge API is served over HTTPS: use an https:// URL.' };
  }
  if (u.username !== '' || u.password !== '') {
    return { ok: false, reason: 'The URL must not hold a user name or password.' };
  }
  if ((u.pathname !== '/' && u.pathname !== '') || u.search !== '' || u.hash !== '') {
    return { ok: false, reason: 'Enter only the scheme, host and port, e.g. https://dns.home.arpa:9853.' };
  }
  return { ok: true, url: u.origin };
}

/** Checks core's UI URL (optional: empty input is null). */
export function parseCoreUrl(raw: string): UrlCheck | { ok: true; url: null } {
  const input = raw.trim();
  if (input.length === 0) {
    return { ok: true, url: null };
  }
  if (input.length > MAX_URL) {
    return { ok: false, reason: 'The URL is too long.' };
  }
  let u: URL;
  try {
    u = new URL(withScheme(input, 'https:'));
  } catch {
    return { ok: false, reason: 'That is not a valid URL.' };
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') {
    return { ok: false, reason: "Core's UI URL must start with https:// or http://." };
  }
  if (u.username !== '' || u.password !== '') {
    return { ok: false, reason: 'The URL must not hold a user name or password.' };
  }
  u.hash = '';
  return { ok: true, url: u.href };
}

/**
 * The host permission pattern for an origin. Match patterns carry no port (Firefox ignores ports;
 * Chromium matches every port when none is given), so the edge's port needs nothing extra.
 */
export function originPattern(origin: string): string {
  const u = new URL(origin);
  return `${u.protocol}//${u.hostname}/*`;
}

function validStored(value: unknown, check: (s: string) => { ok: boolean; url?: string | null }): string | null {
  if (typeof value !== 'string') {
    return null;
  }
  const r = check(value);
  return r.ok && typeof r.url === 'string' ? r.url : null;
}

export async function loadSettings(): Promise<Settings> {
  const got = await browser.storage.local.get([...KEYS]);
  return {
    edgeUrl: validStored(got.edgeUrl, parseEdgeUrl),
    coreUrl: validStored(got.coreUrl, parseCoreUrl),
  };
}

export async function saveSettings(s: Settings): Promise<void> {
  const set: Record<string, string> = {};
  const remove: string[] = [];
  for (const k of KEYS) {
    const v = s[k];
    if (v === null) {
      remove.push(k);
    } else {
      set[k] = v;
    }
  }
  await browser.storage.local.set(set);
  if (remove.length > 0) {
    await browser.storage.local.remove(remove);
  }
}
