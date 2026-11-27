import { beforeEach, describe, expect, it } from 'vitest';

import {
  fromQuery,
  keptUrl,
  MAX_INLINE_URL,
  MAX_KEPT_URLS,
  MAX_URL,
  newRef,
  parseKeptUrls,
  serializeKeptUrls,
  toQuery,
  type BlockInfo,
} from '../src/shared/block-info';
import fake, { resetFakeBrowser } from './fake-browser';

const DNS: BlockInfo = { kind: 'dns', url: 'https://ads.example/page', name: 'ads.example', blockId: 'abcdefgh', bundle: 'b', head: 'h1' };

beforeEach(resetFakeBrowser);

describe("the block page's query", () => {
  it('carries a block and its URL', () => {
    expect(fromQuery(toQuery(DNS))).toEqual({ info: DNS, ref: null, replaced: false });
    const ip: BlockInfo = { kind: 'ip', url: 'https://100.100.100.100/test', ip: '100.100.100.100' };
    expect(fromQuery(toQuery(ip, { replaced: true }))).toEqual({ info: ip, ref: null, replaced: true });
  });

  it('names a kept id for a URL longer than MAX_INLINE_URL, or says it was too long to keep', () => {
    const long = { ...DNS, url: `https://sso.example/?q=${'A'.repeat(MAX_INLINE_URL)}` };
    const ref = '0123456789abcdef0123456789abcdef';
    const q = toQuery(long, { ref });
    expect(q.length).toBeLessThan(1024);
    expect(fromQuery(q)).toEqual({ info: { ...long, url: null }, ref, replaced: false });
    expect(fromQuery(toQuery(long))).toEqual({ info: { ...long, url: null }, ref: null, replaced: false });
  });

  it('refuses malformed parameters', () => {
    for (const q of [
      'kind=dns&name=x&block=abcdefgh',
      'kind=dns&url=javascript:alert(1)&name=x&block=abcdefgh',
      `kind=dns&url=${encodeURIComponent(`https://x.example/?${'a'.repeat(MAX_URL)}`)}&name=x&block=abcdefgh`,
      'kind=dns&ref=NOTHEX&name=x&block=abcdefgh',
      'kind=dns&long=1&name=x&block=bad id',
      'kind=other&long=1',
      'kind=ip&long=1&ip=<b>',
    ]) {
      expect(fromQuery(q), q).toBeNull();
    }
  });
});

describe('kept long URLs', () => {
  it('are stored per tab under a random id, the newest MAX_KEPT_URLS, each up to MAX_URL', async () => {
    const urls = Array.from({ length: MAX_KEPT_URLS + 2 }, (_, i) => `https://sso.example/${String(i)}?${'A'.repeat(MAX_INLINE_URL)}`);
    const entries = urls.map((url, tab) => [tab, { id: newRef(), url }] as [number, { id: string; url: string }]);
    expect(new Set(entries.map(([, k]) => k.id)).size).toBe(urls.length);
    fake.storage.session.data.set('blockUrls', serializeKeptUrls(entries));
    expect(parseKeptUrls(fake.storage.session.data.get('blockUrls'))).toEqual(entries.slice(-MAX_KEPT_URLS));
    expect(await keptUrl(fake.storage.session, entries[0]?.[1].id ?? '')).toBeNull();
    expect(await keptUrl(fake.storage.session, entries[2]?.[1].id ?? '')).toBe(urls[2]);
    expect(await keptUrl(fake.storage.session, entries.at(-1)?.[1].id ?? '')).toBe(urls.at(-1));
  });

  it('reads back only well-formed entries and page URLs', async () => {
    const id = (c: string) => c.repeat(32);
    fake.storage.session.data.set('blockUrls', [
      { tab: 1, id: id('a'), url: 'javascript:alert(1)' },
      { tab: 2, id: id('b'), url: 7 },
      { tab: 3, id: 'short', url: 'https://x.example/' },
      { tab: -1, id: id('c'), url: 'https://x.example/' },
      { tab: 4, id: id('d'), url: `https://x.example/?${'a'.repeat(MAX_URL)}` },
      'x',
      { tab: 5, id: id('e'), url: 'https://ok.example/' },
    ]);
    expect(await keptUrl(fake.storage.session, id('a'))).toBeNull();
    expect(await keptUrl(fake.storage.session, id('b'))).toBeNull();
    expect(parseKeptUrls(fake.storage.session.data.get('blockUrls'))).toEqual([
      [1, { id: id('a'), url: 'javascript:alert(1)' }],
      [5, { id: id('e'), url: 'https://ok.example/' }],
    ]);
    expect(await keptUrl(fake.storage.session, id('e'))).toBe('https://ok.example/');
  });
});
