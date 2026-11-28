import { describe, expect, it } from 'vitest';

import { MAX_URL } from '../src/shared/block-info';
import { parseRequest } from '../src/shared/messages';

describe('parseRequest', () => {
  it('accepts each request', () => {
    const good = [
      { type: 'getState' },
      { type: 'testEdge' },
      { type: 'listAllows' },
      { type: 'saveSettings', edgeUrl: 'https://e', coreUrl: '' },
      { type: 'createAllows', durationS: 900, entries: [{ kind: 'dns', blockId: 'abcdefgh', name: 'a.example', subdomains: false }] },
      { type: 'createAllows', durationS: 3600, entries: [{ kind: 'ip', ip: '100.100.100.100' }] },
      { type: 'endAllow', allowId: 'a-0123456789ab' },
      { type: 'tabBlocks', tabId: 3 },
      { type: 'reloadAfterAllow', url: 'https://a.example/' },
      // A long SAML or OAuth URL is kept (block-info.ts MAX_URL).
      { type: 'reloadAfterAllow', url: `https://sso.example/?SAMLRequest=${'A'.repeat(20_000)}` },
    ];
    for (const g of good) {
      expect(parseRequest(g), JSON.stringify(g)).toEqual(g);
    }
  });

  it('drops unknown fields', () => {
    expect(parseRequest({ type: 'getState', extra: 1 })).toEqual({ type: 'getState' });
  });

  it('refuses anything else, and requests past the limits', () => {
    const entry = { kind: 'ip', ip: '1.2.3.4' };
    const bad: unknown[] = [
      null,
      'getState',
      [],
      { type: 'nope' },
      { type: 'saveSettings', edgeUrl: 1, coreUrl: '' },
      { type: 'createAllows', durationS: 0, entries: [entry] },
      { type: 'createAllows', durationS: 1.5, entries: [entry] },
      { type: 'createAllows', durationS: 3_000_000, entries: [entry] },
      { type: 'createAllows', durationS: 900, entries: [] },
      { type: 'createAllows', durationS: 900, entries: new Array(257).fill(entry) },
      { type: 'createAllows', durationS: 900, entries: [{ kind: 'dns', blockId: 'x' }] },
      { type: 'createAllows', durationS: 900, entries: [{ kind: 'ip', ip: 'x'.repeat(65) }] },
      { type: 'createAllows', durationS: 900, entries: [{ kind: 'other', ip: '1.2.3.4' }] },
      { type: 'endAllow', allowId: '' },
      { type: 'endAllow', allowId: 'a'.repeat(65) },
      { type: 'tabBlocks', tabId: -1 },
      { type: 'tabBlocks', tabId: '3' },
      { type: 'reloadAfterAllow', url: `https://a.example/?${'x'.repeat(MAX_URL)}` },
    ];
    for (const b of bad) {
      expect(parseRequest(b), JSON.stringify(b).slice(0, 80)).toBeNull();
    }
  });
});
