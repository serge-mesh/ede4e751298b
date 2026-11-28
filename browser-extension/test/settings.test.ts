import { beforeEach, describe, expect, it } from 'vitest';

import { loadSettings, originPattern, parseCoreUrl, parseEdgeUrl, saveSettings } from '../src/shared/settings';
import fake, { resetFakeBrowser } from './fake-browser';

beforeEach(resetFakeBrowser);

describe('parseEdgeUrl', () => {
  it('keeps only the https origin', () => {
    expect(parseEdgeUrl(' https://dns.home.arpa:9853 ')).toEqual({ ok: true, url: 'https://dns.home.arpa:9853' });
    expect(parseEdgeUrl('https://dns.home.arpa:9853/')).toEqual({ ok: true, url: 'https://dns.home.arpa:9853' });
    expect(parseEdgeUrl('dns.home.arpa:9853')).toEqual({ ok: true, url: 'https://dns.home.arpa:9853' });
    expect(parseEdgeUrl('https://DNS.Home.Arpa:443')).toEqual({ ok: true, url: 'https://dns.home.arpa' });
    expect(parseEdgeUrl('https://[fd00::1]:9853')).toEqual({ ok: true, url: 'https://[fd00::1]:9853' });
  });

  it('refuses what the bypass API cannot be', () => {
    for (const bad of [
      '',
      'http://dns.home.arpa:9853',
      'https://user:pw@dns.home.arpa',
      'https://dns.home.arpa/v1/temporary-allows',
      'https://dns.home.arpa/?x=1',
      'https://dns.home.arpa/#x',
      'ftp://dns.home.arpa',
      'https://',
      `https://${'a'.repeat(3000)}.arpa`,
    ]) {
      expect(parseEdgeUrl(bad).ok, bad).toBe(false);
    }
  });
});

describe('parseCoreUrl', () => {
  it('is optional, http or https, without credentials or fragment', () => {
    expect(parseCoreUrl('  ')).toEqual({ ok: true, url: null });
    expect(parseCoreUrl('core.home.arpa:8443')).toEqual({ ok: true, url: 'https://core.home.arpa:8443/' });
    expect(parseCoreUrl('http://core.home.arpa:8080/ui#x')).toEqual({ ok: true, url: 'http://core.home.arpa:8080/ui' });
    expect(parseCoreUrl('javascript:alert(1)').ok).toBe(false);
    expect(parseCoreUrl('https://a:b@core').ok).toBe(false);
  });
});

describe('originPattern', () => {
  it('drops the port (match patterns carry none)', () => {
    expect(originPattern('https://dns.home.arpa:9853')).toBe('https://dns.home.arpa/*');
    expect(originPattern('https://[fd00::1]:9853')).toBe('https://[fd00::1]/*');
  });
});

describe('storage', () => {
  it('stores only the two URLs and reads back what is valid', async () => {
    await saveSettings({ edgeUrl: 'https://dns.home.arpa:9853', coreUrl: null });
    expect([...fake.storage.local.data.keys()]).toEqual(['edgeUrl']);
    expect(await loadSettings()).toEqual({ edgeUrl: 'https://dns.home.arpa:9853', coreUrl: null });
    await saveSettings({ edgeUrl: 'https://dns.home.arpa:9853', coreUrl: 'https://core.home.arpa:8443/' });
    expect(await loadSettings()).toEqual({ edgeUrl: 'https://dns.home.arpa:9853', coreUrl: 'https://core.home.arpa:8443/' });
    await saveSettings({ edgeUrl: null, coreUrl: null });
    expect(fake.storage.local.data.size).toBe(0);
  });

  it('ignores stored values that are not valid', async () => {
    fake.storage.local.data.set('edgeUrl', 'http://evil.example');
    fake.storage.local.data.set('coreUrl', 42);
    expect(await loadSettings()).toEqual({ edgeUrl: null, coreUrl: null });
  });
});
