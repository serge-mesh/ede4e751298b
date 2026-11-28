import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { CHROMIUM_ID, CHROMIUM_KEY, CSP, GECKO_ID, manifest, manifestVersion } from '../scripts/manifest.mjs';

type Manifest = Record<string, unknown> & { content_security_policy: { extension_pages: string } };
const brave = manifest('brave', '0.1.0') as Manifest;
const firefox = manifest('firefox', '0.1.0') as Manifest;

describe('manifests', () => {
  it('ask only for webNavigation and storage; the rest is optional', () => {
    for (const m of [brave, firefox]) {
      expect(m.manifest_version).toBe(3);
      expect(m.permissions).toEqual(['webNavigation', 'storage']);
      expect(m.optional_permissions).toEqual(['webRequest']);
      expect(m.optional_host_permissions).toEqual(['<all_urls>']);
      for (const k of ['host_permissions', 'content_scripts', 'web_accessible_resources', 'externally_connectable', 'update_url']) {
        expect(m[k], k).toBeUndefined();
      }
    }
  });

  it('allow no remote or inline code', () => {
    for (const m of [brave, firefox]) {
      const csp = m.content_security_policy.extension_pages;
      expect(csp).toBe(CSP);
      expect(csp).toContain("script-src 'self';");
      expect(csp).toContain("object-src 'none'");
      expect(csp).not.toMatch(/unsafe-|wasm|http:|\*/);
    }
  });

  it('Brave: a service worker and a fixed key for a stable ID', () => {
    expect(brave.background).toEqual({ service_worker: 'background.js' });
    expect(brave.key).toBe(CHROMIUM_KEY);
    // The ID Chromium derives from the key: the first 128 bits of its SHA-256, as a–p.
    const hex = createHash('sha256').update(Buffer.from(CHROMIUM_KEY, 'base64')).digest('hex').slice(0, 32);
    expect(hex.replace(/./g, (c) => String.fromCharCode(97 + parseInt(c, 16)))).toBe(CHROMIUM_ID);
    expect(brave.browser_specific_settings).toBeUndefined();
  });

  it('Firefox: background scripts, a gecko id and 128 ESR as the minimum', () => {
    expect(firefox.background).toEqual({ scripts: ['background.js'] });
    expect(firefox.browser_specific_settings).toMatchObject({ gecko: { id: GECKO_ID, strict_min_version: '128.0' } });
    expect(firefox.key).toBeUndefined();
  });

  it('take one to four integers as the version', () => {
    expect(manifestVersion('0.1.0')).toBe('0.1.0');
    expect(manifestVersion('1.2.3-rc.1')).toBe('1.2.3');
    expect((manifest('brave', '1.2.3-rc.1') as Manifest).version_name).toBe('1.2.3-rc.1');
    expect(() => manifestVersion('v1')).toThrow();
  });
});
