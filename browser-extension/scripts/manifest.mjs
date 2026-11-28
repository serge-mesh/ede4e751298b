// The two manifests (browser-extension.md §1): one codebase, Brave (Chromium MV3:
// `background.service_worker` and a fixed `key` for a stable ID) and Firefox (MV3 ≥ 128 ESR:
// `background.scripts` and `browser_specific_settings.gecko.id`).

/**
 * Public half of the key that fixes the Chromium extension ID (aagdcikeegoglnhilmlaonmjnmlckdgk)
 * for unpacked installs. The private half isn't kept: unpacked loading never needs it, and the
 * extension isn't packed as a .crx.
 */
export const CHROMIUM_KEY =
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8LRYvD29IM2w5Csvefp4X1MCa9YkrQUrOw7GfOy1q7yBvvg0AbFn8RPNo96dh5HJXRW46y2C+COfPl24C0XcbMgZY73prTpRFXNLc1JGjZfl26uDKhluulC0Zv1z0K2RmuSynRVlDGI2ZF3NtUVt4YNE0dBBV+bOd5eUNy3PB5bXW4f9smsnqwCnebJA2bHrgFMdl9MKlL0nnxsOUdxWvZNDOeAK4bQH+UApoWv7MEQYQFUfi6Lw1ESDmPV73e0xvUYvhdXoxkh0Gf8sQcdmqZA5mErJTIov3EYF+clQfkkTAQU9YTTlqCVGf58ajy40X9dFcjRlORZmG4Snt22bHQIDAQAB';
export const CHROMIUM_ID = 'aagdcikeegoglnhilmlaonmjnmlckdgk';
export const GECKO_ID = 'picket-browser-extension@picket.home.arpa';
export const TARGETS = /** @type {const} */ (['brave', 'firefox']);

/**
 * Extension pages: scripts only from the extension, no plugins, no inline code, styles and
 * images only from the extension; the background script connects only over HTTPS (the edge).
 */
export const CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src https:; object-src 'none'; base-uri 'none'; form-action 'none'";

const ICONS = { 16: 'icons/icon-16.png', 32: 'icons/icon-32.png', 48: 'icons/icon-48.png', 128: 'icons/icon-128.png' };

/**
 * The manifest version: one to four dot-separated integers from the release version
 * (`0.3.0-rc.1` → `0.3.0`, with the full text as Chromium's `version_name`).
 * @param {string} version
 */
export function manifestVersion(version) {
  const m = /^(\d{1,9})(\.\d{1,9}){0,3}/.exec(version);
  if (m === null) {
    throw new Error(`not a release version: ${version}`);
  }
  return m[0];
}

/**
 * @param {'brave' | 'firefox'} target
 * @param {string} version
 */
export function manifest(target, version) {
  const base = {
    manifest_version: 3,
    name: 'Picket',
    short_name: 'Picket',
    version: manifestVersion(version),
    description: 'Shows why Picket blocked a page and lifts the block on this device for a chosen time.',
    icons: ICONS,
    action: { default_title: 'Picket', default_popup: 'popup.html', default_icon: ICONS },
    options_ui: { page: 'options.html', open_in_tab: true },
    permissions: ['webNavigation', 'storage'],
    optional_permissions: ['webRequest'],
    // The edge's origin (requested at setup) and `<all_urls>` for sub-resource detection.
    optional_host_permissions: ['<all_urls>'],
    content_security_policy: { extension_pages: CSP },
  };
  if (target === 'brave') {
    return {
      ...base,
      ...(base.version === version ? {} : { version_name: version }),
      key: CHROMIUM_KEY,
      minimum_chrome_version: '120',
      background: { service_worker: 'background.js' },
    };
  }
  return {
    ...base,
    background: { scripts: ['background.js'] },
    browser_specific_settings: {
      gecko: {
        id: GECKO_ID,
        strict_min_version: '128.0',
        // The extension collects no data (browser-extension.md §4). Firefox 140+ shows this at
        // install; older versions ignore the key.
        data_collection_permissions: { required: ['none'] },
      },
    },
  };
}
