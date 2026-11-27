import { beforeEach, describe, expect, it, vi } from 'vitest';

import { listUrl, startOptions, type OptionsEnv } from '../src/pages/options';
import { DETECTION_ON, DETECTION_ON_AFTER_RESTART, DETECTION_PERMISSIONS } from '../src/shared/permissions';
import fake, { BASE, resetFakeBrowser } from './fake-browser';
import { $, background, loadPage, state } from './page-kit';

function env(grant = true, detectionNeedsRestart = false) {
  return {
    requestPermissions: vi.fn(async () => grant),
    removePermissions: vi.fn(async () => true),
    copy: vi.fn(async () => undefined),
    detectionNeedsRestart,
  } satisfies OptionsEnv;
}

const submit = (): void => {
  $<HTMLFormElement>('settings').dispatchEvent(new Event('submit', { cancelable: true }));
};

beforeEach(() => {
  resetFakeBrowser();
  fake.sender = { url: `${BASE}options.html`, tabId: 2 };
  loadPage('options');
});

describe('setup', () => {
  it('fills the form from the stored settings', async () => {
    background({ getState: () => state({ detection: true }) });
    startOptions(env());
    await vi.waitFor(() => {
      expect($<HTMLInputElement>('edge-url').value).toBe('https://dns.home.arpa:9853');
    });
    expect($<HTMLInputElement>('core-url').value).toBe('https://core.home.arpa:8443/');
    expect($<HTMLInputElement>('detection').checked).toBe(true);
    expect($<HTMLInputElement>('list-base').value).toBe('https://core.home.arpa:8443');
  });

  it("requests the edge origin's permission within the user's action, saves, then tests GET /v1/temporary-allows", async () => {
    const got = background({
      getState: () => state({ edgeUrl: null, coreUrl: null, edgeAccess: false }),
      saveSettings: () => state({ coreUrl: null }),
      testEdge: () => ({ ok: true, value: { allows: [{ allow_id: 'a-1', kind: 'dns', target: 'x', expires_at: 1 }], skewMs: 0 } }),
    });
    const e = env();
    startOptions(e);
    await vi.waitFor(() => {
      expect(got).toHaveLength(1);
    });
    $<HTMLInputElement>('edge-url').value = 'dns.home.arpa:9853';
    submit();
    // Synchronously, before anything is awaited (Firefox grants only inside the user's action).
    expect(e.requestPermissions).toHaveBeenCalledWith({ origins: ['https://dns.home.arpa/*'] });
    await vi.waitFor(() => {
      expect($('settings-status').textContent).toBe('Connected. The edge lists 1 active temporary allow for this device.');
    });
    expect(got.slice(1)).toEqual([
      { type: 'saveSettings', edgeUrl: 'https://dns.home.arpa:9853', coreUrl: '' },
      { type: 'testEdge' },
    ]);
    expect($<HTMLInputElement>('edge-url').value).toBe('https://dns.home.arpa:9853');
  });

  it("doesn't ask for a permission or save an invalid URL", async () => {
    const got = background({ getState: () => state({ edgeUrl: null }) });
    const e = env();
    startOptions(e);
    $<HTMLInputElement>('edge-url').value = 'http://dns.home.arpa:9853';
    submit();
    expect(e.requestPermissions).not.toHaveBeenCalled();
    expect($('settings-status').textContent).toContain('HTTPS');
    $<HTMLInputElement>('edge-url').value = 'https://dns.home.arpa';
    $<HTMLInputElement>('core-url').value = 'javascript:alert(1)';
    submit();
    expect(e.requestPermissions).not.toHaveBeenCalled();
    await vi.waitFor(() => {
      expect(got.map((r) => r.type)).toEqual(['getState']);
    });
  });

  it("doesn't save when access to the edge is refused", async () => {
    const got = background({ getState: () => state({ edgeUrl: null }) });
    startOptions(env(false));
    $<HTMLInputElement>('edge-url').value = 'https://dns.home.arpa:9853';
    submit();
    await vi.waitFor(() => {
      expect($('settings-status').textContent).toContain('not granted');
    });
    expect(got.map((r) => r.type)).toEqual(['getState']);
  });

  it("drops the previous edge's access when the edge changes, and reports a failed test", async () => {
    background({
      getState: () => state({ edgeUrl: 'https://old.home.arpa:9853' }),
      saveSettings: () => state({ edgeUrl: 'https://dns.home.arpa:9853' }),
      testEdge: () => ({ ok: false, error: { kind: 'network', message: 'Failed to fetch' } }),
    });
    const e = env();
    startOptions(e);
    await vi.waitFor(() => {
      expect($<HTMLInputElement>('edge-url').value).toBe('https://old.home.arpa:9853');
    });
    $<HTMLInputElement>('edge-url').value = 'https://dns.home.arpa:9853';
    submit();
    await vi.waitFor(() => {
      expect($('settings-status').textContent).toContain('the test failed');
    });
    expect($('settings-status').textContent).toContain('LAN CA');
    expect(e.removePermissions).toHaveBeenCalledWith({ origins: ['https://old.home.arpa/*'] });
  });
});

describe('blocked sub-resource detection', () => {
  it("requests webRequest and <all_urls> within the user's action, and reflects the answer", async () => {
    background({ getState: () => state({ detection: false }) });
    const e = env(false);
    startOptions(e);
    const box = $<HTMLInputElement>('detection');
    box.checked = true;
    box.dispatchEvent(new Event('change'));
    expect(e.requestPermissions).toHaveBeenCalledWith(DETECTION_PERMISSIONS);
    await vi.waitFor(() => {
      expect(box.checked).toBe(false);
    });
    expect($('detection-status').textContent).toContain('not granted');
  });

  it('says when detection starts: at once on Firefox, after a restart on Brave', async () => {
    for (const [restart, text] of [
      [false, DETECTION_ON],
      [true, DETECTION_ON_AFTER_RESTART],
    ] as const) {
      loadPage('options');
      background({ getState: () => state({ detection: false }) });
      startOptions(env(true, restart));
      const box = $<HTMLInputElement>('detection');
      box.checked = true;
      box.dispatchEvent(new Event('change'));
      await vi.waitFor(() => {
        expect($('detection-status').textContent).toBe(text);
      });
      expect(box.checked).toBe(true);
    }
  });

  it('turns off by removing the permissions, and warns if edge access went with them', async () => {
    let call = 0;
    background({ getState: () => (++call === 1 ? state({ detection: true }) : state({ detection: false, edgeAccess: false })) });
    const e = env();
    startOptions(e);
    await vi.waitFor(() => {
      expect($<HTMLInputElement>('detection').checked).toBe(true);
    });
    const box = $<HTMLInputElement>('detection');
    box.checked = false;
    box.dispatchEvent(new Event('change'));
    await vi.waitFor(() => {
      expect($('detection-status').textContent).toContain('Save and test');
    });
    expect(e.removePermissions).toHaveBeenCalledWith(DETECTION_PERMISSIONS);
  });
});

describe('browser lists', () => {
  it('builds the list URLs core serves', () => {
    const base = 'https://core.home.arpa:8443/ui';
    expect(listUrl('pruned', 'kids', base)).toEqual({ ok: true, url: 'https://core.home.arpa:8443/lists/profiles/kids.txt' });
    expect(listUrl('full', 'kids', base)).toEqual({ ok: true, url: 'https://core.home.arpa:8443/lists/profiles/kids-full.txt' });
    expect(listUrl('bundle', 'block-common', 'http://core.home.arpa:8080')).toEqual({ ok: true, url: 'http://core.home.arpa:8080/lists/block-common.txt' });
    expect(listUrl('pruned', 'kids-full', base).ok).toBe(false);
    expect(listUrl('bundle', 'x-full', base).ok).toBe(true);
    expect(listUrl('pruned', '../etc', base).ok).toBe(false);
    expect(listUrl('pruned', '.hidden', base).ok).toBe(false);
    expect(listUrl('pruned', '', base).ok).toBe(false);
    expect(listUrl('pruned', 'kids', '').ok).toBe(false);
  });

  it('shows the URL as the fields change and copies it', async () => {
    background({ getState: () => state() });
    const e = env();
    startOptions(e);
    await vi.waitFor(() => {
      expect($<HTMLInputElement>('list-base').value).toBe('https://core.home.arpa:8443');
    });
    const id = $<HTMLInputElement>('list-id');
    id.value = 'kids';
    id.dispatchEvent(new Event('input'));
    expect($<HTMLInputElement>('list-url').value).toBe('https://core.home.arpa:8443/lists/profiles/kids.txt');
    const kind = $<HTMLSelectElement>('list-kind');
    kind.value = 'full';
    kind.dispatchEvent(new Event('change'));
    expect($<HTMLInputElement>('list-url').value).toBe('https://core.home.arpa:8443/lists/profiles/kids-full.txt');
    $('copy-url').click();
    expect(e.copy).toHaveBeenCalledWith('https://core.home.arpa:8443/lists/profiles/kids-full.txt');
    id.value = 'kids-full';
    id.dispatchEvent(new Event('input'));
    expect($<HTMLInputElement>('list-url').value).toBe('');
    expect($('list-status').textContent).toContain('-full');
    // Nothing about the lists is stored.
    expect(fake.storage.local.set).not.toHaveBeenCalled();
  });
});
