import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { blockSummary, startPopup, type PopupEnv } from '../src/pages/popup';
import { DETECTION_ON_AFTER_RESTART } from '../src/shared/permissions';
import fake, { BASE, resetFakeBrowser } from './fake-browser';
import { $, background, button, loadPage, state } from './page-kit';

const now = Math.floor(Date.now() / 1000);
const allows = [
  { allow_id: 'a-2', kind: 'ip', target: '100.100.100.100', expires_at: now + 3600 },
  { allow_id: 'a-1', kind: 'dns', target: 'ads.example', subdomains: true, expires_at: now + 600 },
];
const list = (a: unknown[], skewMs = 0) => ({ ok: true, value: { allows: a, skewMs } });
const blocks = [
  { host: 'ads.example', kind: 'dns', blockId: 'abcdefgh', bundle: 'block-common', at: 1 },
  { host: 'track.example', kind: 'dns', blockId: 'ijklmnop', lookup: 'quad9', verdict: 'block', at: 2 },
  { host: '100.100.100.100', kind: 'ip', at: 3 },
];

function env() {
  return {
    activeTabId: vi.fn<() => Promise<number | null>>(async () => 7),
    openOptions: vi.fn<() => Promise<void>>(async () => undefined),
    openTab: vi.fn<(url: string) => Promise<void>>(async () => undefined),
    reloadTab: vi.fn<(tabId: number) => Promise<void>>(async () => undefined),
    nowMs: vi.fn<() => number>(() => Date.now()),
    close: vi.fn<() => void>(),
  } satisfies PopupEnv;
}

/** Each row's texts, joined by spaces. */
const rows = (id: string): string[] =>
  [...document.querySelectorAll(`#${id} li`)].map((li) => {
    const walk = document.createTreeWalker(li, NodeFilter.SHOW_TEXT);
    const parts: string[] = [];
    while (walk.nextNode()) {
      const t = (walk.currentNode.textContent ?? '').trim();
      if (t !== '') {
        parts.push(t);
      }
    }
    return parts.join(' ');
  });

beforeEach(() => {
  resetFakeBrowser();
  fake.sender = { url: `${BASE}popup.html`, tabId: undefined };
  loadPage('popup');
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
});
afterEach(() => {
  vi.useRealTimers();
});

describe('the popup', () => {
  it('asks to set up when no edge is configured', async () => {
    background({ getState: () => state({ edgeUrl: null }) });
    const e = env();
    await startPopup(e);
    expect($('setup').hidden).toBe(false);
    expect($('main').hidden).toBe(true);
    $('open-options').click();
    expect(e.openOptions).toHaveBeenCalled();
  });

  it("lists the device's active allows, soonest end first, with End now", async () => {
    const got = background({
      getState: () => state(),
      listAllows: () => list(allows),
      endAllow: () => list([allows[0]]),
    });
    await startPopup(env());
    const listed = rows('allows');
    expect(listed).toHaveLength(2);
    expect(listed[0]).toMatch(/^ads\.example and subdomains End now until .* · 10 min left$/);
    expect(listed[1]).toMatch(/^100\.100\.100\.100 \(IP\) End now until .* · 1 h left$/);
    const end = document.querySelector<HTMLButtonElement>('#allows li button');
    end?.click();
    await vi.waitFor(() => {
      expect(rows('allows')).toHaveLength(1);
    });
    expect(got.find((r) => r.type === 'endAllow')).toEqual({ type: 'endAllow', allowId: 'a-1' });
  });

  it('shows an End now error at its entry', async () => {
    background({
      getState: () => state(),
      listAllows: () => list(allows),
      endAllow: () => ({ ok: false, error: { kind: 'timeout', message: 'timed out' } }),
    });
    await startPopup(env());
    document.querySelector<HTMLButtonElement>('#allows li button')?.click();
    await vi.waitFor(() => {
      expect(document.querySelector('#allows li .row-error')?.textContent).toContain("didn't answer in time");
    });
  });

  it('says detection starts with the browser\'s next start while Brave waits for it, rather than list nothing', async () => {
    const got = background({ getState: () => state({ detection: true, detectionAfterRestart: true }), listAllows: () => list([]) });
    await startPopup(env());
    expect($('blocks-hint').textContent).toBe(DETECTION_ON_AFTER_RESTART);
    expect($('blocks-actions').hidden).toBe(true);
    expect(got.map((m) => m.type)).not.toContain('tabBlocks');
  });

  it('hints at sub-resource detection while it is off', async () => {
    background({ getState: () => state({ detection: false }), listAllows: () => list([]) });
    await startPopup(env());
    expect($('blocks-hint').textContent).toContain('Turn on blocked sub-resource detection');
    expect($('blocks-actions').hidden).toBe(true);
    expect(rows('allows')).toEqual(['No active allows.']);
  });

  it("lists this tab's blocked hosts and allows the chosen ones in one request", async () => {
    const got = background({
      getState: () => state({ detection: true }),
      listAllows: () => list([]),
      tabBlocks: () => ({ ok: true, value: blocks }),
      createAllows: () => {
        const created = [
          { ...allows[1], retry_after_s: 40 },
          { ...allows[0], retry_after_s: 0 },
        ];
        return { ok: true, value: { allows: created, created, requestedUntil: now + 900, skewMs: 0 } };
      },
    });
    const e = env();
    await startPopup(e);
    expect(got.find((r) => r.type === 'tabBlocks')).toEqual({ type: 'tabBlocks', tabId: 7 });
    expect(rows('blocks')).toEqual([
      'ads.example bundle block-common',
      'track.example lookup quad9 (block)',
      '100.100.100.100 firewall',
    ]);
    const checks = document.querySelectorAll<HTMLInputElement>('#blocks input[type=checkbox]');
    checks[0]!.checked = true;
    checks[2]!.checked = true;
    $<HTMLSelectElement>('duration').value = '28800';
    $('allow-selected').click();
    await vi.waitFor(() => {
      expect($('blocks-status').textContent).toContain('Reload the page in 40 s');
    });
    expect(got.find((r) => r.type === 'createAllows')).toEqual({
      type: 'createAllows',
      durationS: 28800,
      entries: [
        { kind: 'dns', blockId: 'abcdefgh', name: 'ads.example', subdomains: false },
        { kind: 'ip', ip: '100.100.100.100' },
      ],
    });
    button('Reload page').click();
    expect(e.reloadTab).toHaveBeenCalledWith(7);
  });

  it('shows an error at the entry its index names', async () => {
    background({
      getState: () => state({ detection: true }),
      listAllows: () => list([]),
      tabBlocks: () => ({ ok: true, value: blocks }),
      createAllows: () => ({ ok: false, error: { kind: 'conflict', status: 409, code: 'not_blocked', message: 'nothing to lift', index: 1 } }),
    });
    await startPopup(env());
    const checks = document.querySelectorAll<HTMLInputElement>('#blocks input[type=checkbox]');
    checks[1]!.checked = true;
    checks[2]!.checked = true;
    $('allow-selected').click();
    await vi.waitFor(() => {
      expect($('blocks-status').textContent).toBe('Nothing was changed.');
    });
    const errors = [...document.querySelectorAll<HTMLElement>('#blocks .row-error')].map((e) => (e.hidden ? '' : e.textContent));
    expect(errors[0]).toBe('');
    expect(errors[1]).toBe('');
    expect(errors[2]).toContain('does not block this address');
  });

  it('shows host names as text', async () => {
    background({
      getState: () => state({ detection: true }),
      listAllows: () => list([{ allow_id: 'a-9', kind: 'dns', target: '<b>bold</b>', expires_at: now + 60 }]),
      tabBlocks: () => ({ ok: true, value: [{ host: '<img src=x>', kind: 'dns', blockId: 'abcdefgh', at: 1 }] }),
    });
    await startPopup(env());
    expect(document.querySelector('#allows b')).toBeNull();
    expect(document.querySelector('#blocks img')).toBeNull();
    expect(rows('blocks')[0]).toContain('<img src=x>');
  });

  it("shows the edge's allows by the edge's clock, however far off this device's is", async () => {
    // This device's clock is an hour ahead: its own view would call both allows over.
    background({ getState: () => state(), listAllows: () => list(allows, -3_600_000) });
    const e = env();
    e.nowMs.mockImplementation(() => Date.now() + 3_600_000);
    await startPopup(e);
    const listed = rows('allows');
    expect(listed).toHaveLength(2);
    expect(listed[0]).toMatch(/· 10 min left$/);
    expect(listed[1]).toMatch(/· 1 h left$/);
    expect(document.querySelectorAll('#allows li button')).toHaveLength(2);
  });

  it('asks for the list again once an allow runs out by the edge clock', async () => {
    let calls = 0;
    background({
      getState: () => state(),
      listAllows: () => (++calls === 1 ? list([{ allow_id: 'a-3', kind: 'dns', target: 'soon.example', expires_at: Math.floor(Date.now() / 1000) + 2 }]) : list([])),
    });
    const e = env();
    await startPopup(e);
    expect(rows('allows')[0]).toMatch(/^soon\.example End now until .* · [12] s left$/);
    e.nowMs.mockImplementation(() => Date.now() + 3000);
    await vi.advanceTimersByTimeAsync(1000);
    await vi.waitFor(() => {
      expect(rows('allows')).toEqual(['No active allows.']);
    });
    expect(calls).toBe(2);
  });

  it('shows at its row an entry the edge did not allow, and lists the allows again', async () => {
    let listed = 0;
    background({
      getState: () => state({ detection: true }),
      listAllows: () => {
        listed += 1;
        return list([]);
      },
      tabBlocks: () => ({ ok: true, value: blocks }),
      createAllows: () => ({ ok: false, error: { kind: 'not_applied', index: 0, message: 'The edge lists no allow for ads.example, so it is still blocked. The other entries were allowed.' } }),
    });
    await startPopup(env());
    const checks = document.querySelectorAll<HTMLInputElement>('#blocks input[type=checkbox]');
    checks[0]!.checked = true;
    checks[2]!.checked = true;
    $('allow-selected').click();
    await vi.waitFor(() => {
      expect($('blocks-status').textContent).toBe('Not everything was allowed.');
    });
    expect(document.querySelector<HTMLElement>('#blocks .row-error')?.textContent).toContain('still blocked');
    await vi.waitFor(() => {
      expect(listed).toBe(2);
    });
  });

  it('summarises blocks', () => {
    expect(blockSummary({ host: 'a', kind: 'dns', at: 1 })).toBe('blocked');
  });
});
