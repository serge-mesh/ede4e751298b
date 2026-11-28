import { describe, expect, it, vi } from 'vitest';

import { CACHE_TTL_MS, CONCURRENCY, MAX_PENDING, SubresourceWatcher, tabBlockOf } from '../src/background/subresources';
import { TabGuard, type Ticket } from '../src/background/tab-guard';
import { isBlockCandidate } from '../src/shared/block-errors';
import type { BlockInfo } from '../src/shared/block-info';
import type { TabBlock } from '../src/shared/messages';

const dns = (name: string): BlockInfo => ({ kind: 'dns', url: `https://${name}/x.js`, name, blockId: 'abcdefgh', bundle: 'ads' });

function watcher(probe: (url: string) => Promise<BlockInfo | null>) {
  let now = 1_000_000;
  const guard = new TabGuard();
  const deps = {
    probe: vi.fn(probe),
    guard,
    record: vi.fn<(tabId: number, block: TabBlock, ticket: Ticket) => Promise<void>>(async () => undefined),
    isCandidate: isBlockCandidate,
    now: () => now,
  };
  return {
    deps,
    guard,
    w: new SubresourceWatcher(deps),
    tick: (ms: number) => {
      now += ms;
    },
    navigate: (tabId: number) => guard.navigated(tabId),
  };
}

const failed = (url: string, tabId = 5, extra: Record<string, unknown> = {}) => ({ tabId, url, error: 'net::ERR_NAME_NOT_RESOLVED', type: 'script', ...extra });

describe('blocked sub-resource detection', () => {
  it('probes a failed request and lists a block for its tab', async () => {
    const { w, deps, guard } = watcher(async (url) => (url.includes('ads.') ? dns('ads.example') : null));
    w.onErrorOccurred(failed('https://ads.example/x.js'));
    w.onErrorOccurred(failed('https://fine.example/y.js'));
    await vi.waitFor(() => {
      expect(deps.probe).toHaveBeenCalledTimes(2);
    });
    await vi.waitFor(() => {
      expect(deps.record).toHaveBeenCalledTimes(1);
    });
    expect(deps.record).toHaveBeenCalledWith(5, { host: 'ads.example', kind: 'dns', blockId: 'abcdefgh', bundle: 'ads', at: 1_000_000 }, guard.ticket(5));
  });

  it('ignores main frames, other errors and requests outside tabs', () => {
    const { w, deps } = watcher(async () => null);
    w.onErrorOccurred(failed('https://a.example/', 5, { type: 'main_frame' }));
    w.onErrorOccurred(failed('https://a.example/', 5, { error: 'net::ERR_ABORTED' }));
    w.onErrorOccurred(failed('https://a.example/', -1));
    w.onErrorOccurred(failed('data:text/plain,x'));
    expect(deps.probe).not.toHaveBeenCalled();
  });

  it("ignores a request from a page being unloaded or prerendered (Chromium's documentLifecycle; recheck G6)", () => {
    const { w, deps } = watcher(async () => dns('ads.example'));
    // The old page's unload beacon, after the tab's next page committed.
    w.onErrorOccurred(failed('https://ads.example/beacon', 5, { documentLifecycle: 'pending_deletion' }));
    // A prerendered page nobody sees yet.
    w.onErrorOccurred(failed('https://ads.example/pre.js', 5, { documentLifecycle: 'prerender' }));
    // A page going into the back/forward cache (its pagehide beacon).
    w.onErrorOccurred(failed('https://ads.example/bf', 5, { documentLifecycle: 'cached' }));
    expect(deps.probe).not.toHaveBeenCalled();
    // The page the tab shows (and Firefox, which doesn't say).
    w.onErrorOccurred(failed('https://ads.example/x.js', 5, { documentLifecycle: 'active' }));
    w.onErrorOccurred(failed('https://other.example/y.js', 5));
    expect(deps.probe).toHaveBeenCalledTimes(2);
  });

  it('probes a host once while it is pending, for every tab that saw it', async () => {
    let release: (b: BlockInfo) => void = () => undefined;
    const { w, deps } = watcher(() => new Promise<BlockInfo>((r) => (release = r)));
    w.onErrorOccurred(failed('https://ads.example/1.js', 1));
    w.onErrorOccurred(failed('https://ads.example/2.js', 2));
    expect(deps.probe).toHaveBeenCalledTimes(1);
    release(dns('ads.example'));
    await vi.waitFor(() => {
      expect(deps.record).toHaveBeenCalledTimes(2);
    });
    expect(deps.record.mock.calls.map((c) => (c as unknown[])[0])).toEqual([1, 2]);
  });

  it('remembers results for a while, and forgets them after an allow', async () => {
    const { w, deps, tick, guard } = watcher(async () => dns('ads.example'));
    w.onErrorOccurred(failed('https://ads.example/1.js'));
    await vi.waitFor(() => {
      expect(deps.record).toHaveBeenCalledTimes(1);
    });
    w.onErrorOccurred(failed('https://ads.example/2.js', 6));
    expect(deps.probe).toHaveBeenCalledTimes(1);
    expect(deps.record).toHaveBeenCalledTimes(2);
    tick(CACHE_TTL_MS);
    w.onErrorOccurred(failed('https://ads.example/3.js'));
    expect(deps.probe).toHaveBeenCalledTimes(2);
    await vi.waitFor(() => {
      expect(deps.record).toHaveBeenCalledTimes(3);
    });
    guard.allowsChanged();
    w.onErrorOccurred(failed('https://ads.example/4.js'));
    expect(deps.probe).toHaveBeenCalledTimes(3);
  });

  it('bounds the probes in flight and the hosts waiting', async () => {
    const releases: (() => void)[] = [];
    const { w, deps } = watcher(
      () =>
        new Promise<null>((r) => {
          releases.push(() => {
            r(null);
          });
        }),
    );
    for (let i = 0; i < MAX_PENDING + 10; i++) {
      w.onErrorOccurred(failed(`https://h${String(i)}.example/x.js`));
    }
    expect(deps.probe).toHaveBeenCalledTimes(CONCURRENCY);
    expect(w.dropped).toBe(10);
    releases.shift()?.();
    await vi.waitFor(() => {
      expect(deps.probe).toHaveBeenCalledTimes(CONCURRENCY + 1);
    });
  });

  it("tags each failure with its tab's page, so a late probe can't fill the next page's list", async () => {
    let release: (b: BlockInfo) => void = () => undefined;
    const { w, deps, navigate, guard } = watcher(() => new Promise<BlockInfo>((r) => (release = r)));
    w.onErrorOccurred(failed('https://ads.example/1.js', 1));
    navigate(1); // the tab's next page
    w.onErrorOccurred(failed('https://ads.example/2.js', 2));
    release(dns('ads.example'));
    await vi.waitFor(() => {
      expect(deps.record).toHaveBeenCalledTimes(1);
    });
    // Tab 1 moved on before the probe ended: listed for tab 2 only, under its own ticket.
    expect(deps.record.mock.calls.map((c) => [c[0], c[2]])).toEqual([[2, guard.ticket(2)]]);
    // A tab that fails again on its new page while the probe is pending gets the new page's ticket.
    let again: (b: BlockInfo) => void = () => undefined;
    const second = watcher(() => new Promise<BlockInfo>((r) => (again = r)));
    second.w.onErrorOccurred(failed('https://ads.example/1.js', 1));
    const page = second.navigate(1);
    second.w.onErrorOccurred(failed('https://ads.example/3.js', 1));
    again(dns('ads.example'));
    await vi.waitFor(() => {
      expect(second.deps.record).toHaveBeenCalledWith(1, expect.anything(), { tabId: 1, nav: page, epoch: 0 });
    });
  });

  it('drops a probe that started before allows changed and probes the host again', async () => {
    const releases: ((b: BlockInfo | null) => void)[] = [];
    const { w, deps, guard } = watcher(() => new Promise<BlockInfo | null>((r) => releases.push(r)));
    w.onErrorOccurred(failed('https://ads.example/1.js'));
    guard.allowsChanged(); // an allow lifted the block meanwhile
    releases.shift()?.(dns('ads.example'));
    await vi.waitFor(() => {
      expect(deps.probe).toHaveBeenCalledTimes(2);
    });
    expect(deps.record).not.toHaveBeenCalled();
    releases.shift()?.(null); // the probe after the allow: no block
    await vi.waitFor(() => {
      expect(releases).toHaveLength(0);
    });
    // Its result is what is cached now.
    w.onErrorOccurred(failed('https://ads.example/2.js'));
    expect(deps.probe).toHaveBeenCalledTimes(2);
    expect(deps.record).not.toHaveBeenCalled();
  });

  it('re-checks each tab right before listing: allows changing between tabs stop the rest', async () => {
    // Recheck R6: the epoch was checked once before the tabs were listed one by one.
    const { w, deps, guard } = watcher(async () => dns('ads.example'));
    deps.record.mockImplementationOnce(async () => {
      guard.allowsChanged(); // an allow while the first tab's listing runs
    });
    for (const tab of [1, 2, 3]) {
      w.onErrorOccurred(failed('https://ads.example/x.js', tab));
    }
    await vi.waitFor(() => {
      expect(deps.record).toHaveBeenCalledTimes(1);
    });
    await new Promise((r) => setTimeout(r, 10));
    expect(deps.record).toHaveBeenCalledTimes(1);
    // Nor is the result cached under the new epoch: the next failure probes again.
    w.onErrorOccurred(failed('https://ads.example/y.js', 2));
    expect(deps.probe).toHaveBeenCalledTimes(2);
  });

  it('probes an IP literal only for a connect-level error (recheck R7)', () => {
    const { w, deps } = watcher(async () => null);
    w.onErrorOccurred(failed('https://192.168.10.5:8006/api', 5, { error: 'net::ERR_CERT_AUTHORITY_INVALID' }));
    w.onErrorOccurred(failed('https://192.168.10.6/x.js', 5, { error: 'net::ERR_EMPTY_RESPONSE' }));
    expect(deps.probe).not.toHaveBeenCalled();
    w.onErrorOccurred(failed('https://192.168.10.7/x.js', 5, { error: 'net::ERR_CONNECTION_REFUSED' }));
    w.onErrorOccurred(failed('https://cdn.example/x.js', 5, { error: 'net::ERR_CERT_AUTHORITY_INVALID' }));
    expect(deps.probe.mock.calls.map((c) => c[0])).toEqual(['https://192.168.10.7/x.js', 'https://cdn.example/x.js']);
  });

  it('lists firewall blocks of IP literals by IP', () => {
    expect(tabBlockOf({ kind: 'ip', url: 'https://1.2.3.4/', ip: '1.2.3.4' }, 9)).toEqual({ host: '1.2.3.4', kind: 'ip', at: 9 });
  });
});
