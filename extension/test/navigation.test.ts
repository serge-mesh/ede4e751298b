import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  MAX_PROBES,
  MAX_WAITING_PROBES,
  NavigationFlow,
  RETRY_DELAY_MS,
  RETRY_WINDOW_MS,
  type NavigationDeps,
} from '../src/background/navigation';
import { MAX_EARLY } from '../src/background/session';
import { TabGuard } from '../src/background/tab-guard';
import { isBlockCandidate } from '../src/shared/block-errors';
import type { BlockInfo } from '../src/shared/block-info';
import { FakeArea } from './fake-browser';

const URL1 = 'https://ads.example/page';
const BLOCK: BlockInfo = { kind: 'dns', url: URL1, name: 'ads.example', blockId: 'abcdefgh', bundle: 'block-common' };
const ANY = expect.any(Function) as unknown;

function flow(probe: (url: string) => Promise<BlockInfo | null> = async () => BLOCK, session = new FakeArea(), over: Partial<NavigationDeps> = {}) {
  const guard = new TabGuard();
  const deps = {
    probe: vi.fn(probe),
    openBlockPage: vi.fn<NavigationDeps['openBlockPage']>(async () => undefined),
    navigate: vi.fn<NavigationDeps['navigate']>(async () => undefined),
    isCandidate: isBlockCandidate,
    setTimer: (fn: () => void, ms: number) => {
      setTimeout(fn, ms);
    },
    now: () => Date.now(),
    session,
    guard,
    log: vi.fn<NonNullable<NavigationDeps['log']>>(),
  } satisfies NavigationDeps;
  return { deps, guard, session, nav: new NavigationFlow({ ...deps, ...over }) };
}

/** Timers a test runs by hand: each callback with its delay. */
function manualTimers() {
  const timers: { fn: () => void; ms: number }[] = [];
  return {
    timers,
    setTimer: (fn: () => void, ms: number) => {
      timers.push({ fn, ms });
    },
    /** Runs the timers set with this delay (the retry's second attempt: RETRY_DELAY_MS). */
    run: (ms: number) => {
      for (const t of timers.filter((x) => x.ms === ms)) {
        t.fn();
      }
    },
  };
}

/** Lets pending promise reactions run (the fake storage answers within a few). */
async function flush(): Promise<void> {
  for (let i = 0; i < 50; i++) {
    await Promise.resolve();
  }
}

/** A promise and its release. */
function gate(): { promise: Promise<void>; release: () => void } {
  let release: () => void = () => undefined;
  const promise = new Promise<void>((r) => (release = r));
  return { promise, release };
}

const fail = (error: string | undefined, extra: Record<string, unknown> = {}) => ({ tabId: 3, frameId: 0, url: URL1, ...(error === undefined ? {} : { error }), ...extra });
const go = (url: string, tabId = 3) => ({ tabId, frameId: 0, url });

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

describe('a failed page load', () => {
  it('opens the block page when the probe finds a block', async () => {
    const { nav, deps } = flow();
    await nav.onBeforeNavigate(go(URL1));
    await nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    expect(deps.probe).toHaveBeenCalledWith(URL1);
    expect(deps.openBlockPage).toHaveBeenCalledWith(3, BLOCK, ANY);
    // The log names the error and outcome, never the URL.
    expect(deps.log).toHaveBeenCalledWith('net::ERR_NAME_NOT_RESOLVED', 'block');
    expect(JSON.stringify(deps.log.mock.calls)).not.toContain('ads.example');
  });

  it('probes only errors a block mode produces, in the top frame', async () => {
    const { nav, deps } = flow();
    await nav.onErrorOccurred(fail('net::ERR_ABORTED'));
    await nav.onErrorOccurred(fail('net::ERR_BLOCKED_BY_CLIENT'));
    await nav.onErrorOccurred({ ...fail('net::ERR_NAME_NOT_RESOLVED'), frameId: 4 });
    await nav.onErrorOccurred({ ...fail('net::ERR_NAME_NOT_RESOLVED'), tabId: -1 });
    await nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED', { frameType: 'fenced_frame' }));
    await nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED', { documentLifecycle: 'prerender' }));
    expect(deps.probe).not.toHaveBeenCalled();
    // Firefox's schema doesn't promise `error`: a host name's failure without one is probed.
    await nav.onErrorOccurred(fail(undefined));
    expect(deps.probe).toHaveBeenCalledTimes(1);
    await nav.onErrorOccurred(fail('Error code 2152398878'));
    expect(deps.probe).toHaveBeenCalledTimes(2);
  });

  it('probes an IP-literal URL only for an error a firewall refusal can cause (recheck R7)', async () => {
    const { nav, deps } = flow(async (url) => ({ kind: 'ip', url, ip: '192.168.10.5' }));
    const ip = 'https://192.168.10.5:8006/';
    // A self-signed certificate: the TCP connection worked, so no refusal.
    await nav.onErrorOccurred(fail('net::ERR_CERT_AUTHORITY_INVALID', { url: ip }));
    await nav.onErrorOccurred(fail('Error code 2153390067', { url: ip })); // SEC_ERROR_UNKNOWN_ISSUER
    await nav.onErrorOccurred(fail('net::ERR_EMPTY_RESPONSE', { url: ip }));
    await nav.onErrorOccurred(fail(undefined, { url: ip }));
    expect(deps.probe).not.toHaveBeenCalled();
    await nav.onErrorOccurred(fail('net::ERR_CONNECTION_REFUSED', { url: ip }));
    expect(deps.probe).toHaveBeenCalledWith(ip);
  });

  it('does nothing when the probe finds no block', async () => {
    const { nav, deps } = flow(async () => null);
    await nav.onErrorOccurred(fail('net::ERR_CONNECTION_REFUSED'));
    expect(deps.openBlockPage).not.toHaveBeenCalled();
  });

  it('leaves a tab alone that started another navigation since the failure', async () => {
    let release: (b: BlockInfo) => void = () => undefined;
    const { nav, deps } = flow(() => new Promise<BlockInfo>((r) => (release = r)));
    await nav.onBeforeNavigate(go(URL1));
    const done = nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    await nav.onBeforeNavigate({ tabId: 3, frameId: 7, url: 'https://ads.example/frame' }); // a subframe doesn't count
    await nav.onBeforeNavigate(go('https://elsewhere.example/'));
    release(BLOCK);
    await done;
    expect(deps.openBlockPage).not.toHaveBeenCalled();
  });

  it('hands the block page a check that fails once the tab moves on', async () => {
    const { nav, deps } = flow();
    await nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    const still = deps.openBlockPage.mock.calls[0]?.[2];
    expect(still?.()).toBe(true);
    await nav.onBeforeNavigate(go('https://elsewhere.example/'));
    expect(still?.()).toBe(false);
  });

  it('probes again when allows change during the probe, and acts on the answer under the new epoch', async () => {
    const answers: ((b: BlockInfo | null) => void)[] = [];
    const { nav, deps, guard } = flow(() => new Promise<BlockInfo | null>((r) => answers.push(r)));
    const done = nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    await vi.waitFor(() => {
      expect(deps.probe).toHaveBeenCalledTimes(1);
    });
    guard.allowsChanged(); // an allow in another tab lifted it meanwhile
    answers.shift()?.(BLOCK); // answered before the allow
    await vi.waitFor(() => {
      expect(deps.probe).toHaveBeenCalledTimes(2);
    });
    answers.shift()?.(null);
    await done;
    expect(deps.openBlockPage).not.toHaveBeenCalled();
    // Allows change during the second probe too: its answer is stale as well, and not acted on.
    const twice = flow(() => new Promise<BlockInfo | null>((r) => answers.push(r)));
    const both = twice.nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    for (let i = 1; i <= 2; i++) {
      await vi.waitFor(() => {
        expect(twice.deps.probe).toHaveBeenCalledTimes(i);
      });
      twice.guard.allowsChanged();
      answers.shift()?.(BLOCK);
    }
    await both;
    expect(twice.deps.probe).toHaveBeenCalledTimes(2);
    expect(twice.deps.openBlockPage).not.toHaveBeenCalled();
    expect(twice.deps.log).toHaveBeenLastCalledWith('net::ERR_NAME_NOT_RESOLVED', 'moved on');
    // And an allow after the answer, before the tab change, stops it too.
    const second = flow();
    const opening = second.nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    await vi.waitFor(() => {
      expect(second.deps.openBlockPage).toHaveBeenCalledTimes(1);
    });
    await opening;
    const still = second.deps.openBlockPage.mock.calls[0]?.[2];
    second.guard.allowsChanged();
    expect(still?.()).toBe(false);
  });

  it('works when the background started with the failure (no navigation seen before it)', async () => {
    const { nav, deps } = flow();
    await nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    expect(deps.openBlockPage).toHaveBeenCalledTimes(1);
  });
});

describe('the reload after an allow', () => {
  it('loads the original URL, and once more 2 s later if that fails', async () => {
    const { nav, deps } = flow();
    await nav.reloadAfterAllow(3, URL1);
    expect(deps.navigate).toHaveBeenLastCalledWith(3, URL1, ANY);
    await nav.onBeforeNavigate(go(URL1));
    await nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    expect(deps.probe).not.toHaveBeenCalled();
    expect(deps.navigate).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(RETRY_DELAY_MS - 1);
    expect(deps.navigate).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    await vi.waitFor(() => {
      expect(deps.navigate).toHaveBeenCalledTimes(2);
    });
    expect(deps.navigate).toHaveBeenLastCalledWith(3, URL1, ANY);
    // A second failure takes the normal path: probe, then the block page if still blocked.
    await nav.onBeforeNavigate(go(URL1));
    await nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    expect(deps.probe).toHaveBeenCalledTimes(1);
    expect(deps.openBlockPage).toHaveBeenCalledTimes(1);
  });

  it("keeps the retry bound when the browser starts the reload's load again (seen on Firefox)", async () => {
    // Firefox starts a load from an extension page (the block page) once more in a web content
    // process, with a second onBeforeNavigate for the same URL before the failure.
    const { nav, deps } = flow();
    await nav.reloadAfterAllow(3, URL1);
    await nav.onBeforeNavigate(go(URL1));
    await nav.onBeforeNavigate(go(URL1));
    await nav.onErrorOccurred(fail('Error code 2152398878'));
    expect(deps.probe).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(RETRY_DELAY_MS);
    expect(deps.navigate).toHaveBeenCalledTimes(2);
    // Its own second attempt is bound the same way.
    await nav.onBeforeNavigate(go(URL1));
    await nav.onCompleted(go(URL1));
    await nav.onErrorOccurred(fail('Error code 2152398878'));
    expect(deps.probe).toHaveBeenCalledTimes(1);
  });

  it('keeps the second attempt when a page load completes during the 2 s (recheck G7)', async () => {
    const { nav, deps } = flow();
    await nav.reloadAfterAllow(3, URL1);
    await nav.onBeforeNavigate(go(URL1));
    await nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    // E.g. Firefox's error page for the failed load.
    await nav.onCompleted(go(URL1));
    await vi.advanceTimersByTimeAsync(RETRY_DELAY_MS);
    expect(deps.navigate).toHaveBeenCalledTimes(2);
  });

  it('needs no retry when the reload works', async () => {
    const { nav, deps } = flow();
    await nav.reloadAfterAllow(3, URL1);
    await nav.onBeforeNavigate(go(URL1));
    await nav.onCompleted(go(URL1));
    await nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    expect(deps.probe).toHaveBeenCalledTimes(1);
  });

  it("doesn't retry once the user navigates elsewhere", async () => {
    const { nav, deps } = flow();
    await nav.reloadAfterAllow(3, URL1);
    await nav.onBeforeNavigate(go(URL1));
    await nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    await nav.onBeforeNavigate(go('https://elsewhere.example/'));
    await vi.advanceTimersByTimeAsync(RETRY_DELAY_MS);
    expect(deps.navigate).toHaveBeenCalledTimes(1);
  });

  it('retries only failures of the same host', async () => {
    const { nav, deps } = flow();
    await nav.reloadAfterAllow(3, URL1);
    await nav.onBeforeNavigate(go(URL1));
    // A redirect to another host that fails is another block: probed.
    await nav.onErrorOccurred({ ...fail('net::ERR_NAME_NOT_RESOLVED'), url: 'https://other.example/' });
    expect(deps.probe).toHaveBeenCalledTimes(1);
  });

  it("doesn't retry a failure that comes before the reload's own navigation starts (recheck R8)", async () => {
    const { nav, deps } = flow();
    await nav.reloadAfterAllow(3, URL1);
    // A failure of the same host while the retry still waits (`expect`) for its navigation.
    await nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    expect(deps.log).not.toHaveBeenCalledWith('net::ERR_NAME_NOT_RESOLVED', 'retried');
    expect(deps.probe).toHaveBeenCalledTimes(1);
  });

  it('lets a retry lapse 60 s after the allow by the wall clock, with no timer needed (recheck R8)', async () => {
    let now = 1_800_000_000_000;
    // Timers never fire here: only the window check can end the retry.
    const { nav, deps } = flow(async () => BLOCK, new FakeArea(), { now: () => now, setTimer: () => undefined });
    await nav.reloadAfterAllow(3, URL1);
    await nav.onBeforeNavigate(go(URL1));
    now += RETRY_WINDOW_MS - 1;
    await nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    expect(deps.log).toHaveBeenLastCalledWith('net::ERR_NAME_NOT_RESOLVED', 'retried');
    await nav.reloadAfterAllow(3, URL1);
    await nav.onBeforeNavigate(go(URL1));
    now += RETRY_WINDOW_MS;
    await nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    expect(deps.probe).toHaveBeenCalledTimes(1);
    // A window further ahead than it can be: this device's clock stepped back.
    await nav.reloadAfterAllow(3, URL1);
    await nav.onBeforeNavigate(go(URL1));
    now -= 2 * RETRY_WINDOW_MS;
    await nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    expect(deps.probe).toHaveBeenCalledTimes(2);
  });

  it('keeps the pending retry across a background restart (a slow reload outlasts the worker)', async () => {
    const session = new FakeArea();
    const before = flow(async () => BLOCK, session);
    await before.nav.reloadAfterAllow(3, URL1);
    await before.nav.onBeforeNavigate(go(URL1));
    // The worker unloads; the reload's failure wakes a new one.
    const after = flow(async () => BLOCK, session);
    await after.nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    expect(after.deps.probe).not.toHaveBeenCalled();
    expect(after.deps.log).toHaveBeenCalledWith('net::ERR_NAME_NOT_RESOLVED', 'retried');
    await vi.advanceTimersByTimeAsync(RETRY_DELAY_MS);
    await vi.waitFor(() => {
      expect(after.deps.navigate).toHaveBeenCalledWith(3, URL1, ANY);
    });
  });

  it('makes a second attempt that was due when the background stopped (recheck R5)', async () => {
    const session = new FakeArea();
    const first = flow(async () => BLOCK, session, { setTimer: manualTimers().setTimer });
    await first.nav.reloadAfterAllow(3, URL1);
    await first.nav.onBeforeNavigate(go(URL1));
    await first.nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    await flush();
    // The script stops during the 2 s; its timer goes with it. The next start makes the attempt.
    const t = manualTimers();
    const restarted = flow(async () => BLOCK, session, { setTimer: t.setTimer });
    await flush();
    const attempt = t.timers.find((x) => x.ms <= RETRY_DELAY_MS);
    expect(attempt).toBeDefined();
    attempt?.fn();
    await flush();
    expect(restarted.deps.navigate).toHaveBeenCalledWith(3, URL1, ANY);
  });

  it('times a kept second attempt for when it is due, not at once (final check of R5)', async () => {
    const session = new FakeArea();
    const first = flow(async () => BLOCK, session, { setTimer: manualTimers().setTimer });
    await first.nav.reloadAfterAllow(3, URL1);
    await first.nav.onBeforeNavigate(go(URL1));
    await first.nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    await flush();
    // The script stops 500 ms into the 2 s wait (Firefox is still refreshing the answer).
    vi.setSystemTime(Date.now() + 500);
    const t = manualTimers();
    flow(async () => BLOCK, session, { setTimer: t.setTimer });
    await flush();
    expect(t.timers.map((x) => x.ms)).toContain(RETRY_DELAY_MS - 500);
    expect(t.timers.some((x) => !(x.ms > 0))).toBe(false);
  });

  it("doesn't load the page again after a restart before the first reload's navigation starts (final check of G3)", async () => {
    const session = new FakeArea();
    const first = flow(async () => BLOCK, session, { setTimer: manualTimers().setTimer });
    await first.nav.reloadAfterAllow(3, URL1);
    await flush();
    const t = manualTimers();
    const restarted = flow(async () => BLOCK, session, { setTimer: t.setTimer });
    await flush();
    // Run every timer but the 60 s lapse (NaN included).
    for (const x of t.timers) {
      if (!(x.ms >= RETRY_WINDOW_MS - 1000)) {
        x.fn();
      }
    }
    await flush();
    expect(restarted.deps.navigate).not.toHaveBeenCalled();
  });

  it('drops a kept second attempt when the tab navigates before or after the restart reads it', async () => {
    const kept = async () => {
      const session = new FakeArea();
      const first = flow(async () => BLOCK, session, { setTimer: manualTimers().setTimer });
      await first.nav.reloadAfterAllow(3, URL1);
      await first.nav.onBeforeNavigate(go(URL1));
      await first.nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
      await flush();
      return session;
    };
    const attempts = (t: ReturnType<typeof manualTimers>) => {
      for (const x of t.timers.filter((y) => y.ms <= RETRY_DELAY_MS)) {
        x.fn();
      }
    };
    // Before the read: the navigation wins over what the previous script kept.
    const t = manualTimers();
    const early = flow(async () => BLOCK, await kept(), { setTimer: t.setTimer });
    void early.nav.onBeforeNavigate(go('https://elsewhere.example/'));
    await flush();
    expect(early.session.data.has('retries')).toBe(false);
    attempts(t);
    await flush();
    expect(early.deps.navigate).not.toHaveBeenCalled();
    // After it, before the attempt is due.
    const t2 = manualTimers();
    const late = flow(async () => BLOCK, await kept(), { setTimer: t2.setTimer });
    await flush();
    await late.nav.onBeforeNavigate(go('https://elsewhere.example/'));
    attempts(t2);
    await flush();
    expect(late.deps.navigate).not.toHaveBeenCalled();
    // Control: with no navigation, the kept attempt is made.
    const t3 = manualTimers();
    const kept3 = flow(async () => BLOCK, await kept(), { setTimer: t3.setTimer });
    await flush();
    attempts(t3);
    await flush();
    expect(kept3.deps.navigate).toHaveBeenCalledWith(3, URL1, ANY);
  });

  it("never replaces a page the user went to after the allow's reload", async () => {
    const { nav, deps } = flow();
    await nav.reloadAfterAllow(3, URL1);
    void nav.onBeforeNavigate(go(URL1));
    // The user goes to another page on the same host, and that fails.
    void nav.onBeforeNavigate(go('https://ads.example/different'));
    await nav.onErrorOccurred({ ...fail('net::ERR_CONNECTION_REFUSED'), url: 'https://ads.example/different' });
    expect(deps.probe).toHaveBeenCalledWith('https://ads.example/different');
    await vi.advanceTimersByTimeAsync(RETRY_DELAY_MS * 2);
    expect(deps.navigate).toHaveBeenCalledTimes(1);
  });

  it('binds the retry to the navigation it starts: another one first cancels it', async () => {
    const { nav, deps } = flow();
    await nav.reloadAfterAllow(3, URL1);
    // Another top-level navigation starts before the reload's own.
    void nav.onBeforeNavigate(go('https://ads.example/typed'));
    void nav.onBeforeNavigate(go(URL1));
    await nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    expect(deps.probe).toHaveBeenCalledTimes(1);
    // The reload's URL matches whatever its fragment.
    const second = flow();
    await second.nav.reloadAfterAllow(3, `${URL1}#top`);
    void second.nav.onBeforeNavigate(go(URL1));
    await second.nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    expect(second.deps.probe).not.toHaveBeenCalled();
  });

  it("doesn't make an old retry's second attempt for a newer allow's reload", async () => {
    const t = manualTimers();
    const { nav, deps } = flow(async () => BLOCK, new FakeArea(), { setTimer: t.setTimer });
    await nav.reloadAfterAllow(3, URL1);
    await nav.onBeforeNavigate(go(URL1));
    await nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    // Within the 2 s the tab shows another block page, whose allow reloads its own URL.
    await nav.onBeforeNavigate(go('chrome-extension://test-extension-id/block.html'));
    await nav.reloadAfterAllow(3, 'https://other.example/');
    t.run(RETRY_DELAY_MS);
    await flush();
    expect(deps.navigate.mock.calls.map((c) => c[1])).toEqual([URL1, 'https://other.example/']);
  });

  it('does not load the page twice when the user reloads it during the 2 s', async () => {
    const { nav, deps } = flow();
    await nav.reloadAfterAllow(3, URL1);
    void nav.onBeforeNavigate(go(URL1));
    await nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    void nav.onBeforeNavigate(go(URL1)); // the user's own reload
    await vi.advanceTimersByTimeAsync(RETRY_DELAY_MS * 2);
    expect(deps.navigate).toHaveBeenCalledTimes(1);
  });
});

describe('races with storage (recheck R2)', () => {
  it("doesn't start the reload when the user navigates while its retry is being kept", async () => {
    const session = new FakeArea();
    const write = gate();
    const set = session.set.getMockImplementation();
    session.set.mockImplementation(async (items) => {
      await write.promise;
      await set?.(items);
    });
    const { nav, deps } = flow(async () => BLOCK, session);
    const reloading = nav.reloadAfterAllow(3, URL1);
    await flush();
    expect(session.set).toHaveBeenCalledTimes(1); // the retry's write is pending
    const moving = nav.onBeforeNavigate(go('https://new.example/'));
    write.release();
    await Promise.all([reloading, moving]);
    expect(deps.navigate).not.toHaveBeenCalled();
    expect(session.data.has('retries')).toBe(false);
  });

  it("doesn't make the second attempt after the user navigated, while that navigation is still being written", async () => {
    const session = new FakeArea();
    const t = manualTimers();
    const { nav, deps } = flow(async () => BLOCK, session, { setTimer: t.setTimer });
    await nav.reloadAfterAllow(3, URL1);
    await nav.onBeforeNavigate(go(URL1));
    await nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    await flush();
    const write = gate();
    const remove = session.remove.getMockImplementation();
    session.remove.mockImplementation(async (keys) => {
      await write.promise;
      await remove?.(keys);
    });
    const moving = nav.onBeforeNavigate(go('https://new.example/'));
    await flush();
    expect(session.remove).toHaveBeenCalledTimes(1); // the cancelled retry's write is pending
    // The attempt decides on memory, not on storage.
    t.run(RETRY_DELAY_MS);
    await flush();
    expect(deps.navigate).toHaveBeenCalledTimes(1); // the first reload only
    write.release();
    await moving;
  });

  it('hands the reload and its retry a check that fails once the tab moves on', async () => {
    const t = manualTimers();
    const { nav, deps } = flow(async () => BLOCK, new FakeArea(), { setTimer: t.setTimer });
    await nav.reloadAfterAllow(3, URL1);
    const first = deps.navigate.mock.calls[0]?.[2];
    expect(first?.()).toBe(true);
    await nav.onBeforeNavigate(go(URL1));
    expect(first?.()).toBe(false);
    await nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    t.run(RETRY_DELAY_MS);
    await flush();
    const second = deps.navigate.mock.calls[1]?.[2];
    expect(second?.()).toBe(true);
    await nav.onBeforeNavigate(go('https://new.example/'));
    expect(second?.()).toBe(false);
  });
});

describe('what is kept (recheck R9)', () => {
  it('keeps a retry only until it is done, cancelled or its tab closes', async () => {
    const t = manualTimers();
    const { nav, session } = flow(async () => BLOCK, new FakeArea(), { setTimer: t.setTimer });
    const kept = () => session.data.has('retries');
    // Done: the reload worked.
    await nav.reloadAfterAllow(3, URL1);
    await flush();
    expect(kept()).toBe(true);
    await nav.onBeforeNavigate(go(URL1));
    await nav.onCompleted(go(URL1));
    await flush();
    expect(kept()).toBe(false);
    // Done: the retry failed too.
    await nav.reloadAfterAllow(3, URL1);
    await nav.onBeforeNavigate(go(URL1));
    await nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    t.run(RETRY_DELAY_MS);
    await flush();
    await nav.onBeforeNavigate(go(URL1));
    await nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    await flush();
    expect(kept()).toBe(false);
    // Done: its navigation failed for a reason no block causes.
    await nav.reloadAfterAllow(3, URL1);
    await nav.onBeforeNavigate(go(URL1));
    await nav.onErrorOccurred(fail('net::ERR_ABORTED'));
    await flush();
    expect(kept()).toBe(false);
    // Cancelled by another navigation.
    await nav.reloadAfterAllow(3, URL1);
    await nav.onBeforeNavigate(go('https://new.example/'));
    await flush();
    expect(kept()).toBe(false);
    // The tab closed.
    await nav.reloadAfterAllow(3, URL1);
    await nav.onTabRemoved(3);
    await flush();
    expect(kept()).toBe(false);
    // Its window ended.
    await nav.reloadAfterAllow(3, URL1);
    t.run(RETRY_WINDOW_MS);
    await flush();
    expect(kept()).toBe(false);
  });

  it("drops a kept retry whose window ended while no background ran, when the next one starts", async () => {
    let now = 1_800_000_000_000;
    const session = new FakeArea();
    const first = flow(async () => BLOCK, session, { now: () => now, setTimer: () => undefined });
    await first.nav.reloadAfterAllow(3, URL1);
    await flush();
    expect(session.data.has('retries')).toBe(true);
    now += RETRY_WINDOW_MS;
    flow(async () => BLOCK, session, { now: () => now, setTimer: () => undefined });
    await flush();
    expect(session.data.has('retries')).toBe(false);
  });
});

describe('events right after a restart (recheck G2, G3, G5, G7)', () => {
  /** A session whose next reads wait for `read.release()`. */
  function heldRead(session: FakeArea): { release: () => void } {
    const read = gate();
    const get = session.get.getMockImplementation();
    session.get.mockImplementation(async (key) => {
      await read.promise;
      return (await get?.(key)) ?? {};
    });
    return read;
  }

  it('applies a navigation and failure that come before the read to the kept retry, in arrival order', async () => {
    const session = new FakeArea();
    const first = flow(async () => BLOCK, session, { setTimer: () => undefined });
    await first.nav.reloadAfterAllow(3, URL1);
    // The script stops after asking for the reload; its navigation's start wakes a new one.
    const read = heldRead(session);
    const second = flow(async () => BLOCK, session);
    void second.nav.onBeforeNavigate(go(URL1));
    const failing = second.nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    await flush();
    // Nothing is decided or written before the read.
    expect(second.deps.log).not.toHaveBeenCalled();
    expect(session.data.get('retries')).toMatchObject([{ tab: 3, phase: 'expect' }]);
    read.release();
    await failing;
    expect(second.deps.probe).not.toHaveBeenCalled();
    expect(second.deps.log).toHaveBeenCalledWith('net::ERR_NAME_NOT_RESOLVED', 'retried');
    await vi.advanceTimersByTimeAsync(RETRY_DELAY_MS);
    expect(second.deps.navigate).toHaveBeenCalledWith(3, URL1, ANY);
  });

  it('ends a kept retry when its completion or final failure is the event that wakes the new script', async () => {
    for (const end of ['completed', 'failed'] as const) {
      const session = new FakeArea();
      const first = flow(async () => BLOCK, session, { setTimer: () => undefined });
      await first.nav.reloadAfterAllow(3, URL1);
      await first.nav.onBeforeNavigate(go(URL1));
      await flush();
      expect(session.data.get('retries')).toMatchObject([{ tab: 3, phase: 'loading' }]);
      const second = flow(async () => BLOCK, session, { setTimer: () => undefined });
      await (end === 'completed' ? second.nav.onCompleted(go(URL1)) : second.nav.onErrorOccurred(fail('net::ERR_ABORTED')));
      await flush();
      expect(session.data.has('retries')).toBe(false);
    }
  });

  it("keeps a second attempt due until its navigation starts, so a script that stops first leaves it to the next (recheck G3)", async () => {
    const session = new FakeArea();
    const due = (t: ReturnType<typeof manualTimers>) => t.timers.filter((x) => x.ms <= RETRY_DELAY_MS);
    const t = manualTimers();
    const first = flow(async () => BLOCK, session, { setTimer: t.setTimer });
    await first.nav.reloadAfterAllow(3, URL1);
    await first.nav.onBeforeNavigate(go(URL1));
    await first.nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    t.run(RETRY_DELAY_MS);
    await flush();
    expect(first.deps.navigate).toHaveBeenCalledTimes(2);
    // The script stops right after asking for the attempt, before its navigation starts.
    expect(session.data.get('retries')).toMatchObject([{ tab: 3, phase: 'expect', left: 0, due: expect.any(Number) as unknown }]);
    const t2 = manualTimers();
    const second = flow(async () => BLOCK, session, { setTimer: t2.setTimer });
    await flush();
    for (const x of due(t2)) {
      x.fn();
    }
    await flush();
    expect(second.deps.navigate).toHaveBeenCalledWith(3, URL1, ANY);
    // Its navigation starts: no longer due, so a further restart doesn't make it again.
    await second.nav.onBeforeNavigate(go(URL1));
    await flush();
    const started = session.data.get('retries') as Record<string, unknown>[];
    expect(started).toMatchObject([{ tab: 3, phase: 'loading' }]);
    expect(started[0]).not.toHaveProperty('due');
    const t3 = manualTimers();
    const third = flow(async () => BLOCK, session, { setTimer: t3.setTimer });
    await flush();
    expect(due(t3)).toHaveLength(0);
    expect(third.deps.navigate).not.toHaveBeenCalled();
    // Its failure still ends the retry (none left), and is probed.
    await third.nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    expect(third.deps.probe).toHaveBeenCalledTimes(1);
  });

  it("doesn't make a kept attempt again when its navigation's start comes before the read", async () => {
    const session = new FakeArea();
    const t = manualTimers();
    const first = flow(async () => BLOCK, session, { setTimer: t.setTimer });
    await first.nav.reloadAfterAllow(3, URL1);
    await first.nav.onBeforeNavigate(go(URL1));
    await first.nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    t.run(RETRY_DELAY_MS);
    await flush();
    // The script stops after asking for the attempt; that attempt's navigation start wakes a new one.
    const read = heldRead(session);
    const t2 = manualTimers();
    const second = flow(async () => BLOCK, session, { setTimer: t2.setTimer });
    void second.nav.onBeforeNavigate(go(URL1));
    read.release();
    await flush();
    for (const x of t2.timers.filter((y) => y.ms <= RETRY_DELAY_MS)) {
      x.fn();
    }
    await flush();
    expect(second.deps.navigate).not.toHaveBeenCalled();
    expect(session.data.get('retries')).toMatchObject([{ tab: 3, phase: 'loading', left: 0 }]);
  });

  it('drops a kept retry when its window ends after the restart, with no further event', async () => {
    let now = 1_800_000_000_000;
    const session = new FakeArea();
    const first = flow(async () => BLOCK, session, { now: () => now, setTimer: () => undefined });
    await first.nav.reloadAfterAllow(3, URL1);
    await first.nav.onBeforeNavigate(go(URL1));
    await flush();
    now += RETRY_WINDOW_MS / 4;
    const t = manualTimers();
    flow(async () => BLOCK, session, { now: () => now, setTimer: t.setTimer });
    await flush();
    expect(session.data.has('retries')).toBe(true);
    const lapse = t.timers.filter((x) => x.ms === (RETRY_WINDOW_MS * 3) / 4);
    expect(lapse).toHaveLength(1);
    lapse[0]?.fn();
    await flush();
    expect(session.data.has('retries')).toBe(false);
  });

  it('applies an allow and its lapse that come before the read after the kept retries', async () => {
    const session = new FakeArea();
    const read = heldRead(session);
    const t = manualTimers();
    const { nav, deps } = flow(async () => BLOCK, session, { setTimer: t.setTimer });
    const reloading = nav.reloadAfterAllow(3, URL1);
    t.run(RETRY_WINDOW_MS);
    read.release();
    await reloading;
    await flush();
    expect(deps.navigate).toHaveBeenCalledWith(3, URL1, ANY);
    expect(session.data.has('retries')).toBe(false);
  });

  it('gives the kept retries up rather than hold more than MAX_EARLY events before the read', async () => {
    const session = new FakeArea();
    const first = flow(async () => BLOCK, session, { setTimer: () => undefined });
    await first.nav.reloadAfterAllow(3, URL1);
    const read = heldRead(session);
    const second = flow(async () => BLOCK, session);
    for (let tab = 100; tab < 100 + MAX_EARLY; tab++) {
      void second.nav.onBeforeNavigate(go('https://x.example/', tab));
    }
    // One more: the waiting events run at once, on this script's state alone.
    void second.nav.onBeforeNavigate(go(URL1));
    const failing = second.nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    await flush();
    expect(second.deps.probe).toHaveBeenCalledTimes(1); // probed: the kept retry is gone
    read.release();
    await failing;
    await flush();
    // And what the previous script left is replaced, so no later script takes it over.
    expect(session.data.has('retries')).toBe(false);
  });
});

describe('a storage failure', () => {
  it('loses only the retry, never the probe or the reload', async () => {
    const session = new FakeArea();
    session.get.mockRejectedValue(new Error('storage gone'));
    session.set.mockRejectedValue(new Error('storage gone'));
    const { nav, deps } = flow(async () => BLOCK, session);
    await nav.reloadAfterAllow(3, URL1);
    expect(deps.navigate).toHaveBeenCalledWith(3, URL1, ANY);
    await nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    expect(deps.openBlockPage).toHaveBeenCalledWith(3, BLOCK, ANY);
  });
});

describe('probe admission', () => {
  it('probes a (tab, host) once while in flight; the newest failure decides (recheck R8)', async () => {
    const releases: ((b: BlockInfo) => void)[] = [];
    const { nav, deps } = flow(() => new Promise<BlockInfo>((r) => releases.push(r)));
    // Two failures of one host in one navigation (no navigation between them), and another tab.
    const first = nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    const second = nav.onErrorOccurred({ ...fail('net::ERR_NAME_NOT_RESOLVED'), url: 'https://ads.example/other' });
    const otherTab = nav.onErrorOccurred({ ...fail('net::ERR_NAME_NOT_RESOLVED'), tabId: 4 });
    await vi.waitFor(() => {
      expect(deps.probe).toHaveBeenCalledTimes(2); // tab 3 once, tab 4 once
    });
    // The first is settled at once, without holding on to the probe.
    await first;
    expect(deps.log).toHaveBeenCalledWith('net::ERR_NAME_NOT_RESOLVED', 'moved on');
    for (const r of releases) {
      r(BLOCK);
    }
    await Promise.all([second, otherTab]);
    expect(deps.probe).toHaveBeenCalledTimes(2);
    // One block page in tab 3, with the newest failure's URL.
    expect(deps.openBlockPage.mock.calls.filter((c) => c[0] === 3).map((c) => c[1])).toEqual([{ ...BLOCK, url: 'https://ads.example/other' }]);
  });

  it("replaces a tab's pending failure with a newer one of another host", async () => {
    const releases: ((b: BlockInfo | null) => void)[] = [];
    const { nav, deps } = flow(() => new Promise<BlockInfo | null>((r) => releases.push(r)));
    const first = nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    await vi.waitFor(() => {
      expect(deps.probe).toHaveBeenCalledTimes(1);
    });
    const second = nav.onErrorOccurred({ ...fail('net::ERR_NAME_NOT_RESOLVED'), url: 'https://other.example/' });
    await first;
    await vi.waitFor(() => {
      expect(deps.probe).toHaveBeenCalledTimes(2);
    });
    releases.shift()?.(BLOCK);
    releases.shift()?.({ kind: 'dns', url: 'https://other.example/', name: 'other.example', blockId: 'ijklmnop' });
    await second;
    expect(deps.openBlockPage.mock.calls.map((c) => c[1].url)).toEqual(['https://other.example/']);
  });

  it('holds at most one failure per tab, whatever arrives while its probe runs (recheck R4)', async () => {
    let release: (b: BlockInfo) => void = () => undefined;
    const { nav, deps } = flow(() => new Promise<BlockInfo>((r) => (release = r)));
    await flush(); // the kept retries are read
    const settled: number[] = [];
    const all = Array.from({ length: 1000 }, (_, i) =>
      nav.onErrorOccurred({ ...fail('net::ERR_NAME_NOT_RESOLVED'), url: `https://ads.example/${String(i)}` }).then(() => settled.push(i)),
    );
    await flush();
    expect(deps.probe).toHaveBeenCalledTimes(1);
    // Every failure but the newest returned at once: none waits on the probe or on storage.
    expect(settled).toHaveLength(999);
    release(BLOCK);
    await Promise.all(all);
    expect(deps.openBlockPage.mock.calls.map((c) => c[1].url)).toEqual(['https://ads.example/999']);
  });

  it('admits failures before reading storage, and bounds those waiting for it (recheck R4)', async () => {
    const session = new FakeArea();
    const read = gate();
    const get = session.get.getMockImplementation();
    session.get.mockImplementation(async (key) => {
      await read.promise;
      return (await get?.(key)) ?? {};
    });
    const { nav, deps } = flow(async () => BLOCK, session);
    const all = Array.from({ length: 1000 }, (_, tab) => nav.onErrorOccurred({ ...fail('net::ERR_NAME_NOT_RESOLVED'), tabId: tab }));
    await flush();
    expect(session.get).toHaveBeenCalledTimes(1); // the start's one read, not one per failure
    expect(nav.dropped).toBe(1000 - MAX_PROBES - MAX_WAITING_PROBES);
    read.release();
    await Promise.all(all);
    expect(deps.probe).toHaveBeenCalledTimes(MAX_PROBES + MAX_WAITING_PROBES);
  });

  it('bounds the probes in flight and waiting, dropping and counting the rest', async () => {
    const releases: (() => void)[] = [];
    const { nav, deps } = flow(
      () =>
        new Promise<null>((r) => {
          releases.push(() => {
            r(null);
          });
        }),
    );
    await flush();
    const total = MAX_PROBES + MAX_WAITING_PROBES + 10;
    for (let tab = 0; tab < total; tab++) {
      void nav.onErrorOccurred({ ...fail('net::ERR_NAME_NOT_RESOLVED'), tabId: tab });
    }
    await vi.waitFor(() => {
      expect(deps.probe).toHaveBeenCalledTimes(MAX_PROBES);
      expect(nav.dropped).toBe(10);
    });
    expect(deps.log).toHaveBeenCalledWith('net::ERR_NAME_NOT_RESOLVED', 'dropped');
    releases.shift()?.();
    await vi.waitFor(() => {
      expect(deps.probe).toHaveBeenCalledTimes(MAX_PROBES + 1);
    });
  });

  it("holds one failure per tab while its block page waits for storage, then opens it for the newest (recheck G1)", async () => {
    const opening = gate();
    const { nav, deps } = flow();
    deps.openBlockPage.mockImplementation(async () => {
      await opening.promise;
    });
    await flush();
    let settled = 0;
    const all: Promise<void>[] = [];
    for (let i = 0; i < 1000; i++) {
      all.push(
        nav.onErrorOccurred({ ...fail('net::ERR_NAME_NOT_RESOLVED'), url: `${URL1}?n=${String(i)}` }).then(() => {
          settled += 1;
        }),
      );
      await flush();
    }
    // The newest takes the job over; every other failure has returned.
    expect(settled).toBe(999);
    expect(deps.probe).toHaveBeenCalledTimes(1);
    expect(deps.openBlockPage).toHaveBeenCalledTimes(1);
    expect(deps.openBlockPage.mock.calls[0]?.[2]()).toBe(false); // taken over: changes nothing
    opening.release();
    await Promise.all(all);
    expect(deps.openBlockPage.mock.calls.map((c) => c[1].url)).toEqual([`${URL1}?n=0`, `${URL1}?n=999`]);
    expect(deps.openBlockPage.mock.calls[1]?.[2]()).toBe(true);
  });

  it('probes again for a failure that took over an opening job when only the allows changed (final check of G1)', async () => {
    const opening = gate();
    const { nav, deps, guard } = flow();
    deps.openBlockPage.mockImplementationOnce(async () => {
      await opening.promise;
    });
    await flush();
    const first = nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    await flush();
    expect(deps.openBlockPage).toHaveBeenCalledTimes(1);
    // The user reloads the tab while the block page opens slowly, and an allow for another
    // host changes the epoch meanwhile; the reload fails for the same still-blocked host.
    await nav.onBeforeNavigate(go(URL1));
    guard.allowsChanged();
    const second = nav.onErrorOccurred(fail('net::ERR_NAME_NOT_RESOLVED'));
    await flush();
    opening.release();
    await Promise.all([first, second]);
    await flush();
    expect(deps.probe).toHaveBeenCalledTimes(2);
    expect(deps.openBlockPage).toHaveBeenCalledTimes(2);
    expect(deps.openBlockPage.mock.calls[1]?.[2]()).toBe(true);
  });

  it('keeps a probe slot until the block page is opened, and abandons it for a newer failure of another host (recheck G1)', async () => {
    const opening = gate();
    const { nav, deps } = flow();
    deps.openBlockPage.mockImplementation(async () => {
      await opening.promise;
    });
    for (let tab = 0; tab < MAX_PROBES; tab++) {
      void nav.onErrorOccurred({ ...fail('net::ERR_NAME_NOT_RESOLVED'), tabId: tab });
    }
    await flush();
    expect(deps.openBlockPage).toHaveBeenCalledTimes(MAX_PROBES);
    // Tab 0's next failure is of another host: it replaces the opening, and waits for a slot.
    void nav.onErrorOccurred({ ...fail('net::ERR_NAME_NOT_RESOLVED'), tabId: 0, url: 'https://other.example/' });
    await flush();
    expect(deps.probe).toHaveBeenCalledTimes(MAX_PROBES);
    expect(deps.openBlockPage.mock.calls[0]?.[2]()).toBe(false);
    expect(deps.openBlockPage.mock.calls[1]?.[2]()).toBe(true);
    opening.release();
    await vi.waitFor(() => {
      expect(deps.openBlockPage).toHaveBeenCalledTimes(MAX_PROBES + 1);
    });
    expect(deps.openBlockPage.mock.calls[MAX_PROBES]?.[1].url).toBe('https://other.example/');
  });

  it("settles a closed tab's failure at once, freeing its place (recheck G7)", async () => {
    const releases: (() => void)[] = [];
    const { nav, deps } = flow(
      () =>
        new Promise<null>((r) => {
          releases.push(() => {
            r(null);
          });
        }),
    );
    const states: string[] = [];
    for (let tab = 0; tab < MAX_PROBES; tab++) {
      void nav.onErrorOccurred({ ...fail('net::ERR_NAME_NOT_RESOLVED'), tabId: tab }).then(() => states.push(`probing ${String(tab)}`));
    }
    void nav.onErrorOccurred({ ...fail('net::ERR_NAME_NOT_RESOLVED'), tabId: 50 }).then(() => states.push('waiting'));
    await flush();
    expect(deps.probe).toHaveBeenCalledTimes(MAX_PROBES);
    expect(states).toEqual([]);
    void nav.onTabRemoved(50);
    void nav.onTabRemoved(0);
    await flush();
    expect(states.sort()).toEqual(['probing 0', 'waiting']);
    expect(deps.log).toHaveBeenLastCalledWith('net::ERR_NAME_NOT_RESOLVED', 'moved on');
    for (const r of releases.splice(0)) {
      r();
    }
    await flush();
    expect(deps.probe).toHaveBeenCalledTimes(MAX_PROBES);
  });

  it('skips a waiting probe whose tab moved on before its turn, freeing its place', async () => {
    const releases: (() => void)[] = [];
    const { nav, deps } = flow(
      () =>
        new Promise<null>((r) => {
          releases.push(() => {
            r(null);
          });
        }),
    );
    for (let tab = 0; tab < MAX_PROBES; tab++) {
      void nav.onErrorOccurred({ ...fail('net::ERR_NAME_NOT_RESOLVED'), tabId: tab });
    }
    const waiting = nav.onErrorOccurred({ ...fail('net::ERR_NAME_NOT_RESOLVED'), tabId: 50 });
    await vi.waitFor(() => {
      expect(deps.probe).toHaveBeenCalledTimes(MAX_PROBES);
    });
    void nav.onBeforeNavigate(go('https://elsewhere.example/', 50));
    await waiting;
    expect(deps.log).toHaveBeenLastCalledWith('net::ERR_NAME_NOT_RESOLVED', 'moved on');
    releases.shift()?.();
    await flush();
    expect(deps.probe).toHaveBeenCalledTimes(MAX_PROBES);
  });
});
