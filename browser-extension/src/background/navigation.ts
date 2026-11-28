// The main-frame flow (browser-extension.md §3 steps 1–4): a failed page load whose error a
// block mode produces is probed; a block opens the block page in the tab, unless the tab has
// started another navigation since the failure. After an allow, the block page asks for the
// original URL to be loaded again, and once more 2 s later if that fails (Firefox serves an
// expired answer once while refreshing it).
//
// - Every tab change (the block page, the reload after an allow, its retry) is decided under a
//   ticket (tab-guard.ts) and made only if the ticket still holds right before it, after its last
//   await: none replaces a page the user went to since.
// - A retry is bound to the navigation it started: it waits (`expect`) for the tab to start
//   loading its exact URL, then (`loading`) only a failure of that navigation retries it; a new
//   navigation to the same URL (the browser starting that load again, or the user reloading it)
//   takes the binding over. Any other top-level navigation in the tab cancels it.
// - Pending retries are per tab, in memory, mirrored to `storage.session` (session.ts; README §2
//   "Restarts"): a slow reload can outlast the background script (Brave's worker and Firefox's
//   event page unload after ~30 s idle), and the failure that wakes a fresh one must still get its
//   second attempt; one that was due when the script stopped, or whose navigation hadn't started
//   yet, is made when it starts again. A retry is kept only while it can be used: it goes when its
//   navigation completes or fails for good, when another navigation starts, when the tab closes,
//   and 60 s after the allow.
// - Right after a restart, every event that reads or changes the retries waits (bounded) for the
//   one read of those the previous script kept, and is then applied to them in arrival order
//   (session.ts). Navigation tokens change at once, as each event arrives.
// - Bounded (README §2 "Bounded"), with failures admitted synchronously, before any storage wait:
//   each tab has one pending failure, its newest (one probe per (tab, host): a newer failure of
//   that host takes the probe over; one of another host replaces it); at most MAX_PROBES probes
//   run and MAX_WAITING_PROBES tabs wait, and a failure past that is dropped and counted. A
//   failure keeps its probe slot, and its place as its tab's pending failure, until its block
//   page is opened or abandoned, so nothing else waits on that page's storage write.

import { MAX_URL, type BlockInfo } from '../shared/block-info';
import { hostOf, type Host } from '../shared/host';
import { isObj, SessionMap, type SessionArea, type SessionCodec } from './session';
import { TabGuard } from './tab-guard';

export const RETRY_DELAY_MS = 2_000;
/** How long after an allow its reload, and the retry of that reload, may still happen. */
export const RETRY_WINDOW_MS = 60_000;
/** Main-frame probes in flight at once (each has the probe timeout, 5 s). */
export const MAX_PROBES = 4;
/** Tabs whose failure waits for a probe; a failure past this is dropped and counted. */
export const MAX_WAITING_PROBES = 32;
/** Probes a job may make again after allows changed under its answer (bounds a job's time). */
export const MAX_REPROBES = 2;
/** Tabs with a pending retry (each from an allow just made there); the oldest goes first. */
export const MAX_RETRIES = 16;
const RETRIES_KEY = 'retries';

export type Outcome = 'ignored' | 'retried' | 'no block' | 'block' | 'moved on' | 'dropped';

export interface NavigationDeps {
  /** The block a failed load of `url` was, or null (not set up, not a block, edge unreachable). */
  probe(url: string): Promise<BlockInfo | null>;
  /**
   * Opens the block page in the tab. `still()` tells whether the decision still holds: call it
   * right before each change to the tab, after any await, and change nothing once it is false.
   */
  openBlockPage(tabId: number, info: BlockInfo, still: () => boolean): Promise<void>;
  /** Loads `url` in the tab (`still` as for `openBlockPage`). */
  navigate(tabId: number, url: string, still: () => boolean): Promise<void>;
  /** Whether a failure with this error may be a block of a host of this kind (block-errors.ts). */
  isCandidate(error: string, host: Host['kind']): boolean;
  setTimer(fn: () => void, ms: number): void;
  /** Wall-clock ms (a pending retry's window outlives the background script). */
  now(): number;
  /** `storage.session`, where pending retries are kept. */
  session: SessionArea;
  /** Navigation tokens and the allow epoch, shared with the rest of the background. */
  guard?: TabGuard;
  /**
   * Notes each top-frame failure's `details.error` and outcome, without its URL (for the
   * browser tests of browser-extension.md §5, read in the background script's console).
   */
  log?(error: string, outcome: Outcome): void;
}

export interface FrameDetails {
  tabId: number;
  frameId: number;
  url: string;
}

export interface ErrorDetails extends FrameDetails {
  /**
   * Chromium: `net::ERR_*`; Firefox: `Error code <nsresult>`. Firefox's API schema doesn't
   * promise it, so a host name's failure without one is probed (the probe's EDE decides).
   */
  error?: string;
  /** Chromium: only `outermost_frame` is a top-level page load. */
  frameType?: string;
  /** Chromium: `prerender` loads aren't shown to the user. */
  documentLifecycle?: string;
}

/** A pending reload after an allow (see the header). */
interface Retry {
  id: number;
  url: string;
  /** Retries left after a failure of the bound navigation. */
  left: number;
  /** Wall-clock ms after which it lapses. */
  until: number;
  phase: 'expect' | 'loading';
  /** Wall-clock ms the next attempt is due: set after a failure until the attempt is made. */
  due?: number;
  /** The navigation `loading` is bound to (in memory only: tokens don't outlive the script). */
  nav?: number;
}

function hostKey(url: string): string {
  const h = hostOf(url);
  return h === null ? '' : h.kind === 'ip' ? h.ip : h.name;
}

/** A URL without its fragment (a navigation's URL as the browser reports it). */
function withoutHash(url: string): string {
  try {
    const u = new URL(url);
    u.hash = '';
    return u.href;
  } catch {
    return url;
  }
}

/** A stored retry, checked (storage is ours, but a bad entry must not break the flow). */
function parseRetry(x: unknown): [number, Retry] | null {
  if (!isObj(x)) {
    return null;
  }
  const { tab, id, url, left, until, phase, due } = x;
  if (typeof tab !== 'number' || !Number.isSafeInteger(tab) || tab < 0) {
    return null;
  }
  if (typeof id !== 'number' || typeof url !== 'string' || url.length > MAX_URL || typeof until !== 'number' || !Number.isFinite(until)) {
    return null;
  }
  if (typeof left !== 'number' || !Number.isInteger(left) || left < 0 || left > 1 || (phase !== 'expect' && phase !== 'loading')) {
    return null;
  }
  if (due !== undefined && (typeof due !== 'number' || !Number.isFinite(due))) {
    return null;
  }
  const r: Retry = { id, url, left, until, phase };
  if (due !== undefined && phase === 'expect') {
    r.due = due;
  }
  return [tab, r];
}

const retryCodec: SessionCodec<Retry> = {
  parse: (x) => (Array.isArray(x) ? x.map(parseRetry).filter((e) => e !== null) : []),
  serialize: (entries) =>
    entries.map(([tab, r]) => ({ tab, id: r.id, url: r.url, left: r.left, until: r.until, phase: r.phase, ...(r.due === undefined ? {} : { due: r.due }) })),
};

/** A tab's pending failure (its newest), waiting for a probe slot, probing, or opening its block page. */
interface Job {
  tabId: number;
  host: string;
  /** The newest failure's navigation token and URL. */
  nav: number;
  url: string;
  /** Ends the newest failure's wait with its outcome (a no-op once it has one). */
  settle(o: Outcome): void;
  /** Counts the newer failures that took the job over. */
  turn: number;
  /** Set once it is no longer its tab's pending failure (replaced, or its tab moved on or closed). */
  cancelled: boolean;
}

export class NavigationFlow {
  private readonly guard: TabGuard;
  private readonly retries: SessionMap<Retry>;
  /** Each tab's pending failure. */
  private readonly jobs = new Map<number, Job>();
  /** Jobs waiting for a probe slot, oldest first. */
  private readonly queue: Job[] = [];
  private running = 0;
  /** Failures not probed because MAX_WAITING_PROBES were already waiting. */
  dropped = 0;

  constructor(private readonly deps: NavigationDeps) {
    this.guard = deps.guard ?? new TabGuard();
    // The kept retries are taken over before any event that waited for them.
    this.retries = new SessionMap(deps.session, RETRIES_KEY, retryCodec, MAX_RETRIES, (kept) => {
      this.resume(kept);
    });
  }

  /** The tab's pending retry; a lapsed one is dropped. Called only once the retries are read. */
  private retry(tabId: number): Retry | undefined {
    const r = this.retries.get(tabId);
    if (r !== undefined && this.lapsed(r)) {
      void this.retries.delete(tabId);
      return undefined;
    }
    return r;
  }

  private lapsed(r: Retry): boolean {
    const now = this.deps.now();
    // A window further ahead than it can be means this device's clock stepped back.
    return now >= r.until || r.until - now > RETRY_WINDOW_MS;
  }

  /** Drops the retry `id` at the end of its window, if it is still pending. */
  private lapse(tabId: number, id: number): void {
    void this.retries
      .whenRead(() => (this.retries.get(tabId)?.id === id ? this.retries.delete(tabId) : undefined))
      .catch(() => undefined);
  }

  /** Takes over the retries a previous background script kept (README §2 "Restarts"). */
  private resume(kept: [number, Retry][]): void {
    for (const [tabId, r] of kept) {
      if (this.lapsed(r)) {
        void this.retries.delete(tabId);
        continue;
      }
      this.deps.setTimer(() => {
        this.lapse(tabId, r.id);
      }, r.until - this.deps.now());
      if (r.phase === 'expect' && r.due !== undefined) {
        // Its second attempt was due, or made but not started, when that script stopped: made
        // now, or when due. Events that waited for the read come after this, and may cancel it.
        this.deps.setTimer(
          () => {
            void this.attempt(tabId, r.id);
          },
          Math.max(0, r.due - this.deps.now()),
        );
      }
    }
  }

  onBeforeNavigate(d: FrameDetails): Promise<void> {
    if (d.frameId !== 0 || d.tabId < 0) {
      return Promise.resolve();
    }
    const nav = this.guard.navigated(d.tabId);
    // A failure still waiting for its turn is moot now.
    this.cancel(d.tabId, true);
    return this.retries
      .whenRead(() => {
        const r = this.retry(d.tabId);
        if (r !== undefined && withoutHash(d.url) === withoutHash(r.url)) {
          // The navigation the reload (or its retry) started: only its failure may be retried. Its
          // due time goes now that it has started. While it loads, a navigation to the same URL is
          // that load started again and takes the binding over: Firefox starts a load from an
          // extension page (the block page) once more in a web content process, with a second
          // onBeforeNavigate (seen in the browser tests).
          return this.retries.set(d.tabId, { id: r.id, url: r.url, left: r.left, until: r.until, phase: 'loading', nav });
        }
        // Any other top-level navigation cancels the retry.
        return this.retries.delete(d.tabId);
      })
      .catch(() => undefined);
  }

  onCompleted(d: FrameDetails): Promise<void> {
    if (d.frameId !== 0 || d.tabId < 0) {
      return Promise.resolve();
    }
    // The reload worked: its retry is done. A completion while a second attempt waits (`expect`;
    // e.g. an error page) leaves that attempt alone.
    return this.retries
      .whenRead(() => (this.retry(d.tabId)?.phase === 'loading' ? this.retries.delete(d.tabId) : undefined))
      .catch(() => undefined);
  }

  onTabRemoved(tabId: number): Promise<void> {
    this.guard.removed(tabId);
    // Its pending failure settles at once, and frees its place if it was waiting.
    this.cancel(tabId, false);
    return this.retries.delete(tabId).catch(() => undefined);
  }

  async onErrorOccurred(d: ErrorDetails): Promise<void> {
    if (d.frameId !== 0 || d.tabId < 0) {
      return;
    }
    if (d.frameType !== undefined && d.frameType !== 'outermost_frame') {
      return;
    }
    const error = d.error ?? '(none)';
    const nav = this.guard.nav(d.tabId);
    const host = hostOf(d.url);
    // An IP-literal URL needs an error a refusal can cause (block-errors.ts): no error, no probe.
    const candidate = host !== null && (d.error === undefined ? host.kind === 'name' : this.deps.isCandidate(d.error, host.kind));
    if (d.documentLifecycle === 'prerender') {
      this.deps.log?.(error, 'ignored');
      return;
    }
    if (!candidate) {
      void this.retries.whenRead(() => this.endBoundRetry(d, nav)).catch(() => undefined);
      this.deps.log?.(error, 'ignored');
      return;
    }
    // Synchronous, once the retries are read, until the failure is retried or admitted to its
    // probe; it then waits until its outcome is known (a block page has started opening).
    const outcome = await this.retries.whenRead((): Outcome | Promise<Outcome> => (this.retryAfterFailure(d, nav) ? 'retried' : this.admit(d.tabId, d.url, nav)));
    this.deps.log?.(error, outcome);
  }

  /** Loads `url` in the tab after an allow, with one retry 2 s after a failure. */
  async reloadAfterAllow(tabId: number, url: string): Promise<void> {
    const nav = this.guard.nav(tabId);
    const id = crypto.getRandomValues(new Uint32Array(1))[0] ?? 0;
    // Kept before the load starts: its failure may wake a new background script.
    const kept = this.retries.set(tabId, { id, url, left: 1, until: this.deps.now() + RETRY_WINDOW_MS, phase: 'expect' });
    this.deps.setTimer(() => {
      this.lapse(tabId, id);
    }, RETRY_WINDOW_MS);
    // A storage failure loses the retry, never the reload.
    await kept.catch(() => undefined);
    // The user may have gone elsewhere meanwhile: their page wins.
    const still = (): boolean => this.guard.nav(tabId) === nav;
    if (still()) {
      await this.deps.navigate(tabId, url, still);
    }
  }

  /** A failure that ends the retry's navigation without a retry ends the retry too. */
  private endBoundRetry(d: ErrorDetails, nav: number): Promise<void> | undefined {
    const r = this.retry(d.tabId);
    if (r?.phase === 'loading' && (r.nav === undefined || r.nav === nav) && hostKey(d.url) === hostKey(r.url)) {
      return this.retries.delete(d.tabId);
    }
    return undefined;
  }

  /**
   * True when the failure is of the navigation a reload after an allow started, with a retry
   * left: the retry is due 2 s later, unless another navigation cancels it meanwhile. Any other
   * failure ends the tab's retry.
   */
  private retryAfterFailure(d: ErrorDetails, nav: number): boolean {
    const r = this.retry(d.tabId);
    if (r === undefined) {
      return false;
    }
    // A retry kept by a previous background script has no token: its host must match.
    const bound = r.phase === 'loading' && (r.nav === undefined || r.nav === nav) && hostKey(d.url) === hostKey(r.url);
    if (!bound || r.left === 0) {
      void this.retries.delete(d.tabId);
      return false;
    }
    // Kept with its due time, so a background script that starts meanwhile still makes it.
    const next: Retry = { id: r.id, url: r.url, left: r.left - 1, until: r.until, phase: 'expect', due: this.deps.now() + RETRY_DELAY_MS };
    void this.retries.set(d.tabId, next).catch(() => undefined);
    this.deps.setTimer(() => {
      void this.attempt(d.tabId, next.id);
    }, RETRY_DELAY_MS);
    return true;
  }

  /**
   * Makes a retry's second attempt, unless the tab moved on since the failure: every top-level
   * navigation cancels the retry or (its own, or the user's reload of its URL) binds it
   * (`loading`), and a closed tab drops it. Its due time stays until its navigation starts: a
   * script that stops before then leaves the attempt for the next one to make.
   */
  private async attempt(tabId: number, id: number): Promise<void> {
    // Timed only once the retries are read (at the restore, or after a failure).
    const pending = (): Retry | undefined => {
      const r = this.retry(tabId);
      return r?.id === id && r.phase === 'expect' ? r : undefined;
    };
    const r = pending();
    if (r !== undefined) {
      await this.deps.navigate(tabId, r.url, () => pending() !== undefined);
    }
  }

  /**
   * Admits the tab's newest failure, synchronously: a failure of the host already pending takes
   * that job over (its probe, or the block page being opened), one of another host replaces it,
   * and a new one gets a slot or a place in the queue, or is dropped. The failure it replaces
   * settles as moved on. Settles with the failure's outcome.
   */
  private admit(tabId: number, url: string, nav: number): Promise<Outcome> {
    const host = hostKey(url);
    return new Promise((resolve) => {
      const cur = this.jobs.get(tabId);
      if (cur?.host === host) {
        cur.settle('moved on');
        cur.nav = nav;
        cur.url = url;
        cur.settle = resolve;
        cur.turn += 1;
        return;
      }
      this.cancel(tabId, false);
      const job: Job = { tabId, host, nav, url, settle: resolve, turn: 0, cancelled: false };
      if (this.running < MAX_PROBES) {
        this.jobs.set(tabId, job);
        this.start(job);
      } else if (this.queue.length < MAX_WAITING_PROBES) {
        this.jobs.set(tabId, job);
        this.queue.push(job);
      } else {
        this.dropped += 1;
        resolve('dropped');
      }
    });
  }

  /**
   * Settles the tab's pending failure as moved on. A queued one leaves the queue; a running probe
   * or block page opening finishes (it holds its slot) and changes nothing, unless `onlyQueued`
   * keeps it for a newer failure of its host.
   */
  private cancel(tabId: number, onlyQueued: boolean): void {
    const job = this.jobs.get(tabId);
    if (job === undefined) {
      return;
    }
    const i = this.queue.indexOf(job);
    if (i < 0 && onlyQueued) {
      return;
    }
    if (i >= 0) {
      this.queue.splice(i, 1);
    }
    this.jobs.delete(tabId);
    job.cancelled = true;
    job.settle('moved on');
  }

  private start(job: Job): void {
    this.running += 1;
    void this.run(job).finally(() => {
      this.running -= 1;
      const next = this.queue.shift();
      if (next !== undefined) {
        this.start(next);
      }
    });
  }

  /**
   * Probes for a job, then opens the block page for a block. When allows change during the probe,
   * its answer may be stale: probed once more. The block page opens under a ticket for the
   * newest failure's navigation and the epoch the answer came under, re-checked right before
   * the tab changes. The job keeps its slot until the page is opened or abandoned; a newer
   * failure of the host that takes it over meanwhile has the page opened again for itself once
   * this opening ends (one opening per job at a time).
   */
  private async run(job: Job): Promise<void> {
    let info: BlockInfo | null = null;
    let epoch = this.guard.epoch;
    if (this.guard.nav(job.tabId) === job.nav) {
      for (let attempt = 0; attempt < 2; attempt++) {
        epoch = this.guard.epoch;
        info = await this.deps.probe(job.url).catch(() => null);
        if (this.guard.epoch === epoch) {
          break;
        }
      }
    }
    // The failure the answer was probed for (a newer one of the host may take the job over).
    let answered = job.turn;
    let reprobes = 0;
    for (;;) {
      if (job.cancelled) {
        // Replaced, or its tab moved on or closed: already settled.
        return;
      }
      const turn = job.turn;
      const ticket = this.guard.ticket(job.tabId, job.nav, epoch);
      if (!this.guard.holds(ticket) && turn !== answered && this.guard.nav(job.tabId) === job.nav && reprobes < MAX_REPROBES) {
        // A newer failure took the job over and only the allows changed since the answer it
        // inherited: that answer may be stale, so probe again for it rather than leave the user
        // on the browser's error page (§3 step 2).
        reprobes += 1;
        answered = turn;
        epoch = this.guard.epoch;
        info = await this.deps.probe(job.url).catch(() => null);
        continue;
      }
      if (!this.guard.holds(ticket) || info === null) {
        this.jobs.delete(job.tabId);
        job.settle(this.guard.holds(ticket) ? 'no block' : 'moved on');
        return;
      }
      job.settle('block');
      /** True while this failure is still its tab's newest and pending. */
      const current = (): boolean => !job.cancelled && job.turn === turn;
      try {
        await this.deps.openBlockPage(job.tabId, { ...info, url: job.url }, () => current() && this.guard.holds(ticket));
      } catch {
        // The tab is gone, or refused the change: nothing more to do for this failure.
      }
      if (current()) {
        this.jobs.delete(job.tabId);
        return;
      }
    }
  }
}
