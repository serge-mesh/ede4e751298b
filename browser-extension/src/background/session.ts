// `storage.session` as the background script uses it: in memory only, cleared with the browser,
// and surviving the restarts of Brave's service worker and Firefox's event page (README §2
// "Restarts": state a restart would lose is kept here).

/** The part of `storage.session` the background uses. */
export interface SessionArea {
  get(keys: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string): Promise<void>;
}

export const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);

const asError = (e: unknown): Error => (e instanceof Error ? e : new Error(String(e)));

/**
 * Events a `SessionMap` holds while it reads the stored map at start (README §2 "Bounded"). Past
 * this it gives that map up: losing a kept retry or URL is the safe failure.
 */
export const MAX_EARLY = 64;

/** How a `SessionMap` stores its entries under its key. */
export interface SessionCodec<V> {
  /** The stored entries, checked (storage is ours, but a bad entry must not break the flow). */
  parse(stored: unknown): [number, V][];
  /** What is stored for the entries, oldest first. */
  serialize(entries: readonly [number, V][]): unknown;
}

interface Deferred {
  done: Promise<void>;
  resolve: () => void;
  reject: (e: unknown) => void;
}

function deferred(): Deferred {
  let resolve: () => void = () => undefined;
  let reject: (e: unknown) => void = () => undefined;
  const done = new Promise<void>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  // Callers may ignore the outcome; a failed write is then not an unhandled rejection.
  done.catch(() => undefined);
  return { done, resolve, reject };
}

/**
 * Per-tab state kept in memory and mirrored to one `storage.session` key, at most `max` tabs
 * (the oldest goes first; README §2 "Bounded").
 *
 * - The map a previous background script left is read once, at start. Until that read is done,
 *   every event that reads or changes the map (`whenRead`, `set`, `delete`) waits in a list, in
 *   arrival order; once it is done, the restored entries are installed, handed to `restore`, and
 *   the waiting events applied in order. The kept state is older than any event this script
 *   sees, so each event acts on it as it would have without the restart; and nothing is changed
 *   or written before the read, so a restart never overwrites kept state it hasn't read (README
 *   §2 "Restarts").
 * - At most MAX_EARLY events wait. One more gives the stored map up: the waiting events run at
 *   once on this script's (empty) map, and its state replaces the stored one.
 * - After the read, reads and changes are synchronous, on memory: a decision never waits on
 *   storage, so no event can slip in between a decision and the change it makes.
 * - Writes are coalesced (one in flight, one pending, always the latest state); each change's
 *   promise settles with the write that carries it.
 */
export class SessionMap<V> {
  private readonly map = new Map<number, V>();
  /** Events waiting for the stored map to be read, oldest first; null once events run at once. */
  private early: (() => void)[] | null = [];
  /** True once too many events waited and the stored map was given up. */
  gaveUp = false;
  private pending: Deferred | null = null;
  private writing = false;
  /** Settles once the stored map has been read and the events that waited for it applied. */
  readonly ready: Promise<void>;

  constructor(
    private readonly area: SessionArea,
    private readonly key: string,
    private readonly codec: SessionCodec<V>,
    private readonly max: number,
    /** Called with the restored entries, before any event that waited for them. */
    private readonly restore: (kept: [number, V][]) => void = () => undefined,
  ) {
    this.ready = this.load();
  }

  /** True once events run at once (the stored map has been read, or given up). */
  get loaded(): boolean {
    return this.early === null;
  }

  /** The tab's state. Valid only once `loaded`: read it inside `whenRead`. */
  get(tabId: number): V | undefined {
    return this.map.get(tabId);
  }

  entries(): [number, V][] {
    return [...this.map];
  }

  /**
   * Runs `fn`, which may read and change the map, once the stored map has been read: at once if
   * it has been, else in arrival order right after the read. Settles with what `fn` returns.
   */
  whenRead<T>(fn: () => T): Promise<Awaited<T>> {
    if (this.early === null) {
      try {
        return Promise.resolve(fn());
      } catch (e) {
        return Promise.reject(asError(e));
      }
    }
    const early = this.early;
    return new Promise<Awaited<T>>((resolve, reject) => {
      const run = (): void => {
        try {
          // A promise `fn` returns is adopted: this settles with it.
          resolve(fn() as Awaited<T> | PromiseLike<Awaited<T>>);
        } catch (e) {
          reject(asError(e));
        }
      };
      if (early.length < MAX_EARLY) {
        early.push(run);
        return;
      }
      // Too many at once: go on with this script's state alone.
      this.early = null;
      this.gaveUp = true;
      for (const f of early) {
        f();
      }
      run();
    });
  }

  /** Sets the tab's state (it becomes the newest), once the stored map has been read. */
  set(tabId: number, value: V): Promise<void> {
    return this.whenRead(() => {
      this.map.delete(tabId);
      this.map.set(tabId, value);
      this.trim();
      return this.flush();
    });
  }

  /** Drops the tab's state, once the stored map has been read. */
  delete(tabId: number): Promise<void> {
    return this.whenRead(() => (this.map.delete(tabId) ? this.flush() : undefined));
  }

  private trim(): void {
    while (this.map.size > this.max) {
      const oldest = this.map.keys().next().value;
      if (oldest === undefined) {
        return;
      }
      this.map.delete(oldest);
    }
  }

  private async load(): Promise<void> {
    let stored: [number, V][] = [];
    try {
      stored = this.codec.parse((await this.area.get(this.key))[this.key]);
    } catch {
      // Unreadable: start empty.
    }
    const waiting = this.early;
    if (waiting === null) {
      // Given up: this script's state replaces what the previous one left.
      if (stored.length > 0) {
        void this.flush();
      }
      return;
    }
    for (const [tabId, v] of stored) {
      this.map.set(tabId, v);
    }
    this.trim();
    // Duplicates or past the cap: what is kept is stored again.
    const shrunk = this.map.size < stored.length;
    this.early = null;
    this.restore(this.entries());
    for (const f of waiting) {
      f();
    }
    if (shrunk) {
      void this.flush();
    }
  }

  private flush(): Promise<void> {
    this.pending ??= deferred();
    const { done } = this.pending;
    if (!this.writing) {
      this.writing = true;
      void this.write();
    }
    return done;
  }

  /** Writes the latest state until no change waits. Only ever started once events run at once. */
  private async write(): Promise<void> {
    for (;;) {
      const p = this.pending;
      if (p === null) {
        this.writing = false;
        return;
      }
      this.pending = null;
      try {
        await (this.map.size === 0 ? this.area.remove(this.key) : this.area.set({ [this.key]: this.codec.serialize([...this.map]) }));
        p.resolve();
      } catch (e) {
        p.reject(e);
      }
    }
  }
}
