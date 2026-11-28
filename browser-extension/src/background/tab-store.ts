// This tab's blocked hosts for the popup (browser-extension.md §3 step 5), kept in
// `storage.session`: in memory only, cleared with the browser, the tab or its next page, and
// surviving the Brave service worker's restarts. At most MAX_PER_TAB hosts per tab.
//
// - Writes are coalesced per tab (README §2 "Bounded"): changes made while a tab's write runs
//   wait in one pending change carrying the latest state, so a request-heavy page costs at most
//   one write in flight and one waiting, whatever its failure rate.
// - A host is listed under a ticket (tab-guard.ts), checked as it is admitted and again by the
//   writer after its last await (the read of the stored list), right before the write: a result
//   found for an earlier page or a closed tab, or answered before allows changed, is dropped
//   instead of filling the next page's list or the badge. The tab's navigation token changes
//   with each top-level navigation (NavigationFlow), which also clears the list.
// - No copy is kept in memory: each write reads the stored list first, so a restarted script
//   merges its changes into what the previous one left (README §2 "Restarts").

import type { TabBlock } from '../shared/messages';
import { isObj, type SessionArea } from './session';
import type { TabGuard, Ticket } from './tab-guard';

export type { SessionArea } from './session';

export const MAX_PER_TAB = 50;

const optStr = (x: unknown): x is string | undefined => x === undefined || (typeof x === 'string' && x.length <= 255);

/** Stored entries, checked (storage is ours, but a bad entry must not break the popup). */
export function parseTabBlocks(x: unknown): TabBlock[] {
  if (!Array.isArray(x)) {
    return [];
  }
  const out: TabBlock[] = [];
  for (const e of x.slice(0, MAX_PER_TAB)) {
    if (!isObj(e) || typeof e.host !== 'string' || e.host.length > 255 || typeof e.at !== 'number') {
      continue;
    }
    if (e.kind !== 'dns' && e.kind !== 'ip') {
      continue;
    }
    const { blockId, bundle, head, lookup, verdict } = e;
    if (!optStr(blockId) || !optStr(bundle) || !optStr(head) || !optStr(lookup) || !optStr(verdict)) {
      continue;
    }
    const b: TabBlock = { host: e.host, kind: e.kind, at: e.at };
    if (blockId !== undefined) {
      b.blockId = blockId;
    }
    if (bundle !== undefined) {
      b.bundle = bundle;
    }
    if (head !== undefined) {
      b.head = head;
    }
    if (lookup !== undefined) {
      b.lookup = lookup;
    }
    if (verdict !== undefined) {
      b.verdict = verdict;
    }
    out.push(b);
  }
  return out;
}

/** A tab's changes not yet written: whether its list starts empty, and the hosts to add. */
interface Pending {
  clear: boolean;
  /** Each host to add, with the ticket it was found under. */
  adds: Map<string, { block: TabBlock; ticket: Ticket }>;
  done: Promise<void>;
  resolve: () => void;
  reject: (e: unknown) => void;
}

export class TabStore {
  private readonly pending = new Map<number, Pending>();
  private readonly writing = new Set<number>();

  constructor(
    private readonly area: SessionArea,
    private readonly guard: TabGuard,
    private readonly onChange: (tabId: number, count: number) => void = () => undefined,
  ) {}

  private static key(tabId: number): string {
    return `tab:${String(tabId)}`;
  }

  async list(tabId: number): Promise<TabBlock[]> {
    const k = TabStore.key(tabId);
    return parseTabBlocks((await this.area.get(k))[k]);
  }

  /**
   * Adds or refreshes a host found under `ticket` (default: the tab as it is now); past the cap
   * the oldest host goes. Dropped if the ticket no longer holds.
   */
  record(tabId: number, block: TabBlock, ticket: Ticket = this.guard.ticket(tabId)): Promise<void> {
    if (ticket.tabId !== tabId || !this.guard.holds(ticket)) {
      return Promise.resolve();
    }
    const p = this.pendingFor(tabId);
    p.adds.delete(block.host);
    p.adds.set(block.host, { block, ticket });
    while (p.adds.size > MAX_PER_TAB) {
      const oldest = p.adds.keys().next().value;
      if (oldest === undefined) {
        break;
      }
      p.adds.delete(oldest);
    }
    this.kick(tabId);
    return p.done;
  }

  /** Empties the tab's list for its next page. */
  clear(tabId: number): Promise<void> {
    return this.restart(tabId);
  }

  /** Forgets a closed tab. */
  remove(tabId: number): Promise<void> {
    return this.restart(tabId);
  }

  private restart(tabId: number): Promise<void> {
    const p = this.pendingFor(tabId);
    p.clear = true;
    p.adds.clear();
    this.kick(tabId);
    return p.done;
  }

  private pendingFor(tabId: number): Pending {
    let p = this.pending.get(tabId);
    if (p === undefined) {
      let resolve: () => void = () => undefined;
      let reject: (e: unknown) => void = () => undefined;
      const done = new Promise<void>((res, rej) => {
        resolve = res;
        reject = rej;
      });
      // Callers may ignore the outcome; a failed write is then not an unhandled rejection.
      done.catch(() => undefined);
      p = { clear: false, adds: new Map(), done, resolve, reject };
      this.pending.set(tabId, p);
    }
    return p;
  }

  /** Starts the tab's writer unless it runs; a running one takes the pending change next. */
  private kick(tabId: number): void {
    if (!this.writing.has(tabId)) {
      this.writing.add(tabId);
      void this.write(tabId);
    }
  }

  private async write(tabId: number): Promise<void> {
    for (;;) {
      const p = this.pending.get(tabId);
      if (p === undefined) {
        this.writing.delete(tabId);
        return;
      }
      this.pending.delete(tabId);
      try {
        let list = p.clear ? [] : await this.list(tabId);
        // After the last await: a host whose ticket no longer holds isn't listed.
        for (const { block: b, ticket } of p.adds.values()) {
          if (!this.guard.holds(ticket)) {
            continue;
          }
          list = list.filter((x) => x.host !== b.host);
          list.push(b);
        }
        while (list.length > MAX_PER_TAB) {
          list.shift();
        }
        const k = TabStore.key(tabId);
        await (list.length === 0 ? this.area.remove(k) : this.area.set({ [k]: list }));
        this.onChange(tabId, list.length);
        p.resolve();
      } catch (e) {
        p.reject(e);
      }
    }
  }
}
