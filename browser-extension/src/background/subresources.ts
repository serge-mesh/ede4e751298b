// Blocked sub-resource detection (browser-extension.md §1, §3 step 5): off until the options page
// grants the optional `webRequest` + `<all_urls>` permissions. A failed request whose error a
// block mode produces is probed like a page load, and a block is listed for its tab.
//
// Bounded: one probe per host at a time, results remembered per host for CACHE_TTL_MS (at most
// MAX_CACHE hosts), at most MAX_PENDING hosts waiting (others are dropped and counted) and
// CONCURRENCY probes in flight.
//
// - Each failure is tagged with its tab's navigation token, and each probe with the allow epoch
//   it started in (tab-guard.ts). A block is listed for a tab only if neither has changed, checked
//   right before each listing: a probe that ends after the tab moved to another page doesn't list
//   its host there, and one answered before allows changed lists nothing.
// - A probe that started before allows changed may report a block an allow has since lifted: its
//   result is neither cached nor listed, and the host is probed once more for the tabs that saw
//   it. Cached results belong to the epoch they were found in.
// - The token changes when the tab's next navigation starts, but the page it leaves runs on until
//   the next one commits, and then runs its pagehide/unload handlers (beacons). Brave (Chromium)
//   says which document a request came from: a failure from one being unloaded
//   (`documentLifecycle: pending_deletion`), one going into the back/forward cache (`cached`,
//   e.g. a pagehide beacon) or a prerendered page nobody sees yet (`prerender`) is ignored, not
//   listed against the tab's next page. Limits: Firefox has no such
//   field, so there a request of the old page that fails after the next navigation starts (an
//   unload beacon, say) is listed for the next page; and on both, so is one the old page makes
//   between the next navigation's start and its commit, while the old page is still active.

import type { BlockInfo } from '../shared/block-info';
import { hostOf, type Host } from '../shared/host';
import type { TabBlock } from '../shared/messages';
import type { TabGuard, Ticket } from './tab-guard';

export const CACHE_TTL_MS = 60_000;
export const MAX_CACHE = 512;
export const MAX_PENDING = 64;
export const CONCURRENCY = 4;
/** Most tabs one pending host remembers. */
const MAX_TABS_PER_HOST = 64;

export interface SubresourceDeps {
  probe(url: string): Promise<BlockInfo | null>;
  /** Navigation tokens and the allow epoch, shared with the rest of the background. */
  guard: TabGuard;
  /** Lists a block for the tab, unless `ticket` no longer holds (TabStore). */
  record(tabId: number, block: TabBlock, ticket: Ticket): Promise<void>;
  /** Whether a failure with this error may be a block of a host of this kind (block-errors.ts). */
  isCandidate(error: string, host: Host['kind']): boolean;
  now(): number;
}

export interface RequestErrorDetails {
  tabId: number;
  url: string;
  error: string;
  type?: string;
  /** Chromium only: the lifecycle of the document the request came from. */
  documentLifecycle?: string;
}

/** Chromium document lifecycles whose requests belong to no page the tab shows (see the header). */
const NOT_SHOWN: ReadonlySet<string> = new Set(['pending_deletion', 'prerender', 'cached']);

/** The popup's entry for a block. */
export function tabBlockOf(info: BlockInfo, at: number): TabBlock {
  if (info.kind === 'ip') {
    return { host: info.ip, kind: 'ip', at };
  }
  const b: TabBlock = { host: info.name, kind: 'dns', blockId: info.blockId, at };
  for (const k of ['bundle', 'head', 'lookup', 'verdict'] as const) {
    const v = info[k];
    if (v !== undefined) {
      b[k] = v;
    }
  }
  return b;
}

export class SubresourceWatcher {
  private readonly cache = new Map<string, { at: number; epoch: number; block: BlockInfo | null }>();
  /** Hosts waiting for or in a probe: a URL to probe and each tab's navigation token. */
  private readonly pending = new Map<string, { url: string; tabs: Map<number, number>; again: boolean }>();
  private readonly queue: string[] = [];
  private running = 0;
  /** Failures not probed because too many hosts were waiting. */
  dropped = 0;

  constructor(private readonly deps: SubresourceDeps) {}

  onErrorOccurred(d: RequestErrorDetails): void {
    if (d.tabId < 0 || d.type === 'main_frame' || (d.documentLifecycle !== undefined && NOT_SHOWN.has(d.documentLifecycle))) {
      return;
    }
    const host = hostOf(d.url);
    if (host === null || !this.deps.isCandidate(d.error, host.kind)) {
      return;
    }
    const { guard } = this.deps;
    const key = host.kind === 'ip' ? `ip:${host.ip}` : `name:${host.name}`;
    const now = this.deps.now();
    const hit = this.cache.get(key);
    if (hit?.epoch === guard.epoch && now - hit.at < CACHE_TTL_MS) {
      if (hit.block !== null) {
        void this.deps.record(d.tabId, tabBlockOf(hit.block, now), guard.ticket(d.tabId)).catch(() => undefined);
      }
      return;
    }
    const nav = guard.nav(d.tabId);
    const waiting = this.pending.get(key);
    if (waiting !== undefined) {
      if (waiting.tabs.has(d.tabId) || waiting.tabs.size < MAX_TABS_PER_HOST) {
        waiting.tabs.set(d.tabId, nav);
      }
      return;
    }
    if (this.pending.size >= MAX_PENDING) {
      this.dropped += 1;
      return;
    }
    this.pending.set(key, { url: d.url, tabs: new Map([[d.tabId, nav]]), again: false });
    this.queue.push(key);
    this.pump();
  }

  private pump(): void {
    while (this.running < CONCURRENCY) {
      const key = this.queue.shift();
      if (key === undefined) {
        return;
      }
      this.running += 1;
      void this.run(key).finally(() => {
        this.running -= 1;
        this.pump();
      });
    }
  }

  private async run(key: string): Promise<void> {
    const job = this.pending.get(key);
    if (job === undefined) {
      return;
    }
    const { guard } = this.deps;
    const epoch = guard.epoch;
    const block = await this.deps.probe(job.url).catch(() => null);
    if (epoch !== guard.epoch) {
      // Started before allows changed: probe once more rather than list a lifted block.
      if (!job.again) {
        job.again = true;
        this.queue.unshift(key);
      } else {
        this.pending.delete(key);
      }
      return;
    }
    this.pending.delete(key);
    const now = this.deps.now();
    this.cache.delete(key);
    this.cache.set(key, { at: now, epoch, block });
    while (this.cache.size > MAX_CACHE) {
      const oldest = this.cache.keys().next().value;
      if (oldest === undefined) {
        break;
      }
      this.cache.delete(oldest);
    }
    if (block === null) {
      return;
    }
    for (const [tabId, nav] of job.tabs) {
      // Checked right before each listing, so an allow or navigation in between stops the rest.
      const ticket = guard.ticket(tabId, nav, epoch);
      if (guard.holds(ticket)) {
        void this.deps.record(tabId, tabBlockOf(block, now), ticket).catch(() => undefined);
      }
    }
  }
}
