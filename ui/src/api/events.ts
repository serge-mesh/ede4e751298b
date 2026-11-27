// The UI WebSocket `/api/ui/v1/events` (api.md §7): `{type, data}` frames that keep the UI
// live. Core checks basic auth on the upgrade and that the Origin is the page's own
// (`https://` + Host, `http://` with web.tls off); the browser sets both, and the socket URL
// is the page's own host, so it connects under the CSP's `connect-src 'self'`.
import * as React from "react";
import { useQueryClient, type Query, type QueryClient, type QueryFilters } from "@tanstack/react-query";
import { API_BASE } from "./http";
import { qk, refreshPagedLists } from "./queries";
import { nextOrder } from "./order";
import type { AlertEvent, AlertEventItem, DnssecEvent, FeedRunEvent, FeedRunItem, JobEvent, JobsView, LancaEvent, RestoreEvent, TempAllowEvent, UiEventFrame } from "./types";
import { timeOrder } from "@/lib/format";

/**
 * The UI events core sends (its OpenAPI `UiEventFrame`: api.md §7's five, and core's `restore`,
 * `temp_allow`, `dnssec`, `dnssec_queued`, `lanca` and `lanca_served`, which the spec doesn't name
 * yet), `lagged` (core dropped events for this socket), and `resync`, which the UI itself gives its
 * listeners after a reconnect or a restore (events may have been missed, or everything changed).
 */
export type UiEventType = UiEventFrame["type"] | "resync";

export interface UiEvent {
  type: UiEventType | string;
  data: unknown;
}

export type ConnectionState = "connecting" | "open" | "closed";

/**
 * The alerts an `alert` event lists (AlertEvent, coalesced: each alert changed since the previous
 * one, once, with its latest state; a change is a raise, resolve or delete, or new evidence) and
 * whether it lists only some (`truncated`: any alert may have changed). Read defensively: an item
 * without a whole-number `id` is left out, and an event whose list can't be read counts as
 * truncated.
 */
export function alertsOf(data: unknown): { alerts: AlertEventItem[]; truncated: boolean } {
  const d = (data && typeof data === "object" ? data : {}) as Partial<AlertEvent>;
  const list: unknown[] = Array.isArray(d.alerts) ? d.alerts : [];
  const alerts = list.filter((a): a is AlertEventItem => !!a && typeof a === "object" && Number.isSafeInteger((a as AlertEventItem).id));
  return { alerts, truncated: d.alerts_truncated !== false || !Array.isArray(d.alerts) };
}

/**
 * The runs a `feed_run` event lists (FeedRunEvent, coalesced: every run stored since the previous
 * one, in order, with the version and, for a manual feed, `saved_at`, the save time of the file it
 * read: its `updated_at`) and whether it lists only some (`truncated`: any feed's runs may have
 * changed). Read defensively: an item without a feed is left out, and an event whose list can't be
 * read counts as truncated.
 */
export function feedRunsOf(data: unknown): { runs: FeedRunItem[]; truncated: boolean } {
  const d = (data && typeof data === "object" ? data : {}) as Partial<FeedRunEvent>;
  const list: unknown[] = Array.isArray(d.runs) ? d.runs : [];
  const runs = list.filter((r): r is FeedRunItem => !!r && typeof r === "object" && typeof (r as FeedRunItem).feed === "string");
  return { runs, truncated: d.runs_truncated !== false || !Array.isArray(d.runs) };
}

/** A heavy job's id as `heavy_running` and `JobEvent.job` name it (`kind:target`). */
export const jobId = (kind: string, target: string) => `${kind}:${target}`;

/** The heavy-job kinds the UI follows (scheduler kinds in core: compiler JOB_KIND, feeds/ingest.rs). */
export const JOB_KIND = { build: "bundle_build", feedRun: "feed_ingest" } as const;

/** The event socket URL for the page's own origin. */
export function eventsUrl(loc: Pick<Location, "protocol" | "host"> = window.location): string {
  const scheme = loc.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${loc.host}${API_BASE}/events`;
}

/** Parses one frame; anything that isn't `{type: string, data}` is ignored. */
export function parseEvent(raw: unknown): UiEvent | null {
  if (typeof raw !== "string" || raw.length > 256 * 1024) return null;
  try {
    const v = JSON.parse(raw) as unknown;
    if (v && typeof v === "object" && typeof (v as UiEvent).type === "string") {
      return { type: (v as UiEvent).type, data: (v as UiEvent).data };
    }
  } catch {
    // Not JSON: ignored.
  }
  return null;
}

/**
 * Refetches everything after events may have been missed (a reconnect, `lagged`, a restore),
 * except a manual feed's file (up to the download cap, qk.manualFile): an open editor reads its
 * runs on `resync`/`lagged` and reloads only when another writer changed the file; a closed
 * editor's cached file is only marked stale (a missed `feed_run` may have changed it), so the
 * next open or import's base_version reads it again.
 *
 * Reads still in flight are cancelled first, or one sent before the change could land after it:
 * TanStack's refetch replaces a read only for a query that already has data, and an inactive
 * query's read clears its invalidation when it lands. The cancel is silent and the refetch comes
 * at once, so whoever awaits a cancelled read of an active query gets the new one; an inactive
 * one keeps its earlier state, marked stale.
 */
export function invalidateAll(qc: QueryClient) {
  const notManualFile = (q: { queryKey: readonly unknown[] }) => q.queryKey[0] !== qk.manualFile("")[0];
  void qc.cancelQueries({ predicate: notManualFile }, { silent: true });
  void qc.invalidateQueries({ predicate: notManualFile });
  markClosedFilesStale(qc);
}

/** Every closed manual-file editor's cached file (qk.manualFile, inactive) is marked stale, not read: its next open, or an import's base_version, reads it again. */
function markClosedFilesStale(qc: QueryClient, feed?: string) {
  void qc.invalidateQueries({ queryKey: feed === undefined ? qk.manualFile("").slice(0, 1) : qk.manualFile(feed), type: "inactive", refetchType: "none" });
}

/**
 * What an event changed: the queries `filters` match (one set, or several: a query more than one
 * matches counts once) are marked stale and the active ones read again. A read in flight, which
 * may have been answered before the change, is never cancelled (a stream of events faster than
 * one read would leave the page with none landing): it lands, and the query is invalidated again
 * once it settles, so an active one reads once more, however many events came meanwhile. A read
 * sent since (a reconnect's, a Retry's, replacing it) covers the event, and nothing more is read;
 * so a paged view holds its "Load more" while any read is out (a next page doesn't cover it).
 */
export function invalidateFresh(qc: QueryClient, filters: QueryFilters | QueryFilters[]) {
  const sets = Array.isArray(filters) ? filters : [filters];
  const seen = new Set<Query>();
  // Every query sorted out before any is read: a read one set sends isn't taken for one in flight.
  const idle = sets.map((f) => {
    const mine = new Set<Query>();
    for (const q of qc.getQueryCache().findAll(f)) {
      if (seen.has(q)) continue;
      seen.add(q);
      const read = q.promise;
      if (!read) {
        mine.add(q);
        continue;
      }
      // TanStack's own handler, added first, has given the query the read's outcome: the first
      // event's handler sends the one more read, and the others' find it in flight, as they do one
      // that replaced this read.
      const after = () => {
        if (q.state.fetchStatus === "idle") void qc.invalidateQueries({ predicate: (x) => x === q });
      };
      void read.then(after, after);
    }
    return mine;
  });
  sets.forEach((f, i) => void qc.invalidateQueries({ ...f, predicate: (q) => idle[i].has(q) }));
}

/**
 * After everything may have changed without events saying what: a reconnect (events missed), or
 * a restore, which replaces all data (core.md §2 Export and restore): core's `restore` event tells
 * every open tab, and the tab that restored resyncs on core's answer too, in case its socket is
 * down. Refetches as `invalidateAll` does, replacing reads still in flight, and gives listeners
 * `resync`, so an open manual-feed editor checks its runs and reloads only when another writer
 * changed its file, keeping its draft rules. After a `restore` (`data.restore`: `isRestore`),
 * core holds each manual file with the export's own save time, which can be older than saves the
 * page knew: closed editors' cached files are dropped, and each feed page forgets the saves it
 * knew, its open editor reading the file again (manual-line.ts `restored`).
 */
export function resync(qc: QueryClient, restore = false) {
  invalidateAll(qc);
  if (restore) qc.removeQueries({ queryKey: qk.manualFile("").slice(0, 1), type: "inactive" });
  for (const l of [...listeners]) l({ type: "resync", data: restore ? { restore: true } : null });
}

/** Whether a listener's `resync` is a restore's (`resync(qc, true)`). */
export const isRestore = (ev: UiEvent) => ev.type === "resync" && (ev.data as { restore?: unknown } | null)?.restore === true;

/**
 * Whether a `temp_allow` event (coalesced: the edges whose allows changed since the previous one)
 * concerns a temporary-allows list (qk.tempAllows: `[…, state, edge]`, "all" for every edge): the
 * list of every edge always, one edge's when the event names it or names only some of the edges.
 */
export function tempAllowsChanged(key: readonly unknown[], ev: Partial<TempAllowEvent>): boolean {
  const edge = key[2];
  if (typeof edge !== "string" || edge === "all" || ev.edges_truncated !== false || !Array.isArray(ev.edges)) return true;
  return ev.edges.includes(edge);
}

/**
 * Whether a `dnssec` event (results stored since the previous one, counted by outcome) concerns a
 * DNSSEC results list (qk.dnssecResults: `[…, outcome]`, "all" for every outcome): the list of
 * every outcome always, one outcome's when the event counts results of it; every list when the
 * event's counts can't be read.
 */
export function dnssecResultsChanged(key: readonly unknown[], ev: Partial<DnssecEvent>): boolean {
  const outcome = key[1];
  const counts = ev.outcomes as unknown;
  if (typeof outcome !== "string" || outcome === "all" || !counts || typeof counts !== "object" || Array.isArray(counts)) return true;
  const n = (counts as Record<string, unknown>)[outcome];
  return typeof n === "number" ? n > 0 : n !== undefined;
}

/**
 * A feed's views that only a stored run of it changes (qk.feed parts): its runs, a run, its entries
 * and its export size (counted from its entries: a full scan in core).
 */
const isRunPart = (part: unknown) => typeof part === "string" && (part === "runs" || part === "export-size" || part.startsWith("run:") || part.startsWith("entries:"));

/**
 * Whether a `feed_run` event (coalesced: the runs stored since the previous one) concerns a feed
 * query (`["feeds", …]`): a feed's runs, a run, its entries and its export size (qk.feed: `[…, id,
 * part]`) when the event lists a run of it or lists only some; everything else always: every
 * feed's statuses, and each feed's status, check history and learned schedule, which a provider's
 * check changes without storing a run (a download found unchanged, a failed check: no event of
 * its own) while the same check stores runs of its other feeds.
 */
export function feedRunsChanged(key: readonly unknown[], runs: FeedRunItem[], truncated: boolean): boolean {
  const [, feed, part] = key;
  if (truncated || typeof feed !== "string" || !isRunPart(part)) return true;
  return runs.some((r) => r.feed === feed);
}

/**
 * Whether an `edge_status` event's edge is one keeping a previous LAN CA root in use (the
 * settings' `lanca.previous`, core.md §11: some of its managed listeners haven't reported a
 * certificate from the current root): its session's start or end changes its online state there,
 * so the LAN CA view reads the settings again. Its reports of the roots it serves come as
 * `lanca_served` events (core 07acc1c). Other edges' events don't.
 */
export function usesPreviousRoot(settings: unknown, edge: string): boolean {
  const previous = (settings as { lanca?: { previous?: { edges?: { edge_id?: string }[] }[] } } | undefined)?.lanca?.previous ?? [];
  return previous.some((r) => (r.edges ?? []).some((e) => e.edge_id === edge));
}

/** The `edge_status` events that change an edge's online state (EdgeStatusEvent.event: its session started or ended; not `heartbeat`). */
export const isSessionChange = (event: string | undefined) => event === "hello" || event === "session_ended";

/** A `lanca` event's data as core sends it (LancaEvent), or null when it isn't one. */
export function lancaEventOf(data: unknown): LancaEvent | null {
  const d = data as Partial<LancaEvent> | null;
  if (!d || typeof d !== "object" || (d.event !== "rotated" && d.event !== "previous_dropped")) return null;
  return typeof d.root === "string" && typeof d.previous === "string" && typeof d.current === "string" ? { event: d.event, root: d.root, previous: d.previous, current: d.current } : null;
}

/**
 * The restore generations each query client (a page) has re-read everything for: core's `restore`
 * event and the restoring tab's own answer carry the same `generation` (core 07acc1c), so that
 * tab re-reads once, on whichever comes first. Forgotten when the event socket closes or opens
 * again: core may have restarted, counting from the start again (the reconnect re-reads anyway).
 */
const restoresRead = new WeakMap<QueryClient, number[]>();
const RESTORES_KEPT = 16;

/**
 * The restore whose own `restore` event a page still waits for on its open socket, the restore's
 * answer having come first (settings.tsx): core sends every event noted before a restore ahead of
 * its `restore` event (core 4e4f53d), so until that event comes, the events arriving were sent
 * before the restore, and an open manual-feed editor takes no save from them (feed-detail.tsx).
 * Waited for only on a socket that was open as the restore was sent (`resyncForRestore`);
 * forgotten when that event or a later restore's comes, when the socket closes or opens again
 * (that re-reads everything), or after RESTORE_EVENT_WAIT_MS (`endRestoreWait`).
 */
const restoreAwaited = new WeakMap<QueryClient, { generation: number; timer: ReturnType<typeof setTimeout> }>();

/**
 * How long a page waits for its restore's own event (`restoreAwaited`): far longer than core takes
 * to send the events noted before it (a stalled socket is dropped after 10 s a frame, web/events.rs
 * SEND_DEADLINE). The event comes unless the restore committed before core subscribed the socket.
 */
export const RESTORE_EVENT_WAIT_MS = 60_000;

/** True while the events this page receives were sent before the restore it has re-read for (`restoreAwaited`). */
export const beforeRestoreEvent = (qc: QueryClient) => restoreAwaited.has(qc);

/** Ends the page's wait for its restore's own event, if any (`restoreAwaited`). */
function endRestoreWait(qc: QueryClient) {
  clearTimeout(restoreAwaited.get(qc)?.timer);
  restoreAwaited.delete(qc);
}

/**
 * Waits for the restore of `generation`'s own event (`restoreAwaited`). Should it not come within
 * RESTORE_EVENT_WAIT_MS, the socket was subscribed after the restore committed, and the events the
 * page skipped meanwhile came after it: the wait ends with a re-read (`resync`; an open editor
 * reads its runs), and the generation no longer counts as read, so an event of it that still comes
 * re-reads once more, resetting what the events before it said.
 */
function awaitRestoreEvent(qc: QueryClient, generation: number) {
  endRestoreWait(qc);
  const timer = setTimeout(() => {
    restoreAwaited.delete(qc);
    restoresRead.set(qc, (restoresRead.get(qc) ?? []).filter((g) => g !== generation));
    resync(qc);
  }, RESTORE_EVENT_WAIT_MS);
  restoreAwaited.set(qc, { generation, timer });
}

/** Where the event socket stood as a restore was sent (`restoreSent`), for its answer (`resyncForRestore`). */
export interface RestoreSent {
  connection: number;
}

/** Taken as the tab sends a restore (settings.tsx), before the request goes. */
export const restoreSent = (): RestoreSent => ({ connection: connections });

/**
 * Re-reads everything after the restore of `generation` (`resync`), unless this page already did
 * for it; a generation that isn't a whole number re-reads every time. From core's `restore` event,
 * or, with `answer` (`restoreSent`), from the restore's answer in the tab that restored.
 *
 * The answer waits for the restore's own event (`restoreAwaited`) only on the socket that was
 * open as the restore was sent: core sends the event on each socket it subscribed before the
 * restore committed, and subscribes one just after answering its upgrade (web/events.rs `pump`),
 * so the event comes on that socket (or came, and this page re-read then) unless the restore
 * committed in the moment between; the wait then ends after RESTORE_EVENT_WAIT_MS. Otherwise (the
 * socket opened, closed or reopened meanwhile) the event may have come on an earlier socket or
 * before this one subscribed, and never come now: the answer re-reads without waiting, and doesn't
 * count the generation as read, so an event of it that still comes re-reads once more, resetting
 * what the events before it said.
 */
export function resyncForRestore(qc: QueryClient, generation: unknown, answer?: RestoreSent) {
  if (typeof generation === "number" && Number.isSafeInteger(generation)) {
    // The awaited event, or a later restore's (generations only grow on one socket): it came.
    const awaited = restoreAwaited.get(qc)?.generation;
    if (!answer && awaited !== undefined && awaited <= generation) endRestoreWait(qc);
    const seen = restoresRead.get(qc) ?? [];
    if (seen.includes(generation)) return;
    const sameSocket = connection === "open" && answer?.connection === connections;
    if (!answer || sameSocket) restoresRead.set(qc, [...seen, generation].slice(-RESTORES_KEPT));
    if (sameSocket) awaitRestoreEvent(qc, generation);
  }
  resync(qc, true);
}

function field(data: unknown, key: string): string | undefined {
  const v = data && typeof data === "object" ? (data as Record<string, unknown>)[key] : undefined;
  return typeof v === "string" ? v : undefined;
}

/**
 * The queries events keep fresh, by key prefix: those an event may mark stale (`applyEvent`; a
 * `restore` or `lagged` reads everything), but a provider's backtest, read only when Run asks.
 * Not a manual feed's file nor an alert's evidence either: their pages decide when to read them.
 */
const EVENT_KEPT: readonly (readonly unknown[])[] = [
  ["alerts"],
  ["feeds"],
  ["feed-providers"],
  qk.config("feeds"),
  qk.config("feed-providers"),
  qk.edges,
  qk.settings,
  qk.identity,
  qk.tempAllows,
  qk.querySummary,
  qk.dnssecResults,
  qk.dnssecQueue,
  ["bundles"],
  qk.browserLists,
  qk.warninglists,
];

/**
 * Whether events keep a query fresh (`EVENT_KEPT`). Its read before the socket's first open may
 * have been answered before core subscribed the socket, so an event in between is missed; the
 * first open reads each such query once more (`useEventStream`).
 */
export function keptByEvents(key: readonly unknown[]): boolean {
  if (key[0] === "feed-providers" && key[2] === "backtest") return false;
  return EVENT_KEPT.some((prefix) => prefix.every((part, i) => key[i] === part));
}

/** What each event invalidates, all in one `invalidateFresh` (a query two of its keys match reads once). */
export function applyEvent(qc: QueryClient, ev: UiEvent) {
  const stale: QueryFilters[] = [];
  const inv = (queryKey: readonly unknown[]) => {
    stale.push({ queryKey });
  };
  switch (ev.type) {
    case "alert":
      // Alerts raised, repeated, resolved or deleted, or whose evidence changed (a backfill or a
      // live capture: core 4e4f53d) (AlertEvent, coalesced: at most one a second, however many
      // changed): the alert views read again once. An alert's evidence (qk.alertEvidence) is
      // outside this prefix: its page reads it again only when the event lists that alert or is
      // truncated (pages/alerts.tsx). The DNSSEC queue's changes, a cross-check that ends among
      // them, come as `dnssec_queued`.
      inv(["alerts"]);
      inv(qk.review);
      inv(qk.providerStatus);
      inv(qk.feedStatus);
      // A provider check that finds new files adds feeds and raises feed_added (feeds.md §1):
      // the feed and provider lists show them.
      inv(qk.config("feeds"));
      inv(qk.config("feed-providers"));
      break;
    case "edge_status": {
      inv(qk.edges);
      const edge = field(ev.data, "edge");
      if (edge) {
        inv(qk.edgeStatus(edge));
        // An edge keeping a previous LAN CA root in use came online or went offline: the LAN CA
        // view shows its state (its listeners' reports come as `lanca_served`; heartbeats don't
        // change the view).
        if (isSessionChange(field(ev.data, "event")) && usesPreviousRoot(qc.getQueryData(qk.settings), edge)) inv(qk.settings);
      }
      break;
    }
    case "temp_allow": {
      // Allows changed on these edges (ingested from their logs, a revoke requested or
      // acknowledged, a reported expiry passed): the lists that show them read again, and the
      // device and profile views, which list their allows (core's TempAllowEvent says so).
      const d = (ev.data ?? {}) as Partial<TempAllowEvent>;
      stale.push({ queryKey: qk.tempAllows, predicate: (q) => tempAllowsChanged(q.queryKey, d) });
      inv(qk.querySummary);
      break;
    }
    case "dnssec": {
      // DNSSEC results were stored (they leave the validation queue): the results lists of their
      // outcomes read their newest rows, throttled (stored results never change, so the older
      // pages loaded stay as they are; core sends up to one event a second, and re-reading every
      // loaded page for each would keep a long list reading).
      const d = (ev.data ?? {}) as Partial<DnssecEvent>;
      refreshPagedLists(qc, { queryKey: qk.dnssecResults, predicate: (q) => dnssecResultsChanged(q.queryKey, d) });
      inv(qk.dnssecQueue);
      break;
    }
    case "dnssec_queued":
      // The validation or cross-check queue changed (DnssecQueuedEvent, coalesced: checks queued,
      // joined, retried, waiting, cross-checks retried or ended, items dropped or stamped; every
      // change to `GET dnssec/queue` but a stored result, which sends `dnssec`): it reads again.
      inv(qk.dnssecQueue);
      break;
    case "lanca":
      // The LAN CA's roots changed (LancaEvent: `rotated` by a zones change from any tab, or
      // `previous_dropped` once every listener reports the current root): the LAN CA view (in the
      // settings) and the identity's root fingerprint and zones read again. An open LAN CA tab
      // takes the roots the event names (`previous`: the one replaced or dropped) for its words.
      inv(qk.settings);
      inv(qk.identity);
      break;
    case "lanca_served":
      // An edge's report of the roots its managed listeners serve changed while a previous root
      // is kept (LancaServedEvent, coalesced): the LAN CA view's edges still on it read again.
      inv(qk.settings);
      break;
    case "restore":
      // A restore committed (from this tab, another, or the CLI): everything is read again, once
      // per restore in the tab that restored (its answer carries the same generation). Core sent
      // every event noted before the restore ahead of this one (core 4e4f53d).
      resyncForRestore(qc, (ev.data as Partial<RestoreEvent> | null)?.generation);
      break;
    case "job": {
      // A heavy job's start or end with the lanes' state as `GET jobs` gives it (JobEvent): the
      // jobs view takes it as it is (no request); a bundle build's start and end refresh the
      // bundle's status (`building`, its result; a failed build sends no bundle_version).
      const j = ev.data as JobEvent | null;
      if (!j || typeof j !== "object" || typeof j.kind !== "string") break;
      qc.setQueryData<JobsView>(qk.jobs, jobsOf(j));
      if (j.kind === JOB_KIND.build) {
        inv(qk.bundleStatus);
        inv(qk.bundle(j.target, "status"));
      }
      // Core dropped job reports before this one (its waiting reports were bounded, README §2):
      // some jobs' starts or ends never came, so what the reports would have refreshed is read
      // again (JobEvent.dropped: "refetch GET jobs and the runs"; the lanes came with this event),
      // and views holding a report check it against those reads (api/order.ts).
      if (typeof j.dropped === "number" && j.dropped > 0) stale.push({ predicate: (q) => missedByJobs(q.queryKey) });
      break;
    }
    case "feed_run": {
      // Runs stored since the previous event (FeedRunEvent, coalesced: at most one a second). Each
      // run of a save later than a closed editor's cached file (another writer, an import) makes
      // the cache stale, so the next open, or an import's base_version, reads again. A run of the
      // cached save or an earlier one (the page's own save, a re-ingest) changes nothing in it; one
      // without a save time is taken as stale. When the event lists only some runs, every closed
      // editor's file is stale. An open editor checks the runs itself.
      const { runs, truncated } = feedRunsOf(ev.data);
      if (truncated) markClosedFilesStale(qc);
      for (const r of runs) {
        const cached = qc.getQueryData<{ saved_at?: string } | null>(qk.manualFile(r.feed));
        if (!(r.saved_at && cached && timeOrder(r.saved_at, cached.saved_at) <= 0)) markClosedFilesStale(qc, r.feed);
      }
      // Each listed run's feed's runs and entries; every feed's status, checks and schedule (a
      // check changes them without a run); every feed's views when the event lists only some.
      stale.push({ queryKey: ["feeds"], predicate: (q) => feedRunsChanged(q.queryKey, runs, truncated) });
      // Not a backtest: it replays history only when Run asks (core computes each in full, and a
      // provider's multi-feed ingest sends run events for as long as it lasts), so Run stays
      // usable meanwhile.
      stale.push({ queryKey: ["feed-providers"], predicate: (q) => q.queryKey[2] !== "backtest" });
      inv(qk.review);
      inv(qk.config("feeds"));
      inv(qk.config("feed-providers"));
      break;
    }
    case "bundle_version":
      inv(["bundles"]);
      inv(qk.browserLists);
      inv(qk.warninglists);
      break;
    case "lagged":
      // Core dropped events for us: refetch everything; the socket reconnects.
      invalidateAll(qc);
      break;
    default:
      break;
  }
  invalidateFresh(qc, stale);
}

/** The statuses and runs a missed `job` report may have changed: bundles' (a build), feeds' and providers' (a run). */
function missedByJobs(key: readonly unknown[]): boolean {
  if (key[0] !== "bundles" && key[0] !== "feeds" && key[0] !== "feed-providers") return false;
  // ["bundles", "status"] and its kin (every one's), or ["bundles", id, "status"] (one's).
  return key[1] === "status" || key[2] === "status" || key[2] === "runs";
}

/** The lanes' state a `job` event carries (the fields of `GET jobs`). */
export function jobsOf(j: JobEvent): JobsView {
  const { light_depth, light_dropped, heavy_depth, heavy_dropped, heavy_completed, heavy_failed, heavy_running } = j;
  return { light_depth, light_dropped, heavy_depth, heavy_dropped, heavy_completed, heavy_failed, heavy_running: heavy_running ?? null };
}

type Listener = (ev: UiEvent) => void;
const listeners = new Set<Listener>();

// The event socket's state, for views that follow events and poll only while it isn't open, and
// how many times it changed (a socket opening, closing or reconnecting changes it: `restoreSent`).
let connection: ConnectionState = "closed";
let connections = 0;
const connectionListeners = new Set<() => void>();

function setConnection(c: ConnectionState) {
  if (connection === c) return;
  connection = c;
  connections++;
  for (const l of [...connectionListeners]) l();
}

/** The event socket's state now (`closed` when no stream runs). */
export function useConnection(): ConnectionState {
  return React.useSyncExternalStore(
    (cb) => {
      connectionListeners.add(cb);
      return () => {
        connectionListeners.delete(cb);
      };
    },
    () => connection,
  );
}

const JOB_REPORTS = 50;

/** A `job` event a view holds, with when it arrived in the page's order of reports and reads (api/order.ts). */
export interface JobReport extends JobEvent {
  seen: number;
}

/**
 * True when a held report of a running job is over: a status read sent after it arrived says the
 * job no longer runs (`running` false). A report can be missed (a reconnect, `lagged`, a `job`
 * event's `dropped`: api.md §7), and those re-read the statuses, so a lost end can't leave a view
 * running; an end report is final.
 */
export function reportOver(r: JobReport, readAt: number, running: boolean | undefined): boolean {
  return r.phase === "start" && running === false && readAt > r.seen;
}

/**
 * The heavy jobs a view follows, from `job` events since `since` (e.g. the time of Build now; null:
 * none): the newest report of each job (`start`, or `end` with its outcome and duration), the job
 * reported last at the end, at most JOB_REPORTS of them. A new `since` forgets the earlier ones.
 */
export function useJobReports(since: number | null, match: (j: JobEvent) => boolean): JobReport[] {
  const [reports, setReports] = React.useState<Map<string, JobReport>>(() => new Map());
  const [seen, setSeen] = React.useState(since);
  if (since !== seen) {
    setSeen(since);
    setReports(new Map());
  }
  useUiEvent((ev) => {
    if (since === null || ev.type !== "job") return;
    const j = ev.data as JobEvent | null;
    if (!j || typeof j.job !== "string" || !match(j)) return;
    const report: JobReport = { ...j, seen: nextOrder() };
    setReports((m) => {
      // Newest report last; at most JOB_REPORTS jobs kept.
      const next = new Map(m);
      next.delete(j.job);
      next.set(j.job, report);
      for (const k of next.keys()) {
        if (next.size <= JOB_REPORTS) break;
        next.delete(k);
      }
      return next;
    });
  });
  return [...reports.values()];
}

/** Subscribe to raw events (e.g. a manual feed's save result arriving as `feed_run`). */
export function useUiEvent(fn: Listener) {
  const ref = React.useRef(fn);
  React.useEffect(() => {
    ref.current = fn;
  });
  React.useEffect(() => {
    const l: Listener = (ev) => ref.current(ev);
    listeners.add(l);
    return () => {
      listeners.delete(l);
    };
  }, []);
}

const MIN_BACKOFF = 1000;
const MAX_BACKOFF = 30_000;

/**
 * Keeps one event socket open while mounted, reconnecting with capped exponential backoff.
 * After a reconnect everything is refetched, since events may have been missed; on the first
 * open, once each, what events keep fresh (`keptByEvents`) and what queries.ts `READ_ON_OPEN` marks.
 */
export function useEventStream(enabled = true): ConnectionState {
  const qc = useQueryClient();
  const [state, setStateOnly] = React.useState<ConnectionState>("connecting");
  const setState = React.useCallback((c: ConnectionState) => {
    setStateOnly(c);
    setConnection(c);
  }, []);

  React.useEffect(() => {
    if (!enabled || typeof WebSocket === "undefined") return;
    let ws: WebSocket | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let backoff = MIN_BACKOFF;
    let stopped = false;
    let wasOpen = false;

    const connect = () => {
      setState("connecting");
      try {
        ws = new WebSocket(eventsUrl());
      } catch {
        schedule();
        return;
      }
      ws.onopen = () => {
        setState("open");
        backoff = MIN_BACKOFF;
        restoresRead.delete(qc);
        endRestoreWait(qc);
        if (wasOpen) resync(qc);
        else invalidateFresh(qc, { predicate: (q) => keptByEvents(q.queryKey) || q.meta?.readOnOpen === true });
        wasOpen = true;
      };
      ws.onmessage = (m) => {
        const ev = parseEvent(m.data);
        if (!ev) return;
        applyEvent(qc, ev);
        for (const l of listeners) l(ev);
      };
      ws.onclose = () => {
        setState("closed");
        restoresRead.delete(qc);
        endRestoreWait(qc);
        schedule();
      };
      ws.onerror = () => {
        ws?.close();
      };
    };
    const schedule = () => {
      if (stopped) return;
      clearTimeout(timer);
      timer = setTimeout(connect, backoff);
      backoff = Math.min(backoff * 2, MAX_BACKOFF);
    };
    connect();
    return () => {
      stopped = true;
      clearTimeout(timer);
      endRestoreWait(qc);
      setConnection("closed");
      if (ws) {
        ws.onclose = null;
        ws.close();
      }
    };
  }, [enabled, qc, setState]);

  return state;
}
