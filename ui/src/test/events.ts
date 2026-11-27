// Core's UI event frames as tests emit them, in core's shapes (the fake socket checks them:
// test/contract.ts `eventViolations`): the coalesced `alert` and `feed_run` events (core a3eb6d5,
// api.md §7: what changed since the previous event of the type, in bounded lists, at most one a
// second; a list that says it is truncated lists core's bound, 64) and `job` (JobEvent).
import type { AlertEventItem, FeedRunItem, JobEvent } from "@/api/types";

/** Core's bound on an event's list (web/events.rs MAX_EVENT_ALERTS, MAX_EVENT_RUNS): a truncated list lists exactly this many. */
export const MAX_LISTED = 64;

/** An alert as a test names it: an alert view (its fields beyond these are left out), or an id with what matters. */
export interface AlertLike {
  id: number;
  kind?: string;
  state?: string | null;
  count?: number;
  deleted?: boolean;
}

/** One alert as an `alert` event lists it (AlertEventItem); by default `edge_offline`, open, raised once. */
export function alertItem(a: AlertLike): AlertEventItem {
  const deleted = a.deleted ?? false;
  return { id: a.id, kind: a.kind ?? "edge_offline", state: deleted ? null : ((a.state ?? "open") as AlertEventItem["state"]), count: a.count ?? 1, deleted };
}

/** A deleted alert as an `alert` event lists it (no state). */
export const deletedAlert = (id: number, kind = "edge_offline", count = 1): AlertEventItem => alertItem({ id, kind, count, deleted: true });

function listed<T>(items: T[], truncated: boolean, what: string): T[] {
  if (items.length > MAX_LISTED || (truncated && items.length !== MAX_LISTED)) throw new Error(`core lists at most ${MAX_LISTED} ${what}, and exactly ${MAX_LISTED} when it says the list is truncated (got ${items.length})`);
  return items;
}

/** An `alert` frame listing these alerts, each changed once; `truncated`: more changed than it lists (then it lists 64: `truncatedAlertFrame`). */
export function alertFrame(alerts: AlertLike[], truncated = false) {
  return { type: "alert" as const, data: { alerts: listed(alerts, truncated, "alerts").map(alertItem), alerts_truncated: truncated, changes: alerts.length + (truncated ? 1 : 0) } };
}

/** `n` alerts other than those a test follows (ids from 900000), as a truncated event lists them first. */
export const otherAlerts = (n: number): AlertLike[] => Array.from({ length: n }, (_, i) => ({ id: 900_000 + i, kind: "category_blocked" }));

/** An `alert` frame that lists only some of the alerts changed: other alerts, then these, 64 in all. */
export const truncatedAlertFrame = (alerts: AlertLike[] = []) => alertFrame([...otherAlerts(MAX_LISTED - alerts.length), ...alerts], true);

/** A run as a test names it: its feed and row id, with what matters. */
export type RunLike = Partial<FeedRunItem> & { feed: string; run: number };

/** One stored run as a `feed_run` event lists it (FeedRunItem); by default an applied download that names no save. */
export const runItem = (r: RunLike): FeedRunItem => ({ kind: "download", status: "applied", gate: null, version: null, saved_at: null, source_run: null, ...r });

/** A `feed_run` frame listing these runs, in the order stored; `truncated`: more were stored than it lists (then it lists 64: `truncatedRunFrame`). */
export function feedRunFrame(runs: RunLike[], truncated = false) {
  return { type: "feed_run" as const, data: { runs: listed(runs, truncated, "runs").map(runItem), runs_truncated: truncated, stored: runs.length + (truncated ? 1 : 0) } };
}

/** `n` runs of feeds other than those a test follows (`other-0`, …), as a truncated event lists them first. */
export const otherRuns = (n: number): RunLike[] => Array.from({ length: n }, (_, i) => ({ feed: `other-${i}`, run: 900_000 + i }));

/** A `feed_run` frame that lists only some of the runs stored: other feeds' runs, then these, 64 in all. */
export const truncatedRunFrame = (runs: RunLike[] = []) => feedRunFrame([...otherRuns(MAX_LISTED - runs.length), ...runs], true);

let lastRun = 0;
const started = new Map<string, number>();

/**
 * A `job` event as core sends it (JobEvent, web/events.rs): a heavy job's start or end, then the
 * lanes' state. A start takes the next run id and its end the same one; an end whose start wasn't
 * reported stands for it (`coalesced` 1). `extra` sets any field (e.g. `dropped`, `outcome`, `ms`).
 */
export function jobFrame(kind: string, target: string, phase: "start" | "end", extra: Partial<JobEvent> = {}) {
  const job = `${kind}:${target}`;
  const begun = started.get(job);
  const run = phase === "start" || begun === undefined ? ++lastRun : begun;
  if (phase === "start") started.set(job, run);
  else started.delete(job);
  const data: JobEvent = {
    phase,
    run,
    job,
    kind,
    target,
    outcome: phase === "end" ? "ok" : null,
    ms: phase === "end" ? 1200 : null,
    coalesced: phase === "end" && begun === undefined ? 1 : 0,
    dropped: 0,
    light_depth: 0,
    light_dropped: 0,
    heavy_depth: 0,
    heavy_dropped: 0,
    heavy_completed: 30,
    heavy_failed: 0,
    heavy_running: phase === "start" ? job : null,
    ...extra,
  };
  return { type: "job" as const, data };
}
