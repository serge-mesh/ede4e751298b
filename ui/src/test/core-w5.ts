// Core's wave-5 answers (logs, attribution, trials, evidence, lookups, DNSSEC, extension builds,
// config export), captured from a real picket-core built from c58ba80 with data: manual feeds in
// a block bundle and a trial bundle, a profile that alerts on security feeds, a client, a lookup
// provider and records posted through the edge API by a registered edge (ui/scripts/capture-w5.mjs).
// Since 720be97 also: the UI events core sent meanwhile (`events`), a revoke the edge acknowledged
// (the `… (revoked)` captures), devices with their MACs, evidence pages (`/alerts/{paged}/…`), the
// per-edge trial metric and a LAN CA rotation with core's refusals (`PUT /settings lanca.zones (…)`,
// `/settings (rotating)`, `(rotating, edge offline)`, `(rotated)`).
// Recaptured from core c58ba80: rotations with `lanca.rotate_from` and its refusals (`(no
// rotate_from)`, `(stale rotate_from)`, `(replaced root)`), the edge's `cert_roots`, a second core
// whose clock isn't synchronised (`/settings (clock not synchronised)` and its 503), the `lanca`
// events, a sync lookup provider's block (`/alerts/{lookup block}`), a second edge (`second edge`)
// whose copy makes `/alerts/{paged}` one of several edges and comes first on its evidence pages
// (newest stored first), and core 720be97's evidence cursor refused (`(old cursor)`).
// Recaptured from core 07acc1c: `lanca_root_changed` for a replaced root, `(null rotate_from)`,
// the `lanca` events naming the `previous` root, `lanca_served` and `dnssec_queued` events, the
// restore's `generation`, devices keyed by a former client's name (`laptop`) and by an entry
// without MACs (`phone`), the lookup block's record (`/logs/{seq 18}`, a decimal score), every
// kind of `limit` and the backtest's `days` and `k` out of range (`limits`), and a self-test that
// passed (this capture's core reached quad9).
// Recaptured from core a3eb6d5: the coalesced `alert` and `feed_run` events (each lists what
// changed since the previous one), among them a burst of 100 alerts raised and bulk-deleted
// (`DELETE /alerts (burst)`), whose events list 64 and say the rest went unlisted
// (`alerts_truncated`: `capturedTruncated`); `dnssec_queued` with every kind of queue change; and
// a lookup's `detail` as a JSON object in a record (`/logs/{seq 9}`, `/logs/{seq 18}`).
// The mock core answers these GETs from here when a test gives no route of its own.
import w5 from "./fixtures/w5.json";
import type { SettingsView, UiEventFrame } from "@/api/types";

export const W5 = w5 as unknown as Record<string, unknown> & {
  "record ids": Record<string, string>;
  "GET /config/export": Record<string, unknown>;
  /** A few frames of each type core sent on the UI WebSocket while the capture ran. */
  events: Record<string, UiEventFrame[]>;
};

/** A captured settings view (`/settings (fresh)`, `(rotating)`, `(rotating, edge offline)`, `(rotated)`). */
export function capturedSettings(key: string): SettingsView {
  const v = W5[key] as SettingsView | undefined;
  if (!v) throw new Error(`no capture ${key}`);
  return v;
}

/** The first captured UI event frame of a type. */
export function capturedEvent<T extends UiEventFrame["type"]>(type: T): Extract<UiEventFrame, { type: T }> {
  const f = W5.events[type]?.[0];
  if (!f) throw new Error(`no captured ${type} event`);
  return f as Extract<UiEventFrame, { type: T }>;
}

/** The captured `alert` event that listed only some of the burst's alerts: raised, or deleted. */
export function capturedTruncated(of: "raised" | "deleted"): Extract<UiEventFrame, { type: "alert" }> {
  const f = (W5.events.alert as Extract<UiEventFrame, { type: "alert" }>[]).find((e) => e.data.alerts_truncated && e.data.alerts.some((a) => a.deleted) === (of === "deleted"));
  if (!f) throw new Error(`no captured truncated alert event (${of})`);
  return f;
}

/** The captured record id of the `q` record with this edge `seq`. */
export function recordId(seq: number): string {
  return W5["record ids"][String(seq)];
}

/** The captured detail of the record with this edge `seq`. */
export function recordDetail(seq: number): Record<string, unknown> {
  return W5[`/logs/{seq ${seq}}`] as Record<string, unknown>;
}

/** The captured body of a write (`POST …`, `PUT …`): status and body. */
export function captured(key: string): { status: number; body: unknown } {
  return W5[key] as { status: number; body: unknown };
}

/** Core's evidence of an alert that keeps none (captured for a bundle_warning). */
export const NO_EVIDENCE = W5["/alerts/{bundle_warning}/evidence"];

/** What the captured core answers a GET (path after /api/ui/v1), or undefined when it has no capture for it. */
export function w5Get(path: string, query: URLSearchParams): unknown {
  const seqOf = Object.entries(W5["record ids"]).find(([, id]) => `/logs/${encodeURIComponent(id)}` === path || `/logs/${id}` === path)?.[0];
  if (seqOf && W5[`/logs/{seq ${seqOf}}`]) return W5[`/logs/{seq ${seqOf}}`];
  switch (path) {
    case "/logs":
      return query.get("limit") === "3" ? W5["/logs?limit=3"] : W5["/logs"];
    case "/top":
      return W5[`/top?kind=${query.get("kind")}`];
    case "/devices":
    case "/trial-results":
    case "/dnssec/queue":
    case "/extension":
    case "/lookup-modules":
      return W5[path];
    case "/dnssec/results":
      return query.get("outcome") === "bogus" ? W5["/dnssec/results?outcome=bogus"] : W5["/dnssec/results"];
    case "/query-summary":
      return query.get("profile") ? W5["/query-summary?profile=p1"] : W5["/query-summary?device=tablet"];
    case "/temp-allows":
      return W5[`/temp-allows?state=${query.get("state") ?? "all"}`];
  }
  if (/^\/alerts\/\d+\/evidence$/.test(path)) return NO_EVIDENCE;
  if (/^\/lookup-providers\/[^/]+\/status$/.test(path)) return W5["/lookup-providers/q9/status"];
  return undefined;
}
