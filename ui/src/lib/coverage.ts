// DNSSEC coverage over a window (core.md §12 System → DNSSEC → Coverage): of the answers clients
// got (by_decision.allow + by_decision.servfail from the heartbeat totals), the share in each
// coverage class, plus "still queued" and "not logged", adding up to 100 %.

export const CHECKED_CLASSES = ["secure", "insecure", "bogus", "indeterminate", "fallback", "dropped"] as const;
export const UNCHECKED_CLASSES = ["forward_zone", "plain_upstream", "edge", "off"] as const;

export interface CoverageInput {
  /** by_decision.allow + by_decision.servfail summed over the window. */
  answersGot: number;
  /** dnssec_answers: the stored q records with decision allow or servfail. */
  logged: number;
  /** dnssec_coverage counts by class, and the fallback's outcomes. */
  classes: Record<string, number>;
  fallbackOutcomes: Record<string, number>;
}

export interface CoverageRow {
  key: string;
  label: string;
  count: number;
  share: number;
  group: "checked" | "not_checked";
}

const LABELS: Record<string, string> = {
  secure: "Secure",
  insecure: "Insecure",
  bogus_indeterminate: "Bogus or Indeterminate",
  fallback: "Fallback (checked by core's own query, not the answer the client got)",
  forward_zone: "Not checked: forward zone",
  plain_upstream: "Not checked: plain upstream",
  edge: "Not checked: the edge's own answer",
  off: "Not checked: validation off",
  dropped: "Not checked: dropped by the queue",
  queued: "Not checked: still queued",
  not_logged: "Not checked: not logged",
};

export function computeCoverage(input: CoverageInput): { rows: CoverageRow[]; total: number } {
  const c = (k: string) => Math.max(0, input.classes[k] ?? 0);
  const classified = Object.values(input.classes).reduce((a, v) => a + Math.max(0, v), 0);
  // Logged answers can't be fewer than those classified (lost heartbeats, rounding).
  const logged = Math.max(input.logged, classified);
  const queued = logged - classified;
  // When lost heartbeat counts make "not logged" negative, the logged answers are the whole.
  const notLogged = Math.max(0, input.answersGot - logged);
  const total = logged + notLogged;
  const entries: [string, number, CoverageRow["group"]][] = [
    ["secure", c("secure"), "checked"],
    ["insecure", c("insecure"), "checked"],
    ["bogus_indeterminate", c("bogus") + c("indeterminate"), "checked"],
    ["fallback", c("fallback"), "checked"],
    ["forward_zone", c("forward_zone"), "not_checked"],
    ["plain_upstream", c("plain_upstream"), "not_checked"],
    ["edge", c("edge"), "not_checked"],
    ["off", c("off"), "not_checked"],
    ["dropped", c("dropped"), "not_checked"],
    ["queued", queued, "not_checked"],
    ["not_logged", notLogged, "not_checked"],
  ];
  return {
    total,
    rows: entries.map(([key, count, group]) => ({ key, label: LABELS[key] ?? key, count, share: total > 0 ? count / total : 0, group })),
  };
}
