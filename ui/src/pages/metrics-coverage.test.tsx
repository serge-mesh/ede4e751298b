import { describe, expect, it, vi } from "vitest";
import { cleanup, screen, waitFor } from "@testing-library/react";
import doc from "@/api/openapi.json";
import { mockApi, type Call, type Route } from "@/test/mock-api";
import { renderApp } from "@/test/render";
import { W5 } from "@/test/core-w5";
import fixtures from "@/test/fixtures/core.json";
import type { ChartLine } from "@/api/types";
import { upstreamRows } from "./dashboard";

// Every series core records or receives is charted or listed on some page (core.md §10, §12).
// The list is the OpenAPI document's MetricSeries catalog, which core generates from its series
// registry (metrics/mod.rs HEARTBEAT_SERIES, CORE_SERIES); a core unit test keeps
// src/api/openapi.json's copy in step. Each page that charts metrics is rendered against a mock
// core that answers every series it asks for with data, and the series it DRAWS are collected from
// the `data-rendered` attributes of its charts (the lines its specs drew, with the series a derived
// line was computed from) and of its tables and figures (the values they show): a series asked
// for but drawn nowhere fails here, unless it is an exception below, with the reason.

const T = { timeout: 8000 };

interface Catalog {
  enum: string[];
  "x-picket-series": Record<string, { kind: string; labels: string[]; family: string }>;
}
const CATALOG = (doc as unknown as { components: { schemas: { MetricSeries: Catalog } } }).components.schemas.MetricSeries;

/** Series no page renders, each with the reason. None: every series core records has a place. */
const EXCEPTIONS: Record<string, string> = {};

const MAP_FAMILIES = new Set(["upstream", "lookups", "cold"]);
const BY_REASON = new Set(["invalid", "scrubbed"]);

/**
 * The catalog series a requested chart series names, in api.md §7's forms (metrics/query.rs
 * `parse_series`): a base name, a map key inside a heartbeat path (`upstream.<id>.queries`,
 * `logs.dropped.<reason>`, `upstream.<id>.invalid.<reason>`), and `.p50`/`.p99` on a histogram.
 */
export function baseSeries(requested: string): string | null {
  const known = new Set(CATALOG.enum);
  const name = requested.replace(/\.(p50|p99)$/, "");
  if (known.has(name)) return name;
  const p = name.split(".");
  if (p.length === 3 && p[0] === "logs" && p[1] === "dropped") return "logs.dropped";
  if (p.length === 3 && MAP_FAMILIES.has(p[0])) {
    if (known.has(`${p[0]}.${p[2]}`)) return `${p[0]}.${p[2]}`;
    if (p[0] === "upstream" && BY_REASON.has(p[1])) return `upstream.${p[1]}`;
  }
  if (p.length === 4 && p[0] === "upstream" && BY_REASON.has(p[2])) return `upstream.${p[2]}`;
  return null;
}

type Rec = Record<string, unknown>;

/** Label values the mock core answers with: the entities the pages show, every queue. */
const VALUES: Record<string, string[]> = {
  queue: ["light", "heavy", "lookup", "dnssec", "crosscheck", "attribution"],
  reason: ["out_of_bailiwick", "padding"],
  provider: ["q9"],
  feed: ["manual-block"],
  bundle: ["block-common"],
  profile: ["default"],
  upstream: ["cf"],
};
const T0 = 1_800_000_000;

/** The mock core's chart of a request: each series with data, one line per label set. */
function chartOf(series: string, edge: string): { step_s: number; series: ChartLine[] } {
  const lines: ChartLine[] = [];
  for (const name of series.split(",").filter(Boolean)) {
    const base = baseSeries(name);
    if (base === null) continue;
    let sets: Record<string, string>[] = [{}];
    for (const k of CATALOG["x-picket-series"][base].labels.filter((k) => k !== "edge")) {
      sets = sets.flatMap((l) => (VALUES[k] ?? [`v-${k}`]).map((v) => ({ ...l, [k]: v })));
    }
    // spool.oldest_ts is a time: before each step, so the spool's age is positive.
    const v = base === "spool.oldest_ts" ? T0 - 100 : 5;
    const lineEdge = edge === "all" ? null : edge === "each" ? "e-cacc845b" : edge;
    for (const labels of sets) {
      lines.push({ name, labels, edge: lineEdge, points: [[T0, v], [T0 + 300, v]] });
    }
  }
  return { step_s: 300, series: lines };
}

const metricsRoute: Route = {
  method: "GET",
  path: "/metrics",
  body: (c: Call) => chartOf(c.query.get("series") ?? "", c.query.get("edge") ?? "all"),
};
const settings = (fixtures as Rec)["/settings"] as { settings: Rec & { crosscheck?: Rec } };
/** The pages that chart metrics, each with a panel title to wait for and the routes it needs. */
const PAGES: { path: string; wait: string; routes?: Route[] }[] = [
  { path: "/", wait: "Upstream health" },
  { path: "/edges/e-cacc845b?tab=system", wait: "Rejected and refused queries" },
  {
    path: "/system",
    wait: "Cross-check queue",
    // The cross-check panels show while it is on (core.md §12 System → DNSSEC).
    routes: [{ method: "GET", path: "/settings", body: { ...settings, settings: { ...settings.settings, crosscheck: { ...settings.settings.crosscheck, enabled: true } } } }],
  },
  { path: "/feeds/manual-block?tab=metrics", wait: "Records added and deleted" },
  { path: "/bundles/block-common?tab=cold", wait: "Missed blocks core found" },
  {
    path: "/lookup-providers/q9?tab=charts",
    wait: "Verdict-set publishes",
    routes: [
      { method: "GET", path: "/lookup-providers", body: { items: [W5["/lookup-providers/q9"]], next_cursor: null } },
      { method: "GET", path: "/lookup-providers/q9", body: W5["/lookup-providers/q9"] },
      { method: "GET", path: "/lookup-providers/q9/status", body: W5["/lookup-providers/q9/status (after)"] },
    ],
  },
  { path: "/dnssec", wait: "Validation queue" },
  { path: "/profiles/default/trial/block-common", wait: "Would-blocks over time" },
];

describe("every series core records is rendered (MetricSeries)", () => {
  it("reads each series' base name back from the forms api.md §7 writes", () => {
    expect(baseSeries("lookups.q9.call_ms.p99")).toBe("lookups.call_ms");
    expect(baseSeries("upstream.cf.queries")).toBe("upstream.queries");
    expect(baseSeries("upstream.cf.invalid.bad_id")).toBe("upstream.invalid");
    expect(baseSeries("upstream.scrubbed.ttl")).toBe("upstream.scrubbed");
    expect(baseSeries("upstream.invalid.queries")).toBe("upstream.queries");
    expect(baseSeries("logs.dropped.too_old")).toBe("logs.dropped");
    expect(baseSeries("cold.block-common.blocks")).toBe("cold.blocks");
    expect(baseSeries("job_ms.p50")).toBe("job_ms");
    expect(baseSeries("queries_total")).toBeNull();
    // The catalog gives each series' kind and labels; a histogram is charted by percentile.
    expect(CATALOG["x-picket-series"]["lookup_call_ms"]).toEqual({ kind: "corehistogram", labels: ["provider"], family: "picket_lookup_call_ms" });
    expect(CATALOG.enum.length).toBeGreaterThan(100);
  });

  it(
    "draws each one on a page",
    async () => {
      const shownOn = new Map<string, Set<string>>();
      const unknown: string[] = [];
      // jsdom lays nothing out: Recharts warns of each chart's zero size (the lines are still drawn).
      const warn = console.warn;
      const quiet = vi.spyOn(console, "warn").mockImplementation((...a: unknown[]) => {
        if (!String(a[0]).startsWith("The width(0) and height(0) of chart")) warn(...a);
      });
      for (const page of PAGES) {
        const { calls } = mockApi([metricsRoute, ...(page.routes ?? [])]);
        const { queryClient } = renderApp(page.path);
        expect((await screen.findAllByText(page.wait, undefined, T)).length).toBeGreaterThan(0);
        await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
        for (const c of calls.filter((c) => c.method === "GET" && c.path === "/metrics")) {
          for (const s of (c.query.get("series") ?? "").split(",").filter(Boolean)) {
            if (baseSeries(s) === null) unknown.push(`${s} (${page.path})`);
          }
        }
        for (const el of document.querySelectorAll("[data-rendered]")) {
          for (const s of (el.getAttribute("data-rendered") ?? "").split(" ").filter(Boolean)) {
            const base = baseSeries(s);
            if (base === null) unknown.push(`${s} drawn (${page.path})`);
            else shownOn.set(base, (shownOn.get(base) ?? new Set()).add(page.path));
          }
        }
        cleanup();
      }
      quiet.mockRestore();
      // Every series asked for or drawn is one core serves (a typo would chart nothing).
      expect(unknown).toEqual([]);
      const missing = CATALOG.enum.filter((s) => !shownOn.has(s) && !(s in EXCEPTIONS));
      expect(missing, "series core records that no page draws: chart them or list them in EXCEPTIONS with why").toEqual([]);
      // An exception is a catalog series no page renders.
      for (const s of Object.keys(EXCEPTIONS)) {
        expect(CATALOG.enum, s).toContain(s);
        expect(shownOn.has(s), `${s} is rendered: drop its exception`).toBe(false);
      }
    },
    120_000,
  );
});

describe("upstream health (dashboard)", () => {
  it("lists invalid answers and scrubbed records by reason per upstream, padding apart", () => {
    const line = (name: string, upstream: string, n: number, reason?: string): ChartLine => ({
      name,
      labels: reason ? { upstream, reason } : { upstream },
      edge: null,
      points: [[1_800_000_000, n], [1_800_000_300, null]],
    });
    const rows = upstreamRows([
      line("upstream.queries", "cf", 10),
      line("upstream.invalid", "cf", 2, "bad_id"),
      line("upstream.scrubbed", "cf", 3, "out_of_bailiwick"),
      line("upstream.scrubbed", "cf", 1, "unexpected_type"),
      // Padding, removed from every padded DoT or DoH answer, never crowds out the anomalies.
      line("upstream.scrubbed", "cf", 900, "padding"),
      line("upstream.scrubbed", "q9", 0, "out_of_bailiwick"),
    ]);
    expect(rows.map((r) => [r.id, r.invalid, r.scrubbed, r.padding])).toEqual([
      ["cf", { bad_id: 2 }, { out_of_bailiwick: 3, unexpected_type: 1 }, 900],
      ["q9", {}, {}, null],
    ]);
  });
});
