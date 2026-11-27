import type { Chart, ChartLine } from "@/api/types";

/** A stable key for a chart line: its name, labels and edge. */
export function lineKey(l: ChartLine): string {
  const labels = Object.entries(l.labels ?? {})
    .filter(([k]) => k !== "edge")
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join(",");
  return `${l.name}${labels ? `{${labels}}` : ""}${l.edge ? `@${l.edge}` : ""}`;
}

export interface Row {
  t: number;
  [key: string]: number | null;
}

/** Points of every line merged into rows by step start (Unix seconds). */
export function toRows(lines: ChartLine[], keyOf: (l: ChartLine) => string = lineKey): Row[] {
  const byT = new Map<number, Row>();
  for (const l of lines) {
    const k = keyOf(l);
    for (const p of l.points ?? []) {
      const t = Number(p[0]);
      const v = p[1] === null || p[1] === undefined ? null : Number(p[1]);
      let row = byT.get(t);
      if (!row) {
        row = { t };
        byT.set(t, row);
      }
      row[k] = v;
    }
  }
  return [...byT.values()].sort((a, b) => a.t - b.t);
}

/** Sum of a line's non-null points (a counter's count over the window). */
export function sumLine(l: ChartLine | undefined): number | null {
  if (!l) return null;
  let total = 0;
  let any = false;
  for (const p of l.points ?? []) {
    if (p[1] !== null && p[1] !== undefined) {
      total += Number(p[1]);
      any = true;
    }
  }
  return any ? total : null;
}

/** Sum over every line of a requested series (all its label sets). Core names each line by
 * the series name it was asked for (`latency_us.p99`, `upstream.queries`). */
export function sumSeries(chart: Chart | undefined, name: string): number | null {
  if (!chart) return null;
  let total: number | null = null;
  for (const l of chart.series.filter((x) => x.name === name)) {
    const s = sumLine(l);
    if (s !== null) total = (total ?? 0) + s;
  }
  return total;
}

export function hasData(lines: ChartLine[]): boolean {
  return lines.some((l) => (l.points ?? []).some((p) => p[1] !== null && p[1] !== undefined));
}

/** A line a transform computed from others (`fw.entries ÷ fw.max`): it shows their series. */
export type DerivedLine = ChartLine & { sources?: string[] };

/** The requested series a line shows: its own, or those a transform computed it from. */
export function sourcesOf(l: ChartLine): string[] {
  return (l as DerivedLine).sources ?? [l.name];
}

/**
 * The `data-rendered` attribute of what a panel shows: the requested series behind the lines or
 * values it draws, only those with data. Tests read it to tell a series drawn from one merely
 * asked for (pages/metrics-coverage.test.tsx).
 */
export function renderedAttr(lines: ChartLine[]): string | undefined {
  const names = new Set(lines.filter((l) => hasData([l])).flatMap(sourcesOf));
  return names.size ? [...names].sort().join(" ") : undefined;
}

/** `data-rendered` for a table or figures: each series whose value is shown (a number, or true). */
export function shownAttr(shown: [number | boolean | null, string][]): string | undefined {
  const names = shown.filter(([v]) => v !== null && v !== false).map(([, n]) => n);
  return names.length ? names.join(" ") : undefined;
}

export const CHART_COLORS = [
  "var(--chart-1)",
  "var(--chart-2)",
  "var(--chart-3)",
  "var(--chart-4)",
  "var(--chart-5)",
  "var(--chart-6)",
];
