import * as React from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  Line,
  ReferenceLine,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { ChartLine } from "@/api/types";
import { formatCompact } from "@/lib/format";
import { escapeControl } from "@/lib/text";
import { CHART_COLORS, hasData, lineKey, renderedAttr, toRows } from "./series";

export interface SeriesSpec {
  /** Which line(s) this spec draws. */
  match: (l: ChartLine) => boolean;
  label?: string | ((l: ChartLine) => string);
  color?: string;
}

function timeTick(t: number, spanS: number) {
  const d = new Date(t * 1000);
  return spanS > 2 * 86400
    ? d.toLocaleString(undefined, { weekday: "short", hour: "2-digit" })
    : d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

/**
 * A time-series chart of metric lines (core.md §10 Charts): a gap (null) is drawn as a gap,
 * never a zero. Labels from outside core (edge names, label values) are shown as text.
 */
export function TimeSeriesChart({
  lines,
  specs,
  kind = "line",
  height = 220,
  format = formatCompact,
  ariaLabel,
  refLines,
}: {
  lines: ChartLine[];
  /** Horizontal limits drawn across the chart (e.g. the unit's MemoryHigh and MemoryMax). */
  refLines?: { y: number; label: string }[];
  specs?: SeriesSpec[];
  kind?: "line" | "area" | "stacked";
  height?: number;
  format?: (v: number) => string;
  ariaLabel: string;
}) {
  const drawn = React.useMemo(() => {
    const out: { key: string; label: string; color: string; line: ChartLine }[] = [];
    let ci = 0;
    if (specs) {
      for (const s of specs) {
        for (const l of lines.filter(s.match)) {
          const label = typeof s.label === "function" ? s.label(l) : (s.label ?? lineKey(l));
          out.push({ key: lineKey(l), label: escapeControl(label), color: s.color ?? CHART_COLORS[ci++ % CHART_COLORS.length], line: l });
        }
      }
    } else {
      for (const l of lines) {
        out.push({ key: lineKey(l), label: escapeControl(lineKey(l)), color: CHART_COLORS[ci++ % CHART_COLORS.length], line: l });
      }
    }
    return out;
  }, [lines, specs]);
  const rows = React.useMemo(() => toRows(drawn.map((d) => d.line)), [drawn]);
  if (!hasData(drawn.map((d) => d.line))) {
    return (
      <div className="flex items-center justify-center rounded-md border border-dashed text-sm text-muted-foreground" style={{ height }}>
        No data in this window.
      </div>
    );
  }
  const span = rows.length > 1 ? rows[rows.length - 1].t - rows[0].t : 3600;
  const common = (
    <>
      <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
      <XAxis
        dataKey="t"
        type="number"
        domain={["dataMin", "dataMax"]}
        scale="time"
        tickFormatter={(t: number) => timeTick(t, span)}
        tick={{ fontSize: 11, fill: "var(--muted-foreground)" }}
        stroke="var(--border)"
        minTickGap={40}
      />
      <YAxis tickFormatter={(v: number) => format(v)} tick={{ fontSize: 11, fill: "var(--muted-foreground)" }} stroke="var(--border)" width={56} />
      <Tooltip
        labelFormatter={(t) => new Date(Number(t) * 1000).toLocaleString()}
        formatter={(v, name) => [v === null || v === undefined ? "—" : format(Number(v)), name]}
        contentStyle={{ background: "var(--popover)", border: "1px solid var(--border)", borderRadius: 6, fontSize: 12, color: "var(--popover-foreground)" }}
      />
      {drawn.length > 1 && <Legend wrapperStyle={{ fontSize: 12 }} />}
      {refLines?.map((r) => (
        <ReferenceLine key={r.label} y={r.y} stroke="var(--destructive)" strokeDasharray="4 4" label={{ value: r.label, fontSize: 10, fill: "var(--muted-foreground)", position: "insideTopRight" }} />
      ))}
    </>
  );
  return (
    <div role="img" aria-label={ariaLabel} style={{ height }} className="w-full min-w-0" data-rendered={renderedAttr(drawn.map((d) => d.line))}>
      <ResponsiveContainer width="100%" height="100%">
        {kind === "line" ? (
          <LineChart data={rows} margin={{ top: 5, right: 10, bottom: 0, left: 0 }}>
            {common}
            {drawn.map((d) => (
              <Line key={d.key} dataKey={d.key} name={d.label} stroke={d.color} dot={false} strokeWidth={1.75} connectNulls={false} isAnimationActive={false} />
            ))}
          </LineChart>
        ) : (
          <AreaChart data={rows} margin={{ top: 5, right: 10, bottom: 0, left: 0 }}>
            {common}
            {drawn.map((d) => (
              <Area
                key={d.key}
                dataKey={d.key}
                name={d.label}
                stroke={d.color}
                fill={d.color}
                fillOpacity={0.35}
                stackId={kind === "stacked" ? "s" : undefined}
                connectNulls={false}
                isAnimationActive={false}
              />
            ))}
          </AreaChart>
        )}
      </ResponsiveContainer>
    </div>
  );
}
