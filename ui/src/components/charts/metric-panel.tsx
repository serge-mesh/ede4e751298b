import * as React from "react";
import { useMetrics } from "@/api/queries";
import type { ChartLine, Window } from "@/api/types";
import { isNotAvailable } from "@/api/errors";
import { Section } from "@/components/common/page";
import { ErrorState, LoadingState, NotAvailable, RefetchError } from "@/components/common/states";
import { TimeSeriesChart, type SeriesSpec } from "./time-series";

/**
 * One chart panel: asks core for its own series (api.md §7 `GET metrics`). A series core.md §10
 * names that this core doesn't record yet is left out and named under the chart; with none left,
 * the panel says "not available yet" (api/availability.ts). A failed refresh keeps the chart
 * loaded for this window and says so, with Retry.
 */
export function MetricPanel({
  title,
  description,
  series,
  window,
  edge,
  specs,
  kind,
  format,
  height,
  refetchInterval,
  note,
  transform,
  actions,
  className,
  refLines,
}: {
  refLines?: { y: number; label: string }[];
  title: string;
  description?: React.ReactNode;
  series: string[];
  window: Window;
  edge: string;
  specs?: SeriesSpec[];
  kind?: "line" | "area" | "stacked";
  format?: (v: number) => string;
  height?: number;
  refetchInterval?: number;
  note?: React.ReactNode;
  transform?: (lines: ChartLine[]) => ChartLine[];
  actions?: React.ReactNode;
  className?: string;
}) {
  const q = useMetrics(series, window, edge, { refetchInterval });
  let body: React.ReactNode;
  const missing = q.data?.unavailable ?? [];
  const unavailable = !!q.error && isNotAvailable(q.error);
  if (q.isPending) body = <LoadingState rows={4} />;
  else if (unavailable) body = <NotAvailable what={title} />;
  else if (q.data === undefined) body = <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  else {
    const lines = transform ? transform(q.data.series) : q.data.series;
    body = (
      <>
        {q.error && <RefetchError error={q.error} onRetry={() => void q.refetch()} className="mb-2" />}
        <TimeSeriesChart lines={lines} specs={specs} kind={kind} format={format} height={height} ariaLabel={title} refLines={refLines} />
      </>
    );
  }
  return (
    <Section title={title} description={description} actions={actions} className={className}>
      {body}
      {!unavailable && missing.length > 0 && <p className="mt-2 text-xs text-muted-foreground">Not recorded by this core yet: {missing.join(", ")}.</p>}
      {note && <p className="mt-2 text-xs text-muted-foreground">{note}</p>}
    </Section>
  );
}
