import * as React from "react";
import { PageHeader, Section, Stat } from "@/components/common/page";
import { ErrorState, LoadingState, NotAvailable } from "@/components/common/states";
import { EdgeSelector, WindowPicker } from "@/components/common/window-picker";
import { MetricPanel } from "@/components/charts/metric-panel";
import { shownAttr, sumSeries } from "@/components/charts/series";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SafeText } from "@/components/common/text";
import { JobBadge } from "@/components/common/job-progress";
import { useJobs, useMetrics, useSettings } from "@/api/queries";
import { useConnection, useJobReports } from "@/api/events";
import { isNotAvailable } from "@/api/errors";
import type { ChartLine, Window } from "@/api/types";
import { computeCoverage } from "@/lib/coverage";
import { formatBytes, formatCompact, formatNumber, formatPercent, formatSeconds } from "@/lib/format";
import { cpuPercent, spoolAge } from "./edge-detail";
import { useWindowState } from "./dashboard";

const byLabel = (key: string, fallback = "") => (l: ChartLine) => l.labels?.[key] ?? fallback;
const withEdge = (label: string) => (l: ChartLine) => (l.edge ? `${label} · ${l.edge}` : label);

/** System: core's own charts (core.md §12, §10), bounded by metrics retention alone. */
export function SystemPage() {
  const { window, edge, allowed, setWindow, setEdge } = useWindowState("metrics");
  // Per-edge charts keep one line per edge when the selector says all.
  const perEdge = edge === "all" ? "each" : edge;
  const settings = useSettings();
  const evidenceCap = (settings.data?.settings.alerts?.evidence_total_mib ?? 128) * 1024 * 1024;
  const crosscheckOn = settings.data?.settings.crosscheck?.enabled === true;
  return (
    <div className="space-y-6">
      <PageHeader
        title="System"
        description="Core's own resources, work queues, log pipeline and checks."
        actions={
          <>
            <WindowPicker value={window} onChange={setWindow} allowed={allowed} />
            <EdgeSelector value={edge} onChange={setEdge} />
          </>
        }
      />
      <h2 className="text-lg font-semibold">Resources</h2>
      <div className="grid gap-4 xl:grid-cols-2">
        <MetricPanel title="Memory (RSS)" series={["core_rss"]} window={window} edge="all" format={formatBytes} specs={[{ match: () => true, label: "core RSS" }]} />
        <MetricPanel title="CPU" description="100 % is one core." series={["core_cpu_ms"]} window={window} edge="all" transform={cpuPercent} format={(v) => `${formatNumber(v, 1)} %`} specs={[{ match: () => true, label: "core" }]} />
        <MetricPanel
          title="Data directory and disk"
          series={["core_disk_used", "core_disk_free"]}
          window={window}
          edge="all"
          format={formatBytes}
          specs={[
            { match: (l) => l.name === "core_disk_used", label: "data directory" },
            { match: (l) => l.name === "core_disk_free", label: "free on its disk" },
          ]}
        />
        <MetricPanel title="Databases" description="core, metrics and the log partitions, each with its WAL." series={["db_bytes"]} window={window} edge="all" format={formatBytes} specs={[{ match: () => true, label: byLabel("db", "db") }]} />
        <MetricPanel
          title="Alert evidence"
          description="Evidence copies and counts of all alerts, against alerts.evidence_total_mib."
          series={["evidence_bytes"]}
          window={window}
          edge="all"
          format={formatBytes}
          refLines={[{ y: evidenceCap, label: "evidence_total_mib" }]}
          specs={[{ match: () => true, label: "evidence" }]}
        />
      </div>

      <h2 className="text-lg font-semibold">Work</h2>
      <JobsNow />
      <div className="grid gap-4 xl:grid-cols-2">
        <MetricPanel title="Queue depths" series={["queue_depth"]} window={window} edge="all" specs={[{ match: () => true, label: byLabel("queue", "queue") }]} />
        <MetricPanel
          title="Job durations"
          description="p50 and p99 by kind."
          series={["job_ms.p50", "job_ms.p99"]}
          window={window}
          edge="all"
          format={(v) => `${formatNumber(v, 0)} ms`}
          specs={[
            { match: (l) => l.name === "job_ms.p50", label: (l) => `${l.labels?.kind ?? "?"} p50` },
            { match: (l) => l.name === "job_ms.p99", label: (l) => `${l.labels?.kind ?? "?"} p99` },
          ]}
        />
      </div>

      <h2 className="text-lg font-semibold">Log pipeline</h2>
      <div className="grid gap-4 xl:grid-cols-2">
        <MetricPanel title="Records ingested" series={["log_records"]} window={window} edge={perEdge} specs={[{ match: () => true, label: withEdge("records") }]} />
        <MetricPanel title="Edge spools" description="Each edge's spool size." series={["spool.bytes"]} window={window} edge={perEdge} format={formatBytes} specs={[{ match: () => true, label: withEdge("spool") }]} />
        <MetricPanel title="Spool age" description="Each edge's oldest record still waiting for core." series={["spool.oldest_ts"]} window={window} edge={perEdge} transform={spoolAge} format={formatSeconds} specs={[{ match: () => true, label: withEdge("age") }]} />
        <MetricPanel
          title="Dropped records"
          description="Records core dropped by reason, and, as their own lines, records each edge dropped."
          series={["log_dropped", "logs.dropped", "log_answer_missing"]}
          window={window}
          edge={perEdge}
          specs={[
            { match: (l) => l.name === "log_dropped", label: (l) => `core: ${l.labels?.reason ?? "?"}${l.edge ? ` · ${l.edge}` : ""}` },
            { match: (l) => l.name === "logs.dropped", label: (l) => `edge: ${l.labels?.reason ?? "?"}${l.edge ? ` · ${l.edge}` : ""}` },
            { match: (l) => l.name === "log_answer_missing", label: withEdge("stored with answer_missing") },
          ]}
        />
        <MetricPanel title="Wire mismatches" description="By kind: rejected, cname, answers, targets, deciding." series={["wire_mismatch"]} window={window} edge={perEdge} specs={[{ match: () => true, label: (l) => `${l.labels?.kind ?? "?"}${l.edge ? ` · ${l.edge}` : ""}` }]} />
        <MetricPanel title="Attribution backlog" description="Records awaiting replay." series={["queue_depth"]} window={window} edge="all" transform={(ls) => ls.filter((l) => l.labels?.queue === "attribution")} specs={[{ match: () => true, label: "attribution" }]} />
        <MetricPanel
          title="Skipped work"
          description="What core gave up to stay within its bounds, by kind: records past the analysis budget, evidence copies not captured, retro-match and trial checks, and metric increments metrics.db couldn't take."
          series={["analysis_skipped"]}
          window={window}
          edge="all"
          specs={[{ match: () => true, label: byLabel("work", "?") }]}
        />
      </div>

      <h2 className="text-lg font-semibold">DNSSEC</h2>
      <div className="grid gap-4 xl:grid-cols-2">
        <MetricPanel title="Results" series={["dnssec_results"]} window={window} edge="all" kind="stacked" specs={[{ match: () => true, label: byLabel("outcome", "?") }]} />
        <MetricPanel
          title="Backlog and fallback queries"
          series={["queue_depth", "dnssec_fallback"]}
          window={window}
          edge="all"
          transform={(ls) => ls.filter((l) => l.name !== "queue_depth" || l.labels?.queue === "dnssec")}
          specs={[
            { match: (l) => l.name === "queue_depth", label: "validation backlog" },
            { match: (l) => l.name === "dnssec_fallback", label: "fallback queries" },
          ]}
        />
        <MetricPanel
          title="Dropped validations"
          description="Answers dropped from the validation queue: full (the queue was at its cap) or too_old (still queued past the log retention window)."
          series={["dnssec_dropped"]}
          window={window}
          edge="all"
          specs={[{ match: () => true, label: byLabel("reason", "?") }]}
        />
      </div>
      <Coverage window={window} edge={edge} />
      {crosscheckOn ? (
        <div className="grid gap-4 xl:grid-cols-2">
          <MetricPanel title="Cross-check" description="Checks by kind and result." series={["crosscheck"]} window={window} edge="all" specs={[{ match: () => true, label: (l) => `${l.labels?.check ?? "?"}: ${l.labels?.result ?? "?"}` }]} />
          <MetricPanel title="Cross-check queue" series={["queue_depth"]} window={window} edge="all" transform={(ls) => ls.filter((l) => l.labels?.queue === "crosscheck")} specs={[{ match: () => true, label: "crosscheck" }]} />
        </div>
      ) : (
        <Section title="Cross-check">
          <p className="text-sm text-muted-foreground">The cross-check of unsigned answers is off (Settings → Cross-check).</p>
        </Section>
      )}

      <h2 className="text-lg font-semibold">Re-checks and retro-match</h2>
      <div className="grid gap-4 xl:grid-cols-2">
        <MetricPanel title="Re-checks" description="Run, skipped and dropped per provider." series={["rechecks"]} window={window} edge="all" specs={[{ match: () => true, label: (l) => `${l.labels?.provider ?? "?"}: ${l.labels?.result ?? "?"}` }]} />
        <MetricPanel title="Blocks re-checks found" series={["recheck_blocks"]} window={window} edge="all" specs={[{ match: () => true, label: byLabel("provider", "?") }]} />
        <MetricPanel title="Retro-match hits" description="Per feed, counted at the time of the run that added the entry." series={["retro_hits"]} window={window} edge="all" specs={[{ match: () => true, label: byLabel("feed", "?") }]} />
      </div>
    </div>
  );
}

/**
 * The lanes now. `job` events set them as each heavy job starts and ends (api/events.ts); light
 * lane jobs and heavy jobs waiting in the queue send none, so `GET jobs` is still read every 30 s,
 * and every 5 s while the event socket is down.
 */
function JobsNow() {
  const live = useConnection() === "open";
  const q = useJobs(live ? 30_000 : 5000);
  const recent = useJobReports(0, () => true);
  if (q.isPending) return <LoadingState rows={1} />;
  if (q.error) return <ErrorState error={q.error} />;
  const j = q.data;
  const ended = recent.filter((r) => r.phase === "end").slice(-10).reverse();
  return (
    <div className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-6" aria-label="Job lanes now">
        <Stat label="Light lane" value={formatNumber(j.light_depth)} hint={`${formatNumber(j.light_dropped)} dropped`} />
        <Stat label="Heavy lane" value={formatNumber(j.heavy_depth)} hint={`${formatNumber(j.heavy_dropped)} dropped`} />
        <Stat label="Heavy running" value={<span className="text-base">{j.heavy_running ?? "idle"}</span>} />
        <Stat label="Heavy done" value={formatCompact(j.heavy_completed)} />
        <Stat label="Heavy failed" value={formatCompact(j.heavy_failed)} />
      </div>
      {ended.length > 0 && (
        <Section title="Heavy jobs since this page opened" description="The newest ten that ended, as core reported them.">
          <Table aria-label="Recent heavy jobs">
            <TableHeader>
              <TableRow>
                <TableHead>Job</TableHead>
                <TableHead>Result</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {ended.map((r) => (
                <TableRow key={r.job}>
                  <TableCell>
                    <SafeText mono>{r.job}</SafeText>
                  </TableCell>
                  <TableCell>
                    <JobBadge j={r} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Section>
      )}
    </div>
  );
}

function Coverage({ window, edge }: { window: Window; edge: string }) {
  const totals = useMetrics(["by_decision.allow", "by_decision.servfail"], window, edge);
  const core = useMetrics(["dnssec_answers", "dnssec_coverage"], window, edge);
  let body: React.ReactNode;
  if (totals.isPending || core.isPending) body = <LoadingState rows={4} />;
  else if (core.error && isNotAvailable(core.error)) body = <NotAvailable what="DNSSEC coverage" />;
  else if (totals.error || core.error) body = <ErrorState error={totals.error ?? core.error} />;
  else {
    const allowed = sumSeries(totals.data, "by_decision.allow");
    const servfail = sumSeries(totals.data, "by_decision.servfail");
    const answers = sumSeries(core.data, "dnssec_answers");
    const answersGot = (allowed ?? 0) + (servfail ?? 0);
    const logged = answers ?? 0;
    const classes: Record<string, number> = {};
    const fallbackOutcomes: Record<string, number> = {};
    for (const l of core.data?.series ?? []) {
      if (l.name !== "dnssec_coverage") continue;
      const total = (l.points ?? []).reduce((a, p) => a + (p[1] === null || p[1] === undefined ? 0 : Number(p[1])), 0);
      const cls = l.labels?.class ?? "?";
      classes[cls] = (classes[cls] ?? 0) + total;
      if (cls === "fallback" && l.labels?.outcome) fallbackOutcomes[l.labels.outcome] = (fallbackOutcomes[l.labels.outcome] ?? 0) + total;
    }
    const { rows, total } = computeCoverage({ answersGot, logged, classes, fallbackOutcomes });
    body = (
      <div className="space-y-3">
        <div className="flex h-3 w-full overflow-hidden rounded-full bg-muted" role="img" aria-label="Coverage shares">
          {rows
            .filter((r) => r.share > 0)
            .map((r, i) => (
              <div key={r.key} title={`${r.label}: ${formatPercent(r.share)}`} className="h-full" style={{ width: `${r.share * 100}%`, background: `var(--chart-${(i % 6) + 1})` }} />
            ))}
        </div>
        <Table
          aria-label="DNSSEC coverage"
          data-rendered={shownAttr([
            [allowed, "by_decision.allow"],
            [servfail, "by_decision.servfail"],
            [answers, "dnssec_answers"],
            [Object.keys(classes).length > 0, "dnssec_coverage"],
          ])}
        >
          <TableHeader>
            <TableRow>
              <TableHead>Answers clients got</TableHead>
              <TableHead className="text-right">Count</TableHead>
              <TableHead className="text-right">Share</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((r) => (
              <TableRow key={r.key}>
                <TableCell>
                  {r.label}
                  {r.key === "fallback" && Object.keys(fallbackOutcomes).length > 0 && (
                    <span className="ml-2 text-xs text-muted-foreground">
                      ({Object.entries(fallbackOutcomes).map(([k, v]) => `${k} ${formatCompact(v)}`).join(", ")})
                    </span>
                  )}
                </TableCell>
                <TableCell className="text-right tabular-nums">{formatCompact(r.count)}</TableCell>
                <TableCell className="text-right tabular-nums">{formatPercent(r.share)}</TableCell>
              </TableRow>
            ))}
            <TableRow>
              <TableCell className="font-medium">Total</TableCell>
              <TableCell className="text-right font-medium tabular-nums">{formatCompact(total)}</TableCell>
              <TableCell className="text-right font-medium tabular-nums">{total > 0 ? "100 %" : "—"}</TableCell>
            </TableRow>
          </TableBody>
        </Table>
        <p className="text-xs text-muted-foreground">
          Not logged covers profiles with log: blocked or off, records an edge or core dropped, and records still spooled on an edge.
        </p>
      </div>
    );
  }
  return (
    <Section title="Coverage" description="Of the answers clients got (allowed plus SERVFAIL, from the heartbeat totals over the window), how each was checked.">
      {body}
    </Section>
  );
}
