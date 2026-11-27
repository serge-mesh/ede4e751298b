import * as React from "react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { BellIcon, RouterIcon, FileTextIcon, TriangleAlertIcon } from "lucide-react";
import { PageHeader, Section, Stat } from "@/components/common/page";
import { EdgeSelector, WindowPicker, allowedWindows, clampWindow, useWindowBound } from "@/components/common/window-picker";
import { ErrorState, LoadingState, NotAvailable, QueryView } from "@/components/common/states";
import { SafeText } from "@/components/common/text";
import { TimeAgo } from "@/components/common/time";
import { MetricPanel } from "@/components/charts/metric-panel";
import { TimeSeriesChart } from "@/components/charts/time-series";
import { shownAttr, sumLine, sumSeries } from "@/components/charts/series";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  useConfigIssues,
  useEdges,
  useEntities,
  useFeedStatuses,
  useMetrics,
  useOpenAlerts,
} from "@/api/queries";
import { isNotAvailable } from "@/api/errors";
import { client, unwrap } from "@/api/http";
import { useQuery } from "@tanstack/react-query";
import type { ChartLine, Window } from "@/api/types";
import { formatCompact, formatNumber, formatPercent, formatSeconds } from "@/lib/format";
import { escapeControl } from "@/lib/text";
import type { WindowSearch } from "@/lib/search";
import { SeverityBadge } from "./alerts";

const REFRESH = 30_000;

export function useWindowState(kind: "dashboard" | "metrics" = "dashboard") {
  const search = useSearch({ strict: false }) as WindowSearch;
  const navigate = useNavigate();
  const allowed = allowedWindows(useWindowBound(kind));
  const window = clampWindow(search.window ?? "24h", allowed);
  const edge = search.edge ?? "all";
  const set = (patch: WindowSearch) =>
    void navigate({ to: ".", search: (prev: Record<string, unknown>) => ({ ...prev, ...patch }), replace: true });
  return { window, edge, allowed, setWindow: (w: Window) => set({ window: w }), setEdge: (e: string) => set({ edge: e }) };
}

export function DashboardPage() {
  const { window, edge, allowed, setWindow, setEdge } = useWindowState("dashboard");
  return (
    <div className="space-y-5">
      <PageHeader
        title="Dashboard"
        description="Refreshes every 30 s. The panels below the first row follow the window and edge chosen here."
        actions={
          <>
            <WindowPicker value={window} onChange={setWindow} allowed={allowed} />
            <EdgeSelector value={edge} onChange={setEdge} />
          </>
        }
      />
      <ConfigIssuesBanner />
      <div className="grid gap-4 lg:grid-cols-3">
        <EdgesCard />
        <AlertsCard />
        <FreshnessCard />
      </div>
      <Totals window={window} edge={edge} />
      <div className="grid gap-4 xl:grid-cols-2">
        <MetricPanel
          title="Queries over time"
          description="Stacked by decision."
          series={["by_decision.allow", "by_decision.block", "by_decision.rewrite", "by_decision.refused", "by_decision.servfail"]}
          window={window}
          edge={edge}
          kind="stacked"
          refetchInterval={REFRESH}
          specs={["allow", "block", "rewrite", "refused", "servfail"].map((d, i) => ({
            match: (l: ChartLine) => l.name === `by_decision.${d}`,
            label: d,
            color: `var(--chart-${[3, 2, 5, 4, 6][i]})`,
          }))}
        />
        <MetricPanel
          title="Queries by transport"
          description="DNS (UDP and TCP), DoT and DoH."
          series={["queries_by_transport"]}
          window={window}
          edge={edge}
          kind="stacked"
          refetchInterval={REFRESH}
          specs={[{ match: () => true, label: (l) => l.labels?.transport ?? "?" }]}
          note="Only logged queries count: a profile with log: blocked adds only blocked queries, one with log: off none."
        />
        <MetricPanel
          title="Latency"
          description="p50 and p99 of the time to answer."
          series={["latency_us.p50", "latency_us.p99"]}
          window={window}
          edge={edge}
          refetchInterval={REFRESH}
          format={(v) => `${formatNumber(v / 1000, 1)} ms`}
          specs={[
            { match: (l) => l.name === "latency_us.p50", label: "p50" },
            { match: (l) => l.name === "latency_us.p99", label: "p99" },
          ]}
        />
        <UpstreamHealth window={window} edge={edge} />
      </div>
      <div className="grid gap-4 xl:grid-cols-3">
        <TopPanel kind="blocked" title="Top blocked names" window={window} edge={edge} />
        <TopPanel kind="allowed" title="Top allowed names" window={window} edge={edge} />
        <TopPanel kind="clients" title="Top devices" window={window} edge={edge} />
      </div>
    </div>
  );
}

function ConfigIssuesBanner() {
  const q = useConfigIssues();
  const issues = q.data ?? [];
  if (issues.length === 0) return null;
  const errors = issues.filter((i) => i.severity === "error");
  return (
    <Alert variant={errors.length ? "destructive" : "warning"}>
      <TriangleAlertIcon />
      <AlertTitle>
        {errors.length ? `${errors.length} configuration error${errors.length > 1 ? "s" : ""}` : `${issues.length} configuration warning${issues.length > 1 ? "s" : ""}`}
      </AlertTitle>
      <AlertDescription>
        <ul className="list-disc pl-4">
          {issues.slice(0, 6).map((i, n) => (
            <li key={n}>
              <code className="font-mono text-xs">
                {i.entity} {escapeControl(i.id)}
              </code>
              : {escapeControl(i.message)}
            </li>
          ))}
          {issues.length > 6 && <li>… and {issues.length - 6} more</li>}
        </ul>
      </AlertDescription>
    </Alert>
  );
}

function EdgesCard() {
  const q = useEdges(REFRESH);
  return (
    <Section
      title={
        <span className="flex items-center gap-2">
          <RouterIcon className="size-4" /> Edges
        </span>
      }
      actions={
        <Link to="/edges" className="text-sm text-primary hover:underline">
          All edges
        </Link>
      }
    >
      <QueryView query={q} rows={3} empty={<p className="text-sm text-muted-foreground">No edges yet. Add one under Edges.</p>} isEmpty={(d) => d.length === 0}>
        {(edges) => (
          <ul className="divide-y">
            {edges.map((e) => {
              const conditions = Array.isArray(e.status?.conditions) ? (e.status?.conditions as unknown[]).length : 0;
              return (
                <li key={e.id} className="flex items-center justify-between gap-2 py-2">
                  <Link to="/edges/$edgeId" params={{ edgeId: e.id ?? "" }} className="min-w-0 truncate font-medium hover:underline">
                    <SafeText>{e.name || e.id}</SafeText>
                  </Link>
                  <span className="flex shrink-0 items-center gap-2">
                    {conditions > 0 && <Badge variant="warning">{conditions} condition{conditions > 1 ? "s" : ""}</Badge>}
                    {e.status?.online ? <Badge variant="success">online</Badge> : <Badge variant="destructive">offline</Badge>}
                  </span>
                </li>
              );
            })}
          </ul>
        )}
      </QueryView>
    </Section>
  );
}

function AlertsCard() {
  const q = useOpenAlerts(REFRESH);
  return (
    <Section
      title={
        <span className="flex items-center gap-2">
          <BellIcon className="size-4" /> Open alerts
        </span>
      }
      actions={
        <Link to="/alerts" className="text-sm text-primary hover:underline">
          All alerts
        </Link>
      }
    >
      <QueryView query={q} rows={3} empty={<p className="text-sm text-muted-foreground">No open alerts.</p>} isEmpty={(d) => d.length === 0}>
        {(alerts) => {
          const bySev = { critical: 0, warning: 0, info: 0 };
          for (const a of alerts) bySev[a.severity] += 1;
          const top = [...alerts].sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || b.last_seen.localeCompare(a.last_seen)).slice(0, 5);
          return (
            <div className="space-y-3">
              <div className="flex gap-2 text-sm">
                <Badge variant="destructive">{bySev.critical} critical</Badge>
                <Badge variant="warning">{bySev.warning} warning</Badge>
                <Badge variant="secondary">{bySev.info} info</Badge>
              </div>
              <ul className="space-y-1.5">
                {top.map((a) => (
                  <li key={a.id} className="flex items-start gap-2 text-sm">
                    <SeverityBadge severity={a.severity} />
                    <Link to="/alerts/$alertId" params={{ alertId: String(a.id) }} className="min-w-0 flex-1 hover:underline">
                      <SafeText>{a.title}</SafeText>
                    </Link>
                    <TimeAgo value={a.last_seen} className="shrink-0 text-xs text-muted-foreground" />
                  </li>
                ))}
              </ul>
            </div>
          );
        }}
      </QueryView>
    </Section>
  );
}

function sevRank(s: string) {
  return s === "critical" ? 3 : s === "warning" ? 2 : 1;
}

function FreshnessCard() {
  const q = useFeedStatuses(REFRESH);
  const alerts = useOpenAlerts(REFRESH);
  const stale = new Set((alerts.data ?? []).filter((a) => a.kind === "feed_stale" && a.feed).map((a) => a.feed as string));
  return (
    <Section
      title={
        <span className="flex items-center gap-2">
          <FileTextIcon className="size-4" /> Feed freshness
        </span>
      }
      actions={
        <Link to="/feeds" className="text-sm text-primary hover:underline">
          All feeds
        </Link>
      }
    >
      <QueryView query={q} rows={3}>
        {(feeds) => {
          const enabled = feeds.filter((f) => f.enabled && !f.manual);
          const failing = enabled.filter((f) => f.failures > 0);
          const held = enabled.filter((f) => f.held_run !== null && f.held_run !== undefined);
          const worst = [...enabled]
            .sort(
              (a, b) =>
                Number(b.failures > 0) - Number(a.failures > 0) ||
                Number(stale.has(b.feed)) - Number(stale.has(a.feed)) ||
                (b.since_last_change_s ?? 0) - (a.since_last_change_s ?? 0),
            )
            .slice(0, 5);
          return (
            <div className="space-y-3">
              <div className="flex flex-wrap gap-2 text-sm">
                <Badge variant="secondary">{enabled.length} downloaded feeds</Badge>
                <Badge variant={failing.length ? "destructive" : "secondary"}>{failing.length} failing</Badge>
                <Badge variant={stale.size ? "warning" : "secondary"}>{stale.size} stale</Badge>
                <Badge variant={held.length ? "warning" : "secondary"}>{held.length} held</Badge>
              </div>
              {worst.length > 0 && (
                <ul className="space-y-1 text-sm">
                  {worst.map((f) => (
                    <li key={f.feed} className="flex items-center justify-between gap-2">
                      <Link to="/feeds/$feedId" params={{ feedId: f.feed }} className="min-w-0 truncate hover:underline">
                        <SafeText>{f.name || f.feed}</SafeText>
                      </Link>
                      <span className="shrink-0 text-xs text-muted-foreground">
                        {f.failures > 0 ? (
                          <span className="text-destructive">{f.failures} failed checks</span>
                        ) : stale.has(f.feed) ? (
                          <span className="text-warning">stale</span>
                        ) : (
                          <>changed {formatSeconds(f.since_last_change_s)} ago</>
                        )}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          );
        }}
      </QueryView>
    </Section>
  );
}

function Totals({ window, edge }: { window: Window; edge: string }) {
  const q = useMetrics(["queries", "by_decision.block", "cache_hits", "cache_misses"], window, edge, { refetchInterval: REFRESH });
  if (q.isPending) return <LoadingState rows={2} />;
  if (q.error) return isNotAvailable(q.error) ? <NotAvailable what="Totals" /> : <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const queries = sumSeries(q.data, "queries");
  const blocked = sumSeries(q.data, "by_decision.block");
  const hits = sumSeries(q.data, "cache_hits");
  const misses = sumSeries(q.data, "cache_misses");
  const blockRate = queries && blocked !== null ? blocked / queries : null;
  const hitRate = hits !== null && misses !== null && hits + misses > 0 ? hits / (hits + misses) : null;
  return (
    <div className="grid gap-3 sm:grid-cols-3" aria-label="Totals" data-rendered={shownAttr([[queries, "queries"], [blocked, "by_decision.block"], [hits, "cache_hits"], [misses, "cache_misses"]])}>
      <Stat label="Queries" value={formatCompact(queries)} hint={`from heartbeat totals over ${window}`} />
      <Stat label="Block rate" value={formatPercent(blockRate)} hint={`${formatCompact(blocked)} blocked`} />
      <Stat label="Cache hit rate" value={formatPercent(hitRate)} hint={`${formatCompact(hits)} hits, ${formatCompact(misses)} misses`} />
    </div>
  );
}

const UPSTREAM_SERIES = [
  "upstream.queries",
  "upstream.hedges",
  "upstream.errors",
  "upstream.invalid",
  "upstream.scrubbed",
  "upstream.rtt_ms.p50",
  "upstream.rtt_ms.p99",
  "stale_served",
];

/** `reason: n, …` of a by-reason count, or a dash. */
function byReason(m: Record<string, number>): string {
  return Object.keys(m).length === 0
    ? "—"
    : Object.entries(m)
        .map(([k, v]) => `${escapeControl(k)}: ${formatCompact(v)}`)
        .join(", ");
}

function UpstreamHealth({ window, edge }: { window: Window; edge: string }) {
  const q = useMetrics(UPSTREAM_SERIES, window, edge, { refetchInterval: REFRESH });
  const upstreams = useEntities("upstreams");
  const names = new Map((upstreams.data ?? []).map((u) => [u.id ?? "", u.name || u.id || ""]));
  let body: React.ReactNode;
  if (q.isPending) body = <LoadingState rows={4} />;
  else if (q.error) body = isNotAvailable(q.error) ? <NotAvailable what="Upstream health" /> : <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  else {
    const lines = q.data?.series ?? [];
    const rows = upstreamRows(lines);
    const total = rows.reduce((a, r) => a + (r.queries ?? 0), 0);
    const stale = sumSeries(q.data, "stale_served");
    const padding = rows.reduce<number | null>((a, r) => (r.padding === null ? a : (a ?? 0) + r.padding), null);
    body = (
      <div className="space-y-3">
        <Table
          aria-label="Upstream health"
          data-rendered={shownAttr([
            [rows.some((r) => r.queries !== null), "upstream.queries"],
            [rows.some((r) => r.hedges !== null), "upstream.hedges"],
            [rows.some((r) => r.errors !== null), "upstream.errors"],
            [rows.some((r) => Object.keys(r.invalid).length > 0), "upstream.invalid"],
            [rows.some((r) => Object.keys(r.scrubbed).length > 0) || padding !== null, "upstream.scrubbed"],
            [stale, "stale_served"],
          ])}
        >
          <TableHeader>
            <TableRow>
              <TableHead>Upstream</TableHead>
              <TableHead className="text-right">Share</TableHead>
              <TableHead className="text-right">Hedges</TableHead>
              <TableHead className="text-right">Errors</TableHead>
              <TableHead>Invalid answers</TableHead>
              <TableHead>Scrubbed records</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} className="text-center text-sm text-muted-foreground">
                  No upstream traffic in this window.
                </TableCell>
              </TableRow>
            )}
            {rows.map((r) => (
              <TableRow key={r.id}>
                <TableCell>
                  <SafeText>{names.get(r.id) ?? r.id}</SafeText>
                </TableCell>
                <TableCell className="text-right tabular-nums">{total ? formatPercent((r.queries ?? 0) / total) : "—"}</TableCell>
                <TableCell className="text-right tabular-nums">{formatCompact(r.hedges)}</TableCell>
                <TableCell className="text-right tabular-nums">{formatCompact(r.errors)}</TableCell>
                <TableCell className="text-xs">{byReason(r.invalid)}</TableCell>
                <TableCell className="text-xs">{byReason(r.scrubbed)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        <TimeSeriesChart
          ariaLabel="Upstream RTT"
          height={180}
          format={(v) => `${formatNumber(v, 1)} ms`}
          lines={lines.filter((l) => l.name.startsWith("upstream.rtt_ms."))}
          specs={[{ match: () => true, label: (l) => `${names.get(l.labels?.upstream ?? "") ?? l.labels?.upstream ?? ""} ${l.name.slice(-3)}` }]}
        />
        <p className="text-xs text-muted-foreground">
          Stale answers served: {formatCompact(stale)}. Padding removed from upstream answers (expected: DoT and DoH upstreams pad them): {formatCompact(padding)}. RTT lines are
          p50 and p99 per step.
        </p>
      </div>
    );
  }
  return (
    <Section
      title="Upstream health"
      description="Per upstream: query share, hedges, errors, invalid answers and records the scrub removed from valid ones by reason (padding, which DoT and DoH upstreams add to every answer, is counted below the table), and RTT."
    >
      {body}
    </Section>
  );
}

interface UpstreamRow {
  id: string;
  queries: number | null;
  hedges: number | null;
  errors: number | null;
  invalid: Record<string, number>;
  /** Records the scrub removed, by reason, without padding. */
  scrubbed: Record<string, number>;
  /** Padding options the scrub removed: expected on every padded DoT or DoH answer, so kept out of `scrubbed`. */
  padding: number | null;
}

export function upstreamRows(lines: ChartLine[]): UpstreamRow[] {
  const rows = new Map<string, UpstreamRow>();
  const get = (id: string) => {
    let r = rows.get(id);
    if (!r) {
      r = { id, queries: null, hedges: null, errors: null, invalid: {}, scrubbed: {}, padding: null };
      rows.set(id, r);
    }
    return r;
  };
  for (const l of lines) {
    const id = l.labels?.upstream;
    if (!id) continue;
    const s = sumLine(l);
    if (l.name === "upstream.queries") get(id).queries = s;
    else if (l.name === "upstream.hedges") get(id).hedges = s;
    else if (l.name === "upstream.errors") get(id).errors = s;
    else if (l.name === "upstream.scrubbed" && l.labels?.reason === "padding") {
      const r = get(id);
      if (s !== null) r.padding = (r.padding ?? 0) + s;
    } else if (l.name === "upstream.invalid" || l.name === "upstream.scrubbed") {
      const by = get(id)[l.name === "upstream.invalid" ? "invalid" : "scrubbed"];
      const reason = l.labels?.reason ?? "?";
      if (s) by[reason] = (by[reason] ?? 0) + s;
    } else get(id);
  }
  return [...rows.values()].sort((a, b) => (b.queries ?? 0) - (a.queries ?? 0));
}

function TopPanel({ kind, title, window, edge }: { kind: "blocked" | "allowed" | "clients"; title: string; window: Window; edge: string }) {
  const q = useQuery({
    queryKey: ["top", kind, window, edge],
    queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/top", { params: { query: { kind, window, edge, limit: 10 } }, signal })),
    refetchInterval: REFRESH,
  });
  const note =
    kind === "clients"
      ? "Devices over all logged records (each record's device, else its client)."
      : `Names in logged records whose decision is ${kind === "blocked" ? "block" : "allow"}.`;
  return (
    <Section title={title} description={note}>
      <QueryView query={q} what={title} rows={5} empty={<p className="text-sm text-muted-foreground">Nothing in this window.</p>} isEmpty={(d) => d.items.length === 0}>
        {(d) => (
          <ol className="space-y-1 text-sm">
            {d.items.map((it) => (
              <li key={it.key} className="flex items-center justify-between gap-2">
                {kind === "clients" ? (
                  <Link to="/clients/device" search={{ key: it.key, window, edge }} className="min-w-0 truncate font-mono text-xs hover:underline">
                    <SafeText>{it.key}</SafeText>
                  </Link>
                ) : (
                  <Link
                    to="/query-log"
                    search={{ qname: it.key, match: "exact", decision: kind === "blocked" ? "block" : "allow", window, edge }}
                    className="min-w-0 truncate font-mono text-xs hover:underline"
                  >
                    <SafeText>{it.key}</SafeText>
                  </Link>
                )}
                <span className="shrink-0 tabular-nums text-muted-foreground">{formatCompact(it.count)}</span>
              </li>
            ))}
          </ol>
        )}
      </QueryView>
      <p className="mt-3 text-xs text-muted-foreground">
        Only logged queries count: a profile with log: blocked adds no allowed names, one with log: off nothing, and records
        still spooled on an edge count once they arrive.
      </p>
    </Section>
  );
}
