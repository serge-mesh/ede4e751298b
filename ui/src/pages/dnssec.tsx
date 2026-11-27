import * as React from "react";
import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { PageHeader, Section, KeyValue } from "@/components/common/page";
import { ErrorState, LoadingState, PagedListError, QueryView } from "@/components/common/states";
import { JsonBlock, Mono, SafeText } from "@/components/common/text";
import { TimeAgo } from "@/components/common/time";
import { WindowPicker } from "@/components/common/window-picker";
import { MetricPanel } from "@/components/charts/metric-panel";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { qk, useAlerts, usePagedList, useSettings } from "@/api/queries";
import { client, unwrap } from "@/api/http";
import { useConnection } from "@/api/events";
import type { DnssecResult } from "@/api/types";
import { formatNumber, formatTime } from "@/lib/format";
import { escapeControl } from "@/lib/text";
import { useWindowState } from "./dashboard";

const OUTCOMES = ["bogus", "indeterminate", "insecure", "secure"] as const;
type Outcome = (typeof OUTCOMES)[number];
const ALL = "__all__";

/**
 * How often open results read again while the event socket is down. While it is open, core's
 * `dnssec` event says when results were stored (api/events.ts), so they don't poll; they read once
 * more when it first opens (api/events.ts keptByEvents).
 */
export const DNSSEC_RESULTS_POLL = 60_000;

/**
 * How often the queue reads again while the event socket is down. While it is open, every change
 * to the queue sends an event (api/events.ts): `dnssec_queued` for checks queued, joined, retried,
 * waiting, cross-checks retried or ended, items dropped or stamped; `dnssec` for stored results.
 * It reads once more when the socket first opens (api/events.ts keptByEvents).
 */
export const DNSSEC_QUEUE_POLL = 60_000;

/** `GET dnssec/results?outcome&cursor&limit`: results in the retention window, newest first. */
function useDnssecResults(outcome: Outcome | undefined) {
  const live = useConnection() === "open";
  return usePagedList({
    queryKey: [...qk.dnssecResults, outcome ?? "all"],
    fetchPage: (cursor, signal) => unwrap(client.GET("/api/ui/v1/dnssec/results", { params: { query: { outcome, cursor, limit: 100 } }, signal })),
    rowKey: (r) => String(r.id),
    interval: live ? undefined : DNSSEC_RESULTS_POLL,
  });
}

const list = (v: string[]) => (v.length ? v.map(escapeControl).join(", ") : "—");

/** DNSSEC: queue and recent Bogus results (core.md §12; validation in core.md §8). */
export function DnssecPage() {
  const { window, allowed, setWindow } = useWindowState("metrics");
  const settings = useSettings();
  const live = useConnection() === "open";
  const queue = useQuery({
    queryKey: qk.dnssecQueue,
    queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/dnssec/queue", { signal })),
    refetchInterval: live ? false : DNSSEC_QUEUE_POLL,
  });
  const [outcome, setOutcome] = React.useState<Outcome | typeof ALL>("bogus");
  const results = useDnssecResults(outcome === ALL ? undefined : outcome);
  const alerts = useAlerts({ kind: "dnssec_bogus" });
  const d = settings.data?.settings.dnssec;
  const crosscheckOn = settings.data?.settings.crosscheck?.enabled === true;
  const bogusAlerts = alerts.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <div className="space-y-4">
      <PageHeader
        title="DNSSEC"
        description="Core validates the signed answers edges log, asynchronously, fetching chains through an edge's DoH listener under the dnssec-validator profile. Edges never validate."
        actions={<WindowPicker value={window} onChange={setWindow} allowed={allowed} />}
      />
      <div className="grid gap-4 lg:grid-cols-3">
        <Section title="Validation settings" actions={<Link to="/settings" search={{ tab: "dnssec" }} className="text-sm text-primary hover:underline">Change</Link>}>
          {d ? (
            <KeyValue
              items={[
                ["Enabled", d.enabled === false ? <Badge variant="outline">off</Badge> : <Badge variant="success">on</Badge>],
                ["Listener", d.listener ? <Mono>{d.listener}</Mono> : "the first DoH listener on a connected edge"],
                ["Source addresses", d.source_ips?.length ? <SafeText mono>{d.source_ips.join(", ")}</SafeText> : "core's own addresses"],
                ["Requests per minute", d.max_per_minute ?? 120],
                ["Dedupe window", d.dedupe_window ?? "1d"],
              ]}
            />
          ) : (
            <span className="text-sm text-muted-foreground">…</span>
          )}
        </Section>
        <MetricPanel className="lg:col-span-2" title="Validation queue" series={["queue_depth"]} window={window} edge="all" transform={(ls) => ls.filter((l) => l.labels?.queue === "dnssec")} specs={[{ match: () => true, label: "dnssec queue" }]} />
      </div>
      <Section title="Queue" description="Checks waiting for a network request (chain lookups and fallback queries), earliest due first, paced by the requests-per-minute limit. While no edge DoH listener is reachable, they wait without using attempts.">
        <QueryView query={queue} what="The DNSSEC queue" rows={4}>
          {(q) => (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                {formatNumber(q.depth)} queued{q.items.length < q.depth ? `; the first ${formatNumber(q.items.length)} shown` : ""}.
              </p>
              {q.items.length > 0 && (
                <Table aria-label="DNSSEC queue">
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Kind</TableHead>
                      <TableHead className="text-right">Records</TableHead>
                      <TableHead className="text-right">Attempts</TableHead>
                      <TableHead>Next</TableHead>
                      <TableHead>As of</TableHead>
                      <TableHead>Edges</TableHead>
                      <TableHead>Clients</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {q.items.map((it, i) => (
                      <TableRow key={i}>
                        <TableCell>
                          <SafeText mono>{it.qname}</SafeText> <span className="text-xs text-muted-foreground">{escapeControl(it.qtype)}</span>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" title={KIND_TEXT[it.kind]}>
                            {escapeControl(it.kind)}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right tabular-nums">{formatNumber(it.records)}</TableCell>
                        <TableCell className="text-right tabular-nums">{it.attempts}</TableCell>
                        <TableCell className="whitespace-nowrap text-xs">{it.next_at ? <TimeAgo value={it.next_at} /> : "—"}</TableCell>
                        <TableCell className="whitespace-nowrap text-xs">{it.received_at ? formatTime(it.received_at) : "now (core's own query)"}</TableCell>
                        <TableCell className="text-xs">{list(it.edges)}</TableCell>
                        <TableCell className="text-xs">{list(it.clients)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
              {(q.crosscheck_depth > 0 || crosscheckOn) && (
                <div className="space-y-1 border-t pt-3">
                  <h3 className="text-sm font-medium">Cross-check queue: {formatNumber(q.crosscheck_depth)}</h3>
                  <ul className="space-y-1 text-sm">
                    {q.crosscheck_items.map((c, i) => (
                      <li key={i} className="flex flex-wrap items-center gap-2">
                        <SafeText mono>{c.qname}</SafeText> <span className="text-xs text-muted-foreground">{escapeControl(c.qtype)}</span>
                        <Badge variant="outline">{escapeControl(c.kind)}</Badge>
                        {c.attempts ? <span className="text-xs">{formatNumber(c.attempts)} failed {c.attempts === 1 ? "query" : "queries"}</span> : null}
                        <span className="text-xs text-muted-foreground">
                          queued <TimeAgo value={c.queued_at} />, next <TimeAgo value={c.next_at} />
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </QueryView>
      </Section>
      <Section
        title="Results"
        description="Each Bogus result names the zone where validation broke, the RFC 8914 code 1.1.1.1 would return, hickory's proof error, the validator's upstream group, and the edges, clients and upstream groups of the records."
        actions={
          <Select value={outcome} onValueChange={(v) => setOutcome(v as Outcome | typeof ALL)}>
            <SelectTrigger size="sm" aria-label="Outcome" className="w-40">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL}>Every outcome</SelectItem>
              {OUTCOMES.map((o) => (
                <SelectItem key={o} value={o}>
                  {o}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        }
      >
        {results.data === undefined ? (
          results.error ? (
            <ErrorState error={results.error} onRetry={() => void results.refetch()} />
          ) : (
            <LoadingState rows={4} />
          )
        ) : (
          <div className="space-y-3">
            <PagedListError query={results} placement="top" what="older results" />
            <DnssecResults items={results.data.pages.flatMap((p) => p.items)} />
            <PagedListError query={results} placement="bottom" what="older results" />
            {results.hasNextPage && (
              <Button variant="outline" onClick={() => void results.fetchNextPage()} disabled={results.isFetching}>
                Load older results
              </Button>
            )}
          </div>
        )}
      </Section>
      <Section title="dnssec_bogus alerts" description="One per zone where validation broke; the evidence keeps the validator's DNSKEY and DS answers.">
        {bogusAlerts.length === 0 ? (
          <p className="text-sm text-muted-foreground">None.</p>
        ) : (
          <ul className="space-y-2">
            {bogusAlerts.map((a) => (
              <li key={a.id} className="text-sm">
                <Link to="/alerts/$alertId" params={{ alertId: String(a.id) }} className="font-medium hover:underline">
                  <SafeText>{a.title}</SafeText>
                </Link>{" "}
                <Badge variant={a.state === "open" ? "outline" : "secondary"}>{a.state}</Badge> <TimeAgo value={a.last_seen} className="text-xs text-muted-foreground" />
                <JsonBlock value={a.details} className="mt-1 max-h-32" />
              </li>
            ))}
          </ul>
        )}
      </Section>
    </div>
  );
}

const KIND_TEXT: Record<string, string> = {
  answer: "A logged answer, validated as of the time the edge received it",
  fallback: "Core's own query: the logged answer is unknown (truncated, missing, or a reply the edge made)",
  servfail: "An upstream SERVFAIL's query, checked once and never retried",
};

function DnssecResults({ items }: { items: DnssecResult[] }) {
  if (items.length === 0) return <p className="text-sm text-muted-foreground">None in the retention window.</p>;
  return (
    <ul className="space-y-2 text-sm" aria-label="DNSSEC results">
      {items.map((b) => (
        <li key={b.id} className="rounded-md border p-2">
          <div className="flex flex-wrap items-center gap-2">
            <SafeText mono>{b.name}</SafeText>
            <span className="text-xs text-muted-foreground">{escapeControl(b.qtype)}</span>
            <Badge variant={b.outcome === "bogus" ? "destructive" : b.outcome === "secure" ? "success" : "outline"}>{escapeControl(b.outcome)}</Badge>
            {b.kind && <Badge variant="outline">{escapeControl(b.kind)}</Badge>}
            {b.ede !== null && b.ede !== undefined && (
              <Badge variant="destructive">
                EDE {b.ede}
                {b.ede_text ? ` ${escapeControl(b.ede_text)}` : ""}
              </Badge>
            )}
            <TimeAgo value={b.at} className="text-xs text-muted-foreground" />
          </div>
          <dl className="mt-1 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs">
            {b.zone && (
              <>
                <dt className="text-muted-foreground">Zone</dt>
                <dd className="min-w-0 break-words">
                  <SafeText mono>{b.zone}</SafeText>
                </dd>
              </>
            )}
            {b.proof && (
              <>
                <dt className="text-muted-foreground">Proof</dt>
                <dd className="min-w-0 break-words">
                  <SafeText>{b.proof}</SafeText>
                </dd>
              </>
            )}
            <dt className="text-muted-foreground">Validator group</dt>
            <dd>
              <SafeText mono>{b.group}</SafeText>
            </dd>
            <dt className="text-muted-foreground">Answered by</dt>
            <dd className="min-w-0 break-words">{list(b.groups)}</dd>
            <dt className="text-muted-foreground">Edges</dt>
            <dd className="min-w-0 break-words">{list(b.edges)}</dd>
            <dt className="text-muted-foreground">Clients</dt>
            <dd className="min-w-0 break-words">{list(b.clients)}</dd>
            <dt className="text-muted-foreground">As of</dt>
            <dd>{b.received_at ? formatTime(b.received_at) : "the time of core's own query"}</dd>
          </dl>
        </li>
      ))}
    </ul>
  );
}
