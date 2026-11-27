import * as React from "react";
import { Link, useNavigate, useParams, useSearch } from "@tanstack/react-router";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { HammerIcon, SearchIcon } from "lucide-react";
import { KeyValue, PageHeader, Section, Stat } from "@/components/common/page";
import { ErrorState, LoadingState, QueryView } from "@/components/common/states";
import { JsonBlock, Mono, SafeText } from "@/components/common/text";
import { TimeAgo } from "@/components/common/time";
import { CopyField } from "@/components/common/copy-button";
import { EntityForm } from "@/components/common/entity-editor";
import { EdgeSelector, WindowPicker } from "@/components/common/window-picker";
import { MetricPanel } from "@/components/charts/metric-panel";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { JobBadge } from "@/components/common/job-progress";
import { qk, useEdges, useEntity } from "@/api/queries";
import { JOB_KIND, reportOver, useConnection, useJobReports, type JobReport } from "@/api/events";
import { nextOrder, ordered, readOrder } from "@/api/order";
import { client, unwrap } from "@/api/http";
import { errorMessage } from "@/api/errors";
import type { BundleDef, BundleDetail, Explanation } from "@/api/types";
import { formatBytes, formatNumber, formatPercent, formatTime } from "@/lib/format";
import { escapeControl } from "@/lib/text";
import { cn } from "@/lib/utils";
import { BuildBadge, useBundleFormProps } from "./bundles";
import { SeverityBadge } from "./alerts";
import { useWindowState } from "./dashboard";

export function BundleDetailPage() {
  const { bundleId } = useParams({ strict: false }) as { bundleId: string };
  const search = useSearch({ strict: false }) as { tab?: string };
  const navigate = useNavigate();
  const def = useEntity("bundles", bundleId);
  /** Build now, from the click (before the request is sent): its build's progress shows from then (`job` events). */
  const [ask, setAsk] = React.useState<BuildAsk | null>(null);
  const live = useConnection() === "open";
  const report = useJobReports(ask?.at ?? null, (j) => j.kind === JOB_KIND.build && j.target === bundleId).at(-1);
  const detail = useQuery<BundleDetail>({
    queryKey: qk.bundle(bundleId, "status"),
    // Each answer with when its read was sent (api/order.ts), to tell when the build asked for ended.
    queryFn: ordered((signal) => unwrap(client.GET("/api/ui/v1/bundles/{id}/status", { params: { path: { id: bundleId } }, signal }))),
    structuralSharing: false,
    // The build's start and end refresh it, and a reconnect, `lagged` or a `job` event's `dropped`
    // re-read it (api/events.ts); while the event socket is down, a build asked for is followed by
    // polling until it ends, and it reads once more when the socket first opens (keptByEvents).
    refetchInterval: (q) => (ask !== null && !live && !buildOver(ask, report, q.state.data) ? 3000 : false),
  });
  const qc = useQueryClient();
  const build = useMutation({
    mutationFn: () => unwrap(client.POST("/api/ui/v1/bundles/{id}/build", { params: { path: { id: bundleId } } })),
    onSuccess: (r) => {
      toast.success(r.queued ? "Build queued (heavy lane, P0)" : "A build is already queued");
      // Before the reads below: a read sent from here on shows the build asked for (or its end).
      const answered = nextOrder();
      setAsk((a) => (a ? { ...a, answered } : a));
      void qc.invalidateQueries({ queryKey: ["bundles"] });
    },
    onError: (e) => {
      setAsk(null);
      toast.error(errorMessage(e));
    },
  });
  const tab = search.tab ?? "overview";
  // Once loaded, a failed refetch keeps the page (and the entity form's draft) mounted; the form says so (core.md §12).
  if (def.data === undefined) return def.error ? <ErrorState error={def.error} onRetry={() => void def.refetch()} /> : <LoadingState rows={8} />;
  const b = def.data;
  const action = b.action ?? "block";
  return (
    <div className="space-y-4">
      <PageHeader
        title={
          <span>
            <Mono className="text-2xl">{b.id}</Mono>
          </span>
        }
        description={
          <span className="flex flex-wrap items-center gap-2">
            {b.name && <SafeText>{b.name}</SafeText>}
            <Badge variant="outline">{action}</Badge>
            {b.system && <Badge variant="outline">system</Badge>}
            {detail.data && <BuildBadge s={detail.data} />}
          </span>
        }
        actions={
          action !== "warn" && action !== "scope" ? (
            <Button
              variant="outline"
              onClick={() => {
                // Followed from before the request: a fast build's start and end may come before its answer.
                setAsk({ at: Date.now(), answered: null });
                build.mutate();
              }}
              disabled={build.isPending}
            >
              <HammerIcon /> Build now
            </Button>
          ) : undefined
        }
      />
      {ask !== null && <BuildProgress report={report} status={detail.data} ask={ask} />}
      <Tabs value={tab} onValueChange={(t) => void navigate({ to: ".", search: { tab: t }, replace: true })}>
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="feeds">Feeds</TabsTrigger>
          <TabsTrigger value="shards">Shards</TabsTrigger>
          <TabsTrigger value="versions">Versions</TabsTrigger>
          <TabsTrigger value="warnings">{action === "allow" ? "Overrides and warnings" : "Warnings"}</TabsTrigger>
          <TabsTrigger value="explain">Explain</TabsTrigger>
          {action === "block" && <TabsTrigger value="cold">Cold hits</TabsTrigger>}
          <TabsTrigger value="settings">Settings</TabsTrigger>
        </TabsList>
        <TabsContent value="overview">
          <QueryView query={detail} rows={6}>
            {(d) => <Overview bundle={b} d={d} />}
          </QueryView>
        </TabsContent>
        <TabsContent value="feeds">
          <FeedsTab bundle={b} d={detail.data} />
        </TabsContent>
        <TabsContent value="shards">
          <QueryView query={detail} rows={6}>
            {(d) => <Shards d={d} />}
          </QueryView>
        </TabsContent>
        <TabsContent value="versions">
          <Versions id={bundleId} />
        </TabsContent>
        <TabsContent value="warnings">
          <Warnings id={bundleId} action={action} />
        </TabsContent>
        <TabsContent value="explain">
          <Explain id={bundleId} />
        </TabsContent>
        <TabsContent value="cold">
          <ColdHits id={bundleId} />
        </TabsContent>
        <TabsContent value="settings">
          <Section title="Bundle settings">
            <BundleSettings bundle={b} onDeleted={() => void navigate({ to: "/bundles" })} />
          </Section>
        </TabsContent>
      </Tabs>
    </div>
  );
}

/** Build now: when it was clicked, and when its request was answered in the page's order of reports and reads (api/order.ts; null until then). */
interface BuildAsk {
  at: number;
  answered: number | null;
}

/**
 * The build asked for is over by the bundle's status: `building` holds from a build's request to
 * its end (compiler `busy`), so a status read sent after the request was answered, and after the
 * build's newest report, that shows no build running or waiting means it ended, whether or not its
 * `job` events came (api.md §7: a report can be missed).
 */
function buildOver(ask: BuildAsk, report: JobReport | undefined, status: BundleDetail | undefined): boolean {
  if (report?.phase === "end") return true;
  if (!status || ask.answered === null) return false;
  const read = readOrder(status);
  if (read <= ask.answered) return false;
  return report ? reportOver(report, read, status.building) : !status.building;
}

/**
 * The build Build now asked for: queued until its `job` event says it started, then how it ended
 * (outcome and duration). When its events don't come (the socket was down, core dropped them), a
 * status read after them tells when it ended.
 */
function BuildProgress({ report, status, ask }: { report?: JobReport; status?: BundleDetail; ask: BuildAsk }) {
  let state: React.ReactNode;
  let failed = false;
  const over = buildOver(ask, report, status);
  if (report && (report.phase === "end" || !over)) {
    state = <JobBadge j={report} />;
    failed = report.phase === "end" && report.outcome === "failed";
  } else if (status && over) {
    failed = status.status === "failed";
    state = <Badge variant={failed ? "destructive" : "success"}>{failed ? "failed" : "done"}</Badge>;
  } else state = <Badge variant="secondary">queued</Badge>;
  return (
    <p className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground" aria-label="Build progress">
      Build asked for at {formatTime(ask.at)}: {state}
      {failed ? " The Overview tab shows the error." : ""}
    </p>
  );
}

function BundleSettings({ bundle, onDeleted }: { bundle: BundleDef; onDeleted: () => void }) {
  const props = useBundleFormProps(bundle.action ?? "block");
  return <EntityForm kind="bundles" id={bundle.id} {...props} onDeleted={onDeleted} deleteDescription="Profiles that list it lose it." />;
}

function num(stats: unknown, key: string): number | null {
  const v = stats && typeof stats === "object" ? (stats as Record<string, unknown>)[key] : undefined;
  return typeof v === "number" ? v : null;
}

function Overview({ bundle, d }: { bundle: BundleDef; d: BundleDetail }) {
  const edges = useEdges();
  const edgeName = new Map((edges.data ?? []).map((e) => [e.id ?? "", e.name || e.id || ""]));
  const s = d.stats;
  return (
    <div className="space-y-4">
      {d.error && (
        <Section title="Last build failed">
          <SafeText multiline>{d.error}</SafeText>
        </Section>
      )}
      {(bundle.action ?? "block") === "block" && (
        <div className="grid gap-3 sm:grid-cols-4">
          <Stat label="Hot keys" value={formatNumber(num(s, "hot_keys"))} hint={formatBytes(num(s, "hot_bytes"))} />
          <Stat label="Cold keys" value={formatNumber(num(s, "cold_keys"))} hint={`${formatBytes(num(s, "cold_page_bytes"))} pages, ${formatBytes(num(s, "cold_filter_bytes"))} filter`} />
          <Stat label="Edge memory" value={formatBytes(num(s, "edge_mem_bytes"))} hint={bundle.hot_max_mib ? `hot cap ${bundle.hot_max_mib} MiB` : "no hot cap"} />
          <Stat label="Shards" value={formatNumber(num(s, "shards"))} hint={`max ${formatNumber(bundle.max_shard_keys ?? 1_000_000)} keys each`} />
        </div>
      )}
      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="Build">
          <KeyValue
            items={[
              ["Status", <BuildBadge s={d} />],
              ["Built", d.built_at ? formatTime(d.built_at) : "—"],
              ["Head", d.head ? <Mono>{d.head.slice(0, 16)}</Mono> : "none"],
              ["Open alerts", d.open_alerts],
              ["Browser list", d.browser_list ? <CopyField value={`${window.location.origin}${d.browser_list}`} label="Copy the browser-list URL" /> : "—"],
              ["Feed runs read", Object.entries(d.feed_runs ?? {}).map(([f, r]) => `${escapeControl(f)}#${r}`).join(", ") || "—"],
            ]}
          />
        </Section>
        <Section title="Heads edges are named">
          {Object.keys(d.edges ?? {}).length === 0 ? (
            <p className="text-sm text-muted-foreground">No edge config names this bundle.</p>
          ) : (
            <ul className="space-y-1 text-sm">
              {Object.entries(d.edges).map(([e, h]) => (
                <li key={e} className="flex justify-between gap-2">
                  <SafeText>{edgeName.get(e) ?? e}</SafeText>
                  <span>
                    <Mono>{String(h).slice(0, 16)}</Mono> {d.head && h !== d.head && <Badge variant="warning">behind</Badge>}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Section>
      </div>
      {d.dry_run && <DryRunView run={d.dry_run} />}
      <Section title="Last build's counts and sizes">
        <StatsTable stats={s} />
      </Section>
    </div>
  );
}

/**
 * The tiering dry run (bundles.md §2 Tiering): before a split or tier change, how many of the
 * window's blocks would have come from keys the proposal puts cold. The split waits for it, or
 * for a bounded hold.
 */
function DryRunView({ run }: { run: NonNullable<BundleDetail["dry_run"]> }) {
  const share = run.blocks && run.cold_blocks !== null && run.cold_blocks !== undefined ? run.cold_blocks / run.blocks : null;
  return (
    <Section title="Tiering dry run" description="Before a split or tier change, core replays the log window: the blocks that would have come from keys the proposal puts cold.">
      <div className="space-y-3" data-testid="dry-run">
        <KeyValue
          items={[
            ["Status", <Badge variant={run.status === "done" ? "success" : run.status === "failed" ? "destructive" : "outline"}>{escapeControl(run.status)}</Badge>],
            ["Blocks in the window", run.blocks === null || run.blocks === undefined ? "—" : formatNumber(run.blocks)],
            ["From keys that would be cold", run.cold_blocks === null || run.cold_blocks === undefined ? "—" : `${formatNumber(run.cold_blocks)}${share !== null ? ` (${formatPercent(share)})` : ""}`],
            ["Window", run.window_from && run.window_to ? `${formatTime(run.window_from)} – ${formatTime(run.window_to)}` : "—"],
            ["Started", formatTime(run.started_at)],
            ["Finished", run.finished_at ? formatTime(run.finished_at) : "—"],
            ...(run.error ? ([["Error", <SafeText multiline>{run.error}</SafeText>]] as [string, React.ReactNode][]) : []),
          ]}
        />
        <div className="grid gap-3 md:grid-cols-2">
          <div className="min-w-0">
            <h4 className="mb-1 text-xs font-medium text-muted-foreground">Proposed</h4>
            <JsonBlock value={run.proposed} className="max-h-48" />
          </div>
          {run.detail !== undefined && run.detail !== null && (
            <div className="min-w-0">
              <h4 className="mb-1 text-xs font-medium text-muted-foreground">Per tier, and the most-blocked cold keys</h4>
              <JsonBlock value={run.detail} className="max-h-48" />
            </div>
          )}
        </div>
      </div>
    </Section>
  );
}

function StatsTable({ stats }: { stats: unknown }) {
  if (!stats || typeof stats !== "object") return <p className="text-sm text-muted-foreground">None.</p>;
  const entries = Object.entries(stats as Record<string, unknown>);
  const text = (k: string, v: unknown) => (typeof v === "number" ? (/bytes/.test(k) ? formatBytes(v) : formatNumber(v)) : escapeControl(typeof v === "string" ? v : JSON.stringify(v)));
  // Short values in columns; a long one (a digest, a list of reasons, an object) on a row of its
  // own that wraps anywhere, so no value widens the grid past the page (1280–1440 px included).
  const long = (k: string, v: unknown) => typeof v === "object" || text(k, v).length > 24;
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-1 text-sm sm:grid-cols-2 lg:grid-cols-3" data-testid="bundle-stats">
      {entries.map(([k, v]) => (
        <div key={k} className={cn("flex min-w-0 gap-2 border-b py-1", long(k, v) ? "flex-col sm:col-span-2 lg:col-span-3" : "justify-between")}>
          <dt className="shrink-0 font-mono text-xs text-muted-foreground">{escapeControl(k)}</dt>
          <dd className={cn("min-w-0 text-xs tabular-nums break-all", long(k, v) ? "font-mono" : "text-right")}>{text(k, v)}</dd>
        </div>
      ))}
    </dl>
  );
}

function FeedsTab({ bundle, d }: { bundle: BundleDef; d?: BundleDetail }) {
  const block = (bundle.action ?? "block") === "block";
  return (
    <Section title="Feeds" description={block ? "With the rule types taken from each and its tier: hot keys load into RAM; cold keys stay in page files on the SSD." : "With the rule types taken from each."}>
      {(bundle.feeds ?? []).length === 0 ? (
        <p className="text-sm text-muted-foreground">No feeds. Add them under Settings.</p>
      ) : (
        <Table aria-label="Bundle feeds">
          <TableHeader>
            <TableRow>
              <TableHead>Feed</TableHead>
              <TableHead>Rule types</TableHead>
              {block && <TableHead>Tier</TableHead>}
              <TableHead>Run read</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {(bundle.feeds ?? []).map((f) => (
              <TableRow key={f.feed}>
                <TableCell>
                  <Link to="/feeds/$feedId" params={{ feedId: f.feed ?? "" }} className="hover:underline">
                    <Mono>{f.feed}</Mono>
                  </Link>
                </TableCell>
                <TableCell>{f.rule_types ? f.rule_types.join(", ") : <span className="text-muted-foreground">every type it stores</span>}</TableCell>
                {block && <TableCell>{f.tier ?? "hot"}</TableCell>}
                <TableCell className="tabular-nums">{d?.feed_runs?.[f.feed ?? ""] ?? "—"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      {block && <p className="mt-3 text-xs text-muted-foreground">Before a split or tier change, the dry run's count of blocks that would have come from cold shows in the build's counts once core reports it.</p>}
    </Section>
  );
}

function Shards({ d }: { d: BundleDetail }) {
  return (
    <div className="space-y-4">
      <Section title="Shards" description="Per shard: part, keys, base, chain length, overlay entries and sizes.">
        {d.shards.length === 0 ? (
          <p className="text-sm text-muted-foreground">None.</p>
        ) : (
          <Table aria-label="Shards">
            <TableHeader>
              <TableRow>
                <TableHead>Part</TableHead>
                <TableHead>Shard</TableHead>
                <TableHead className="text-right">Keys</TableHead>
                <TableHead className="text-right">Deltas</TableHead>
                <TableHead className="text-right">Overlay entries</TableHead>
                <TableHead className="text-right">Memory</TableHead>
                <TableHead className="text-right">Disk</TableHead>
                <TableHead>Base</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {d.shards.map((s) => (
                <TableRow key={`${s.part}-${s.shard}`}>
                  <TableCell>{s.part}</TableCell>
                  <TableCell className="tabular-nums">{s.shard}</TableCell>
                  <TableCell className="text-right tabular-nums">{formatNumber(s.keys)}</TableCell>
                  <TableCell className="text-right tabular-nums">{s.deltas}</TableCell>
                  <TableCell className="text-right tabular-nums">{formatNumber(s.overlay_entries)}</TableCell>
                  <TableCell className="text-right tabular-nums">{formatBytes(s.mem_bytes)}</TableCell>
                  <TableCell className="text-right tabular-nums">{formatBytes(s.disk_bytes)}</TableCell>
                  <TableCell>
                    <Mono>{(s.base ?? "").slice(0, 12)}</Mono>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Section>
      <Section title="IP shards" description="IPv4 by first octet, IPv6 as one.">
        {d.ip_shards.length === 0 ? (
          <p className="text-sm text-muted-foreground">None.</p>
        ) : (
          <Table aria-label="IP shards">
            <TableHeader>
              <TableRow>
                <TableHead>IP shard</TableHead>
                <TableHead className="text-right">Runs</TableHead>
                <TableHead className="text-right">Deltas</TableHead>
                <TableHead className="text-right">Overlay entries</TableHead>
                <TableHead className="text-right">Memory</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {d.ip_shards.map((s) => (
                <TableRow key={s.ip_shard}>
                  <TableCell>{s.ip_shard}</TableCell>
                  <TableCell className="text-right tabular-nums">{formatNumber(s.runs)}</TableCell>
                  <TableCell className="text-right tabular-nums">{s.deltas}</TableCell>
                  <TableCell className="text-right tabular-nums">{formatNumber(s.overlay_entries)}</TableCell>
                  <TableCell className="text-right tabular-nums">{formatBytes(s.mem_bytes)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Section>
    </div>
  );
}

function Versions({ id }: { id: string }) {
  const q = useInfiniteQuery({
    queryKey: qk.bundle(id, "versions"),
    queryFn: ({ pageParam, signal }) => unwrap(client.GET("/api/ui/v1/bundles/{id}/versions", { params: { path: { id }, query: { cursor: pageParam, limit: 50 } }, signal })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (p) => p.next_cursor ?? undefined,
  });
  const [open, setOpen] = React.useState<string | null>(null);
  const items = q.data?.pages.flatMap((p) => p.items) ?? [];
  if (q.isPending) return <LoadingState rows={6} />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  return (
    <Section title="Versions" description="Newest first, with each version's stats.">
      <Table aria-label="Versions">
        <TableHeader>
          <TableRow>
            <TableHead>Head</TableHead>
            <TableHead>Published</TableHead>
            <TableHead className="text-right">Keys added</TableHead>
            <TableHead className="text-right">Deleted</TableHead>
            <TableHead>Last used</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.length === 0 && (
            <TableRow>
              <TableCell colSpan={5} className="text-center text-sm text-muted-foreground">
                No versions yet.
              </TableCell>
            </TableRow>
          )}
          {items.map((v) => (
            <React.Fragment key={v.head}>
              <TableRow className="cursor-pointer" tabIndex={0} onClick={() => setOpen(open === v.head ? null : v.head)} onKeyDown={(e) => e.key === "Enter" && setOpen(open === v.head ? null : v.head)}>
                <TableCell>
                  <Mono>{v.head.slice(0, 16)}</Mono> {v.current && <Badge variant="secondary">current</Badge>}
                </TableCell>
                <TableCell className="text-xs">{formatTime(v.published_at)}</TableCell>
                <TableCell className="text-right tabular-nums">{formatNumber(num(v.stats, "keys_added"))}</TableCell>
                <TableCell className="text-right tabular-nums">{formatNumber(num(v.stats, "keys_deleted"))}</TableCell>
                <TableCell>
                  <TimeAgo value={v.last_used_at} />
                </TableCell>
              </TableRow>
              {open === v.head && (
                <TableRow>
                  <TableCell colSpan={5}>
                    <StatsTable stats={v.stats} />
                  </TableCell>
                </TableRow>
              )}
            </React.Fragment>
          ))}
        </TableBody>
      </Table>
      {q.hasNextPage && (
        <Button className="mt-3" variant="outline" onClick={() => void q.fetchNextPage()} disabled={q.isFetching}>
          Load more
        </Button>
      )}
    </Section>
  );
}

/**
 * A bundle's warnings, page by page (api.md §7 cursors): `GET bundles/{id}/warnings` returns its
 * open alerts and one page of `warnings`, with `next_cursor` for the next.
 */
export function useBundleWarnings(id: string) {
  return useInfiniteQuery({
    queryKey: qk.bundle(id, "warnings"),
    queryFn: ({ pageParam, signal }) =>
      unwrap(client.GET("/api/ui/v1/bundles/{id}/warnings", { params: { path: { id }, query: { cursor: pageParam, limit: 100 } }, signal })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (p) => p.warnings.next_cursor ?? undefined,
  });
}

/** Every page of warnings loaded so far, with a Load more button while core has more. */
export function WarningPages({ q }: { q: ReturnType<typeof useBundleWarnings> }) {
  const items = q.data?.pages.flatMap((p) => p.warnings.items) ?? [];
  if (items.length === 0) return <p className="text-sm text-muted-foreground">None.</p>;
  return (
    <>
      <WarningTable items={items} />
      {q.hasNextPage && (
        <Button className="mt-3" variant="outline" onClick={() => void q.fetchNextPage()} disabled={q.isFetching}>
          Load more
        </Button>
      )}
    </>
  );
}

function Warnings({ id, action }: { id: string; action: string }) {
  const q = useBundleWarnings(id);
  return (
    <QueryView query={q} rows={5}>
      {(w) => (
        <div className="space-y-4">
          <Section title="Open guardrail and build alerts">
            {(w.pages[0]?.alerts ?? []).length === 0 ? (
              <p className="text-sm text-muted-foreground">None.</p>
            ) : (
              <ul className="space-y-1.5">
                {(w.pages[0]?.alerts ?? []).map((a) => (
                  <li key={a.id} className="flex items-center gap-2 text-sm">
                    <SeverityBadge severity={a.severity} />
                    <Link to="/alerts/$alertId" params={{ alertId: String(a.id) }} className="hover:underline">
                      <SafeText>{a.title}</SafeText>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Section>
          <Section
            title={action === "allow" ? "Block entries this bundle's downloaded feeds override" : action === "warn" ? "Warnings this warninglist found" : "Compile-time warnings on its entries"}
            description="A warning resolves on its own once its cause is gone."
          >
            <WarningPages q={q} />
          </Section>
        </div>
      )}
    </QueryView>
  );
}

export function WarningTable({ items }: { items: { id: number; kind: string; value: string; raw?: string | null; feed?: string | null; bundle?: string | null; by_bundle?: string | null; by_feed?: string | null; first_seen: string; status: string }[] }) {
  return (
    <Table aria-label="Warnings">
      <TableHeader>
        <TableRow>
          <TableHead>Kind</TableHead>
          <TableHead>Value</TableHead>
          <TableHead>Block entry</TableHead>
          <TableHead>In</TableHead>
          <TableHead>Matched by</TableHead>
          <TableHead>Since</TableHead>
          <TableHead>Status</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {items.map((x) => (
          <TableRow key={x.id}>
            <TableCell>
              <Badge variant="outline">{x.kind}</Badge>
            </TableCell>
            <TableCell>
              <SafeText mono>{x.value}</SafeText>
            </TableCell>
            <TableCell>
              <SafeText mono>{x.raw}</SafeText>
            </TableCell>
            <TableCell className="text-xs">
              <SafeText>{[x.feed, x.bundle].filter(Boolean).join(" in ")}</SafeText>
            </TableCell>
            <TableCell className="text-xs">
              <SafeText>{[x.by_feed, x.by_bundle].filter(Boolean).join(" in ")}</SafeText>
            </TableCell>
            <TableCell>
              <TimeAgo value={x.first_seen} />
            </TableCell>
            <TableCell>{x.status}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function Explain({ id }: { id: string }) {
  const [name, setName] = React.useState("");
  const [qtype, setQtype] = React.useState("A");
  const [clientIp, setClientIp] = React.useState("");
  const [result, setResult] = React.useState<Explanation | null>(null);
  const m = useMutation({
    mutationFn: () =>
      unwrap(
        client.GET("/api/ui/v1/bundles/{id}/explain", {
          params: { path: { id }, query: { name: name.trim(), qtype: qtype || undefined, client_ip: clientIp || undefined } },
        }),
      ),
    onSuccess: setResult,
    onError: (e) => toast.error(errorMessage(e)),
  });
  return (
    <Section title="Explain" description="How the bundle's current rules decide a name or an address (the reference matcher, against the feeds as they stand now).">
      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (name.trim()) m.mutate();
        }}
      >
        <div className="space-y-1.5">
          <Label htmlFor="ex-name">Name or address</Label>
          <Input id="ex-name" value={name} onChange={(e) => setName(e.target.value)} className="w-72 font-mono" placeholder="ads.example.com" />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="ex-qtype">Query type</Label>
          <Input id="ex-qtype" value={qtype} onChange={(e) => setQtype(e.target.value)} className="w-24 font-mono" />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="ex-client">Client address (optional)</Label>
          <Input id="ex-client" value={clientIp} onChange={(e) => setClientIp(e.target.value)} className="w-48 font-mono" />
        </div>
        <Button type="submit" disabled={!name.trim() || m.isPending}>
          <SearchIcon /> Explain
        </Button>
      </form>
      {result && (
        <div className="mt-4 space-y-3">
          <KeyValue
            items={[
              ["Outcome", <Mono>{typeof result.outcome === "string" ? result.outcome : JSON.stringify(result.outcome)}</Mono>],
              ["Step", result.step ?? "—"],
            ]}
          />
          {result.matches.length === 0 ? (
            <p className="text-sm text-muted-foreground">No rule matches.</p>
          ) : (
            <Table aria-label="Matches">
              <TableHeader>
                <TableRow>
                  <TableHead>Role</TableHead>
                  <TableHead>Feed</TableHead>
                  <TableHead>Rule</TableHead>
                  <TableHead>Line</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {result.matches.map((x, i) => (
                  <TableRow key={i}>
                    <TableCell>
                      <Badge variant={x.role === "decisive" ? "default" : "secondary"}>{escapeControl(String(x.role))}</Badge>
                    </TableCell>
                    <TableCell>
                      <SafeText>{x.feed}</SafeText>
                    </TableCell>
                    <TableCell>
                      <SafeText mono>{x.rule}</SafeText>
                    </TableCell>
                    <TableCell className="tabular-nums">{x.line ?? "—"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          <JsonBlock value={result.feed_runs} className="max-h-32" />
        </div>
      )}
    </Section>
  );
}

function ColdHits({ id }: { id: string }) {
  const { window, edge, allowed, setWindow, setEdge } = useWindowState("metrics");
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap justify-end gap-2">
        <WindowPicker value={window} onChange={setWindow} allowed={allowed} />
        <EdgeSelector value={edge} onChange={setEdge} />
      </div>
      <MetricPanel
        title="Cold part"
        description="Blocks answered from the cold part, queries whose cold check couldn't be read (core checks them afterwards), and page reads."
        series={[`cold.${id}.blocks`, `cold.${id}.unchecked`, `cold.${id}.page_reads`]}
        window={window}
        edge={edge}
        specs={[
          { match: (l) => l.name.endsWith(".blocks"), label: "cold blocks" },
          { match: (l) => l.name.endsWith(".unchecked"), label: "unchecked" },
          { match: (l) => l.name.endsWith(".page_reads"), label: "page reads" },
        ]}
        note="Per-feed shares of cold blocks are in the bundle_cold_share alert's detail."
      />
      <MetricPanel
        title="Missed blocks core found"
        description="Queries the edges couldn't check against the cold part that core found should have been blocked, from the query log."
        series={["cold_missed_blocks"]}
        window={window}
        edge={edge}
        transform={(ls) => ls.filter((l) => l.labels?.bundle === id)}
        specs={[{ match: () => true, label: (l) => (l.edge ? `missed blocks · ${l.edge}` : "missed blocks") }]}
      />
    </div>
  );
}
