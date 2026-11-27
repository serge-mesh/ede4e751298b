import * as React from "react";
import { Link, useNavigate, useParams, useSearch } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { DownloadCloudIcon, EraserIcon, Loader2Icon, SaveIcon, Trash2Icon, TriangleAlertIcon } from "lucide-react";
import { KeyValue, PageHeader, Section } from "@/components/common/page";
import { useDraft } from "@/components/common/drafts";
import { ErrorState, LoadingState, QueryView, RefetchError } from "@/components/common/states";
import { JsonBlock, Mono, SafeText } from "@/components/common/text";
import { TimeAgo } from "@/components/common/time";
import { Confirm } from "@/components/common/confirm";
import { CopyField } from "@/components/common/copy-button";
import { IssueList } from "@/components/common/entity-editor";
import { WindowPicker } from "@/components/common/window-picker";
import { MetricPanel } from "@/components/charts/metric-panel";
import type { DerivedLine } from "@/components/charts/series";
import { SchemaForm } from "@/components/schema-form/schema-form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useEdgeMutation, useEdgeStatus, useEdges, useEntities, useModifyEntity } from "@/api/queries";
import { client, request, unwrap } from "@/api/http";
import { ApiError, errorMessage } from "@/api/errors";
import type { ChartLine, EdgeDef, EdgeStatusView, EdgeView, Issue, ListenerDef, Outcome } from "@/api/types";
import { openapiRoot } from "@/lib/openapi";
import { clone, validate, type FieldErrors } from "@/lib/schema";
import { formatBytes, formatNumber, formatPercent, formatSeconds, formatTime } from "@/lib/format";
import { escapeControl } from "@/lib/text";
import { useWindowState } from "./dashboard";

export function EdgeDetailPage() {
  const { edgeId } = useParams({ strict: false }) as { edgeId: string };
  const search = useSearch({ strict: false }) as { tab?: string };
  const navigate = useNavigate();
  const edges = useEdges();
  const status = useEdgeStatus(edgeId);
  const edge = edges.data?.find((e) => e.id === edgeId);
  const tab = search.tab ?? "overview";
  // Once loaded, a failed refetch keeps the page (and a settings draft) mounted and says so (core.md §12).
  if (edges.data === undefined) return edges.error ? <ErrorState error={edges.error} onRetry={() => void edges.refetch()} /> : <LoadingState rows={8} />;
  if (!edge) return <ErrorState error={new ApiError(404, "not_found", `No edge ${escapeControl(edgeId)}.`)} />;
  return (
    <div className="space-y-4">
      {edges.error && <RefetchError error={edges.error} onRetry={() => void edges.refetch()} />}
      <PageHeader
        title={<SafeText>{edge.name || edge.id}</SafeText>}
        description={
          <span className="flex flex-wrap items-center gap-2">
            {edge.status?.online ? <Badge variant="success">online</Badge> : <Badge variant="destructive">offline</Badge>}
            <Badge variant="outline">{edge.platform}</Badge>
            <span>
              id <Mono>{edge.id}</Mono>
            </span>
            <span>last heartbeat <TimeAgo value={edge.status?.last_seen} /></span>
          </span>
        }
        actions={<EdgeActions edge={edge} status={status.data} />}
      />
      <Tabs value={tab} onValueChange={(t) => void navigate({ to: ".", search: (p: Record<string, unknown>) => ({ ...p, tab: t }), replace: true })}>
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="system">System</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
          <TabsTrigger value="listeners">Listeners</TabsTrigger>
          <TabsTrigger value="events">Events</TabsTrigger>
          <TabsTrigger value="config">Config object</TabsTrigger>
        </TabsList>
        <TabsContent value="overview">
          <QueryView query={status} rows={6}>
            {(s) => <Overview edge={edge} status={s} />}
          </QueryView>
        </TabsContent>
        <TabsContent value="system">
          <SystemPanel edge={edge} />
        </TabsContent>
        <TabsContent value="settings">
          <EdgeSettings edge={edge} onDeleted={() => void navigate({ to: "/edges" })} />
        </TabsContent>
        <TabsContent value="listeners">
          <ListenerAssignment edge={edge} status={status.data} />
        </TabsContent>
        <TabsContent value="events">
          <QueryView query={status} rows={6}>
            {(s) => <Events status={s} />}
          </QueryView>
        </TabsContent>
        <TabsContent value="config">
          <ConfigPreview edgeId={edge.id ?? ""} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function releaseVersion(s: EdgeStatusView | undefined): string | undefined {
  const r = s?.release as { version?: unknown } | null | undefined;
  return typeof r?.version === "string" ? r.version : undefined;
}

function pendingOf(s: EdgeStatusView | undefined, kind: string) {
  return s?.requests.find((r) => r.kind === kind && r.pending);
}

function EdgeActions({ edge, status }: { edge: EdgeView; status?: EdgeStatusView }) {
  const id = edge.id ?? "";
  const update = useEdgeMutation(() => unwrap(client.POST("/api/ui/v1/edges/{id}/update", { params: { path: { id } } })));
  const flush = useEdgeMutation(() => unwrap(client.POST("/api/ui/v1/edges/{id}/flush", { params: { path: { id } }, body: {} })));
  const offered = releaseVersion(status);
  const running = status?.hello?.edge_version;
  const updateAvailable = !!offered && !!running && offered !== running;
  const pendingUpdate = pendingOf(status, "install_now");
  const pendingFlush = pendingOf(status, "flush_dns");
  return (
    <>
      <Button
        variant="outline"
        disabled={update.isPending || !!pendingUpdate || !updateAvailable}
        title={updateAvailable ? `Install ${offered} now` : "No other release is offered to this edge"}
        onClick={() =>
          update.mutate(undefined, {
            onSuccess: () => toast.success("Update requested; it stays pending until the edge applies it."),
            onError: (e) => toast.error(errorMessage(e)),
          })
        }
      >
        {pendingUpdate ? <Loader2Icon className="animate-spin" /> : <DownloadCloudIcon />}
        {pendingUpdate ? "Update pending" : updateAvailable && !edge.auto_update ? `Update to ${offered}` : "Update"}
      </Button>
      <Button
        variant="outline"
        disabled={flush.isPending || !!pendingFlush}
        onClick={() =>
          flush.mutate(undefined, {
            onSuccess: () => toast.success("Flush requested; it stays pending until the edge applies it."),
            onError: (e) => toast.error(errorMessage(e)),
          })
        }
      >
        {pendingFlush ? <Loader2Icon className="animate-spin" /> : <EraserIcon />}
        {pendingFlush ? "Flush pending" : "Flush DNS cache"}
      </Button>
    </>
  );
}

interface Condition {
  kind?: string;
  key?: string;
  since?: string;
  detail?: unknown;
}

function Overview({ edge, status: s }: { edge: EdgeView; status: EdgeStatusView }) {
  const conditions = (Array.isArray(s.conditions) ? s.conditions : []) as Condition[];
  const offered = releaseVersion(s);
  const running = s.hello?.edge_version;
  return (
    <div className="space-y-4">
      {(s.missing_heads.length > 0 || s.missing_secrets.length > 0 || s.missing_verdict_sets.length > 0) && (
        <Alert variant="warning">
          <TriangleAlertIcon />
          <AlertTitle>The config object names things core doesn't have yet</AlertTitle>
          <AlertDescription>
            {s.missing_heads.length > 0 && <p>Bundles without a head: {s.missing_heads.map(escapeControl).join(", ")}</p>}
            {s.missing_verdict_sets.length > 0 && <p>Verdict sets: {s.missing_verdict_sets.map(escapeControl).join(", ")}</p>}
            {s.missing_secrets.length > 0 && <p>Secrets without a value: {s.missing_secrets.map(escapeControl).join(", ")}</p>}
          </AlertDescription>
        </Alert>
      )}
      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="Status">
          <KeyValue
            items={[
              ["State", s.online ? <Badge variant="success">online</Badge> : <Badge variant="destructive">offline (no heartbeat for 90 s)</Badge>],
              ["Last heartbeat", <TimeAgo value={s.last_seen} />],
              ["Session", s.session ? <span>from <SafeText mono>{s.session.addr}</SafeText> since {formatTime(s.session.since)}</span> : "none"],
              ["Boot", <SafeText mono>{s.session?.boot ?? s.hello?.boot}</SafeText>],
              ["Starts since last session", s.hello?.starts ?? "—"],
              ["Config served", s.config ? <span><Mono>{s.config.slice(0, 16)}</Mono> published <TimeAgo value={s.config_published_at} /></span> : "—"],
            ]}
          />
        </Section>
        <Section title="Versions">
          <KeyValue
            items={[
              ["Running", <SafeText mono>{running}</SafeText>],
              ["Ready version", <SafeText mono>{s.ready_version}</SafeText>],
              [
                "Offered",
                offered ? (
                  <span className="flex flex-wrap items-center gap-2">
                    <Mono>{offered}</Mono>
                    {offered !== running && (edge.auto_update ? <Badge variant="secondary">installing automatically</Badge> : <Badge variant="warning">update available</Badge>)}
                  </span>
                ) : (
                  "—"
                ),
              ],
              [
                "Last update",
                s.update ? (
                  <span>
                    <Badge variant={s.update.outcome === "ok" ? "success" : "destructive"}>{s.update.outcome}</Badge> <Mono>{s.update.version}</Mono>{" "}
                    {s.update.stage && <>at stage <Mono>{s.update.stage}</Mono> </>}
                    <TimeAgo value={s.update.at} />
                  </span>
                ) : (
                  "—"
                ),
              ],
              [
                "UniFi firmware",
                s.hello?.firmware ? (
                  <span>
                    <SafeText>{s.hello.firmware}</SafeText>
                    {s.hello.firmware_changed_at && <span className="text-muted-foreground"> (changed <TimeAgo value={s.hello.firmware_changed_at} />)</span>}
                  </span>
                ) : (
                  "—"
                ),
              ],
              ["Platform", s.hello ? <SafeText>{`${s.hello.platform} · ${s.hello.os} · ${s.hello.arch} · kernel ${s.hello.kernel}`}</SafeText> : "—"],
              ["Memory", s.hello?.mem_total ? formatBytes(s.hello.mem_total) : "—"],
            ]}
          />
        </Section>
      </div>
      <Section title="Open conditions" description="As the edge last reported them; while it is offline they stay as last reported.">
        {conditions.length === 0 ? (
          <p className="text-sm text-muted-foreground">None.</p>
        ) : (
          <Table aria-label="Open conditions">
            <TableHeader>
              <TableRow>
                <TableHead>Condition</TableHead>
                <TableHead>Key</TableHead>
                <TableHead>Since</TableHead>
                <TableHead>Detail</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {conditions.map((c, i) => (
                <TableRow key={i}>
                  <TableCell>
                    <Mono>{escapeControl(String(c.kind ?? ""))}</Mono>
                  </TableCell>
                  <TableCell>
                    <SafeText mono>{c.key}</SafeText>
                  </TableCell>
                  <TableCell>
                    <TimeAgo value={c.since} />
                  </TableCell>
                  <TableCell className="max-w-md">{c.detail !== undefined && c.detail !== null ? <JsonBlock value={c.detail} className="max-h-32" /> : "—"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Section>
      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="Requests" description="Update, flushes and revokes stay pending until the edge's applied report carries their id.">
          {s.requests.length === 0 ? (
            <p className="text-sm text-muted-foreground">None.</p>
          ) : (
            <ul className="space-y-1.5 text-sm">
              {s.requests.map((r) => (
                <li key={r.request_id} className="flex flex-wrap items-center gap-2">
                  <Mono>{r.kind}</Mono>
                  {r.provider && <SafeText mono>{r.provider}</SafeText>}
                  {r.version && <Mono>{r.version}</Mono>}
                  <span className="text-muted-foreground">requested <TimeAgo value={r.requested_at} /></span>
                  {r.pending ? <Badge variant="warning">pending</Badge> : <Badge variant="success">applied</Badge>}
                </li>
              ))}
            </ul>
          )}
        </Section>
        <Section title="Convergence" description="Each version core names in the config object, and when the edge first showed it active.">
          {s.named.length === 0 ? (
            <p className="text-sm text-muted-foreground">Nothing named yet.</p>
          ) : (
            <Table aria-label="Convergence">
              <TableHeader>
                <TableRow>
                  <TableHead>Kind</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead>Active</TableHead>
                  <TableHead className="text-right">Lag</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {s.named.map((n, i) => (
                  <TableRow key={i}>
                    <TableCell>{n.kind}</TableCell>
                    <TableCell>
                      <SafeText mono>{n.target}</SafeText>
                    </TableCell>
                    <TableCell>
                      <Mono>{n.id.slice(0, 16)}</Mono>
                    </TableCell>
                    <TableCell>{n.active_at ? <TimeAgo value={n.active_at} /> : <Badge variant="warning">pending</Badge>}</TableCell>
                    <TableCell className="text-right tabular-nums">{formatSeconds(n.lag_s)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </Section>
      </div>
    </div>
  );
}

function Events({ status: s }: { status: EdgeStatusView }) {
  return (
    <Section title="Events and condition changes" description="The last 72 h: one-off events from the log and every condition that appeared or cleared.">
      {s.events.length === 0 ? (
        <p className="text-sm text-muted-foreground">No events in the last 72 h.</p>
      ) : (
        <Table aria-label="Events">
          <TableHeader>
            <TableRow>
              <TableHead>When</TableHead>
              <TableHead>Event</TableHead>
              <TableHead>Detail</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {s.events.map((e, i) => (
              <TableRow key={i}>
                <TableCell className="whitespace-nowrap">{formatTime(e.at)}</TableCell>
                <TableCell>
                  <Mono>{escapeControl(e.kind)}</Mono>
                </TableCell>
                <TableCell className="max-w-xl">{e.detail !== null && e.detail !== undefined ? <JsonBlock value={e.detail} className="max-h-32" /> : "—"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </Section>
  );
}

function ConfigPreview({ edgeId }: { edgeId: string }) {
  const q = useQuery({
    queryKey: ["edges", edgeId, "config"],
    queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/edges/{id}/config", { params: { path: { id: edgeId } }, signal })),
  });
  return (
    <Section title="Config object" description="As core would render it now, with secret values blanked.">
      <QueryView query={q} rows={6}>
        {(c) => (
          <div className="space-y-3">
            <p className="text-sm">
              Id <CopyField value={c.id} label="Copy config id" />
            </p>
            {(c.missing_heads.length > 0 || c.missing_secrets.length > 0) && (
              <p className="text-sm text-warning">
                Missing: {[...c.missing_heads, ...c.missing_secrets].map(escapeControl).join(", ")}
              </p>
            )}
            <JsonBlock value={c.config} className="max-h-[60vh]" />
          </div>
        )}
      </QueryView>
    </Section>
  );
}

// ---------------------------------------------------------------------------------------------
// Settings

/** The total `max_mib` of the sync lookup providers an edge's profiles attach (core.md §4). */
function useVerdictTotal(): number | null {
  const profiles = useEntities("profiles");
  const providers = useEntities("lookup-providers");
  if (!profiles.data || !providers.data) return null;
  const ids = new Set<string>();
  for (const p of profiles.data) for (const a of p.lookups ?? []) if ((a.mode ?? "sync") === "sync" && a.provider) ids.add(a.provider);
  let total = 0;
  for (const lp of providers.data) if (ids.has(lp.id ?? "")) total += lp.cache?.max_mib ?? 2;
  return total;
}

function EdgeSettings({ edge, onDeleted }: { edge: EdgeView; onDeleted: () => void }) {
  const { listeners: _l, status: _s, ...def } = edge;
  const start = React.useMemo(() => clone(def as EdgeDef), [edge]); // eslint-disable-line react-hooks/exhaustive-deps
  const [value, setValue] = React.useState<EdgeDef>(start);
  const [errors, setErrors] = React.useState<FieldErrors>({});
  const [issues, setIssues] = React.useState<Issue[]>([]);
  const [warnings, setWarnings] = React.useState<Issue[]>([]);
  const id = edge.id ?? "";
  const verdictTotal = useVerdictTotal();
  const schema = React.useMemo(() => ({ $ref: "#/components/schemas/EdgeDef" }), []);
  const save = useEdgeMutation((body: EdgeDef) => unwrap(client.PUT("/api/ui/v1/edges/{id}", { params: { path: { id } }, body })));
  const del = useEdgeMutation(() => unwrap(client.DELETE("/api/ui/v1/edges/{id}", { params: { path: { id } } })));
  const dirty = JSON.stringify(value) !== JSON.stringify(start);
  useDraft(dirty);
  const overBudget = verdictTotal !== null && verdictTotal > (value.verdict_budget_mib ?? 16);
  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        const local = validate(schema, value, openapiRoot);
        setErrors(local);
        if (Object.keys(local).length) return;
        save.mutate(value, {
          onSuccess: (o) => {
            setWarnings((o as Outcome).warnings ?? []);
            setIssues([]);
            toast.success("Saved edge settings");
          },
          onError: (err) => {
            if (err instanceof ApiError) {
              setErrors(err.fieldErrors());
              setIssues(err.issues.filter((i) => !i.field));
            }
            toast.error(errorMessage(err));
          },
        });
      }}
    >
      <IssueList issues={issues} title="Core refused the change" />
      <Section title="Per-edge settings" description="Name, platform presets, budgets, firewall interfaces and modes, static allows, exempt sources and UniFi options. The key can be replaced here.">
        <SchemaForm
          schema={schema}
          root={openapiRoot}
          value={value}
          onChange={(v) => setValue(v as EdgeDef)}
          errors={errors}
          readOnly={["id", "created_at"]}
          disabled={save.isPending}
          order={["key", "platform", "auto_update"]}
          overrides={{
            verdict_budget_mib: ({ renderDefault }) => (
              <div className="space-y-1">
                {renderDefault()}
                <p className={overBudget ? "text-xs text-warning" : "text-xs text-muted-foreground"}>
                  Sync lookup providers' RAM tiers total {verdictTotal === null ? "…" : `${verdictTotal} MiB`}
                  {overBudget && ": above this budget"}.
                </p>
              </div>
            ),
          }}
        />
      </Section>
      <IssueList issues={warnings} title="Saved, with warnings" />
      <div className="sticky bottom-0 flex flex-wrap gap-2 border-t bg-background/95 py-3">
        <Button type="submit" disabled={!dirty || save.isPending}>
          {save.isPending ? <Loader2Icon className="animate-spin" /> : <SaveIcon />} Save
        </Button>
        {dirty && (
          <Button variant="ghost" onClick={() => setValue(start)}>
            Discard changes
          </Button>
        )}
        <Confirm
          title={`Delete edge ${escapeControl(edge.name || id)}?`}
          description="Core forgets its key; the edge can't connect until it is added again."
          destructive
          confirmLabel="Delete"
          onConfirm={() => del.mutate(undefined, { onSuccess: onDeleted, onError: (e) => toast.error(errorMessage(e)) })}
        >
          <Button variant="outline" className="ml-auto text-destructive">
            <Trash2Icon /> Delete edge
          </Button>
        </Confirm>
      </div>
    </form>
  );
}

function ListenerAssignment({ edge, status }: { edge: EdgeView; status?: EdgeStatusView }) {
  const listeners = useEntities("listeners");
  const save = useModifyEntity("listeners");
  const id = edge.id ?? "";
  const flags = new Map((status?.listeners ?? []).map((l) => [l.id, l.allowed]));
  const toggle = (l: ListenerDef, on: boolean) => {
    save.mutate(
      {
        id: l.id ?? "",
        change: (cur) => {
          const edges = new Set(cur.edges ?? []);
          if (edges.has(id) === on) return null;
          if (on) edges.add(id);
          else edges.delete(id);
          return { ...cur, edges: [...edges] };
        },
      },
      { onError: (e) => toast.error(errorMessage(e)), onSuccess: () => toast.success(on ? "Listener assigned" : "Listener unassigned") },
    );
  };
  return (
    <Section title="Listener assignment" description="Listeners this edge serves. Core flags a bind that isn't in the edge's reported allowed_binds; the edge refuses it too.">
      <QueryView query={listeners} rows={4} empty={<p className="text-sm text-muted-foreground">No listeners defined. Add them on the Listeners page.</p>} isEmpty={(d) => d.length === 0}>
        {(ls) => (
          <Table aria-label="Listeners">
            <TableHeader>
              <TableRow>
                <TableHead className="w-10">On</TableHead>
                <TableHead>Listener</TableHead>
                <TableHead>Protocol</TableHead>
                <TableHead>Bind</TableHead>
                <TableHead>Bind allowed</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {ls.map((l) => {
                const assigned = (l.edges ?? []).includes(id);
                const allowed = flags.get(l.id ?? "");
                return (
                  <TableRow key={l.id}>
                    <TableCell>
                      <Checkbox checked={assigned} disabled={save.isPending} aria-label={`Assign ${l.name || l.id}`} onCheckedChange={(on) => toggle(l, on === true)} />
                    </TableCell>
                    <TableCell>
                      <SafeText>{l.name || l.id}</SafeText>
                    </TableCell>
                    <TableCell>{l.proto}</TableCell>
                    <TableCell>
                      <Mono>{l.bind}</Mono>
                    </TableCell>
                    <TableCell>
                      {!assigned ? (
                        "—"
                      ) : allowed === false ? (
                        <Badge variant="destructive">not in allowed_binds</Badge>
                      ) : allowed === true ? (
                        <Badge variant="success">allowed</Badge>
                      ) : (
                        <span className="text-xs text-muted-foreground">not reported yet</span>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </QueryView>
      <p className="mt-3 text-xs text-muted-foreground">
        Edit listeners themselves on the <Link to="/listeners" className="underline">Listeners</Link> page.
      </p>
    </Section>
  );
}

// ---------------------------------------------------------------------------------------------
// System panel (core.md §12 Edges → System panel)

function stepOf(l: ChartLine): number {
  const p = l.points ?? [];
  return p.length > 1 ? Number(p[1][0]) - Number(p[0][0]) : 30;
}

/** A CPU counter (ms per step) as a percentage of one core. */
export function cpuPercent(lines: ChartLine[]): ChartLine[] {
  return lines.map((l) => {
    const step = stepOf(l);
    return { ...l, points: (l.points ?? []).map(([t, v]) => [t, v === null || v === undefined ? null : (Number(v) / (step * 1000)) * 100]) };
  });
}

/** `ts − spool.oldest_ts` per step, in seconds; an empty spool (no oldest record) is a gap. */
export function spoolAge(lines: ChartLine[]): DerivedLine[] {
  return lines
    .filter((l) => l.name === "spool.oldest_ts")
    .map((l) => ({
      ...l,
      name: "spool age",
      sources: [l.name],
      points: (l.points ?? []).map(([t, v]) => {
        if (v === null || v === undefined || Number(v) <= 0) return [t, null];
        const oldest = Number(v) > 1e11 ? Number(v) / 1000 : Number(v);
        return [t, Math.max(0, Number(t) - oldest)];
      }),
    }));
}

/** Firewall set fill: `fw.entries ÷ fw.max` per step. */
export function firewallFill(lines: ChartLine[]): DerivedLine[] {
  const entries = lines.find((l) => l.name === "fw.entries");
  const max = lines.find((l) => l.name === "fw.max");
  if (!entries || !max) return [];
  const maxBy = new Map((max.points ?? []).map(([t, v]) => [Number(t), v]));
  return [
    {
      ...entries,
      name: "fill",
      sources: [entries.name, max.name],
      points: (entries.points ?? []).map(([t, v]) => {
        const m = maxBy.get(Number(t));
        return [t, v === null || v === undefined || !m ? null : Number(v) / Number(m)];
      }),
    },
  ];
}

function SystemPanel({ edge }: { edge: EdgeView }) {
  const { window, allowed, setWindow } = useWindowState("dashboard");
  const id = edge.id ?? "";
  const unifi = edge.platform === "unifi";
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm text-muted-foreground">From this edge's heartbeats, plus core's convergence and firewall series.</p>
        <WindowPicker value={window} onChange={setWindow} allowed={allowed} />
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <MetricPanel
          title="Memory"
          description={unifi ? "The unit's memory.current against its MemoryHigh (640 MiB) and MemoryMax (768 MiB), with the edge's RSS and the helper's RSS." : "The unit's memory.current, the edge's RSS and the helper's RSS."}
          series={["cgroup_mem.unit", "rss", "cgroup_mem.helper_rss"]}
          window={window}
          edge={id}
          format={formatBytes}
          refLines={unifi ? [{ y: 640 * 1024 * 1024, label: "MemoryHigh" }, { y: 768 * 1024 * 1024, label: "MemoryMax" }] : undefined}
          specs={[
            { match: (l) => l.name === "cgroup_mem.unit", label: "unit memory.current" },
            { match: (l) => l.name === "rss", label: "edge RSS" },
            { match: (l) => l.name === "cgroup_mem.helper_rss", label: "helper RSS" },
          ]}
        />
        <MetricPanel
          title="CPU"
          description="CPU time per second; 100 % is one core."
          series={["cpu_ms.edge", "cpu_ms.helper"]}
          window={window}
          edge={id}
          transform={cpuPercent}
          format={(v) => `${formatNumber(v, 1)} %`}
          specs={[
            { match: (l) => l.name === "cpu_ms.edge", label: "edge" },
            { match: (l) => l.name === "cpu_ms.helper", label: "helper" },
          ]}
        />
        <MetricPanel
          title="Rejected and refused queries"
          description="Rejected: no decision (unreadable, malformed, from another interface, not recursion-desired, or over the client's limits). Refused: no profile admits the client. Panics: panics the edge caught (a query that panics is answered SERVFAIL)."
          series={["rejected", "refused", "panics"]}
          window={window}
          edge={id}
          specs={[
            { match: (l) => l.name === "rejected", label: "rejected" },
            { match: (l) => l.name === "refused", label: "refused" },
            { match: (l) => l.name === "panics", label: "panics" },
          ]}
        />
        <MetricPanel
          title="Unattributed TLS refusals"
          description="Handshakes a DoT or DoH listener refused for offering no TLS 1.3 that the edge couldn't attribute to a device, because its table of refused devices was full. Attributed refusals raise edge_tls_version_refused alerts."
          series={["tls_refused_unlogged"]}
          window={window}
          edge={id}
          specs={[{ match: (l) => l.name === "tls_refused_unlogged", label: "unattributed refusals" }]}
        />
        <MetricPanel title="Available memory (box)" description="MemAvailable of the whole box." series={["mem_available"]} window={window} edge={id} format={formatBytes} specs={[{ match: () => true, label: "MemAvailable" }]} />
        <MetricPanel title="Spool size" series={["spool.bytes"]} window={window} edge={id} format={formatBytes} specs={[{ match: () => true, label: "spool" }]} />
        <MetricPanel title="Spool age" description="Age of the oldest record the edge still holds for core." series={["spool.oldest_ts"]} window={window} edge={id} transform={spoolAge} format={(v) => formatSeconds(v)} specs={[{ match: () => true, label: "oldest record" }]} />
        <MetricPanel
          title="Disk"
          description="Picket's files and the free space on data_dir and the SSD."
          series={["disk.data_dir.used", "disk.data_dir.free", "disk.ssd_dir.used", "disk.ssd_dir.free"]}
          window={window}
          edge={id}
          format={formatBytes}
          specs={[
            { match: (l) => l.name === "disk.data_dir.used", label: "data_dir used" },
            { match: (l) => l.name === "disk.data_dir.free", label: "data_dir free" },
            { match: (l) => l.name === "disk.ssd_dir.used", label: "SSD used" },
            { match: (l) => l.name === "disk.ssd_dir.free", label: "SSD free" },
          ]}
        />
        <MetricPanel title="Firewall set fill" series={["fw.entries", "fw.max"]} window={window} edge={id} transform={firewallFill} format={(v) => formatPercent(v, 0)} specs={[{ match: () => true, label: "entries ÷ max" }]} />
        <MetricPanel
          title="Convergence lag"
          description="By kind, with failed activations. A pending version counts with its age so far."
          series={["convergence_lag_s", "activations_failed"]}
          window={window}
          edge={id}
          specs={[
            { match: (l) => l.name === "convergence_lag_s", label: (l) => `lag: ${l.labels?.kind ?? "?"}` },
            { match: (l) => l.name === "activations_failed", label: (l) => `failed: ${l.labels?.kind ?? "?"}` },
          ]}
        />
        <MetricPanel
          title="Firewall activity"
          className="xl:col-span-2"
          description="New connections without a grant that enforce interfaces left to the Block All (fw.rejects), next to would-be rejects on monitor interfaces (fw.mon_rejects); late acks, rule repairs and drift."
          series={["fw.rejects", "fw.mon_rejects", "fw_ack_late", "fw_repairs", "fw_drift"]}
          window={window}
          edge={id}
          specs={[
            { match: (l) => l.name === "fw.rejects", label: "rejects (enforce)" },
            { match: (l) => l.name === "fw.mon_rejects", label: "would-be rejects (monitor)" },
            { match: (l) => l.name === "fw_ack_late", label: "late acks" },
            { match: (l) => l.name === "fw_repairs", label: "rule repairs" },
            { match: (l) => l.name === "fw_drift", label: (l) => `drift: ${l.labels?.kind ?? "?"}` },
          ]}
        />
      </div>
    </div>
  );
}

/** Revoke a temporary allow on an edge (pending until the edge acknowledges it). */
export async function revokeAllow(edge: string, allow: string) {
  return request("POST", `/edges/${encodeURIComponent(edge)}/allows/${encodeURIComponent(allow)}/revoke`, { body: {} });
}
