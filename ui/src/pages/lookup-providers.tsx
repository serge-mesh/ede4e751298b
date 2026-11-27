import * as React from "react";
import { Link, useNavigate, useParams, useSearch } from "@tanstack/react-router";
import type { ColumnDef } from "@tanstack/react-table";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { EraserIcon, FlaskConicalIcon, Loader2Icon, PlusIcon, RotateCcwIcon, RotateCwIcon, TriangleAlertIcon } from "lucide-react";
import { KeyValue, PageHeader, Section } from "@/components/common/page";
import { DataTable } from "@/components/common/data-table";
import { ErrorState, LoadingState, QueryView } from "@/components/common/states";
import { JsonBlock, Mono, SafeText } from "@/components/common/text";
import { TimeAgo } from "@/components/common/time";
import { EntityForm } from "@/components/common/entity-editor";
import { IdSelect } from "@/components/common/ordered-picker";
import { EdgeSelector, WindowPicker } from "@/components/common/window-picker";
import { MetricPanel } from "@/components/charts/metric-panel";
import type { DerivedLine } from "@/components/charts/series";
import { SchemaForm, type FieldOverride } from "@/components/schema-form/schema-form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { invalidateConfig, useEdges, useEntities, useEntity, useModifyEntity, useSaveEntity } from "@/api/queries";
import { IdField, useDerivedId } from "@/components/common/id-field";
import { client, unwrap } from "@/api/http";
import { ApiError, errorMessage } from "@/api/errors";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import type { ChartLine, LookupModuleInfo, LookupProviderDef, SelfTestView } from "@/api/types";
import { collectWarnings, defaultValue, type SchemaRoot } from "@/lib/schema";
import { nextRuns, parseCron } from "@/lib/cron";
import { formatBytes, formatNumber, formatPercent } from "@/lib/format";
import { escapeControl } from "@/lib/text";
import { useWindowState } from "./dashboard";

/** `lookup-modules` (api.md §7): each lookup module with its Config schema and presets (id, title, params_schema). */
type LookupModule = LookupModuleInfo;

function useLookupModules() {
  return useQuery({ queryKey: ["lookup-modules"], queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/lookup-modules", { signal })), staleTime: Infinity });
}

function modulesOf(d: LookupModule[] | undefined): LookupModule[] {
  return d ?? [];
}

/** `POST lookup-modules/{module}/presets/{preset}`: the preset's config from its parameters; changes nothing. */
function buildPreset(module: string, preset: string, params: unknown) {
  return unwrap(client.POST("/api/ui/v1/lookup-modules/{module}/presets/{preset}", { params: { path: { module, preset } }, body: (params ?? {}) as Record<string, never> }));
}

/** Plain DNS is marked Unencrypted in the list (providers.md §5): the module's field warning. */
export function providerWarnings(p: LookupProviderDef, modules: LookupModule[]): string[] {
  const m = modules.find((x) => x.id === p.module);
  if (m) return collectWarnings(m.config_schema as SchemaRoot, p.config, m.config_schema as SchemaRoot);
  const t = (p.config as { transport?: unknown } | undefined)?.transport;
  return t === "udp" || t === "tcp" ? ["Plain DNS is unencrypted."] : [];
}

export function LookupProvidersPage() {
  const providers = useEntities("lookup-providers");
  const modules = useLookupModules();
  const navigate = useNavigate();
  const [adding, setAdding] = React.useState(false);
  const mods = modulesOf(modules.data);
  const columns = React.useMemo<ColumnDef<LookupProviderDef, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Provider",
        accessorFn: (p) => p.name || p.id,
        cell: ({ row }) => (
          <span className="flex flex-wrap items-center gap-2">
            <Link to="/lookup-providers/$providerId" params={{ providerId: row.original.id ?? "" }} className="font-medium hover:underline" onClick={(e) => e.stopPropagation()}>
              <SafeText>{row.original.name || row.original.id}</SafeText>
            </Link>
            {providerWarnings(row.original, mods).length > 0 && <Badge variant="warning">Unencrypted</Badge>}
          </span>
        ),
      },
      { id: "id", header: "Id", accessorFn: (p) => p.id, cell: ({ getValue }) => <Mono>{String(getValue() ?? "")}</Mono> },
      { id: "module", header: "Module", accessorFn: (p) => p.module, cell: ({ getValue }) => <Mono>{String(getValue() ?? "")}</Mono> },
      { id: "category", header: "Category", accessorFn: (p) => p.category },
      { id: "fail", header: "Fail mode", accessorFn: (p) => p.fail_mode },
      {
        id: "selftest",
        header: "Last self-test",
        accessorFn: (p) => JSON.stringify(p.last_self_test ?? ""),
        cell: ({ row }) => <SelfTestBadge value={row.original.last_self_test} />,
      },
    ],
    [mods],
  );
  return (
    <div>
      <PageHeader
        title="Lookup providers"
        description="Configured lookup modules that give a verdict for a name in real time: sync on the edge, async on core."
        actions={
          <Button onClick={() => setAdding(true)}>
            <PlusIcon /> New lookup provider
          </Button>
        }
      />
      <QueryView query={providers} rows={5}>
        {(list) => (
          <DataTable
            label="Lookup providers"
            data={list}
            columns={columns}
            searchable
            onRowClick={(p) => void navigate({ to: "/lookup-providers/$providerId", params: { providerId: p.id ?? "" } })}
            empty="No lookup providers yet."
          />
        )}
      </QueryView>
      {adding && <NewLookupProviderDialog modules={mods} modulesUnavailable={!!modules.error} onClose={() => setAdding(false)} />}
    </div>
  );
}

/** A self-test's result (lookups/selftest.rs `SelfTestView`): `pass`, `wrong` or `inconclusive`. */
function SelfTestBadge({ value }: { value: unknown }) {
  if (!value || typeof value !== "object") return <span className="text-muted-foreground">—</span>;
  const v = value as Partial<SelfTestView>;
  return (
    <span className="flex items-center gap-1.5">
      <Badge variant={v.result === "pass" ? "success" : v.result === "wrong" ? "destructive" : "outline"}>{escapeControl(String(v.result ?? "?"))}</Badge>
      {v.state && v.state !== "ok" && <Badge variant={v.state === "failing" ? "destructive" : "warning"}>{escapeControl(v.state)}</Badge>}
      <TimeAgo value={v.at} className="text-xs text-muted-foreground" />
    </span>
  );
}

/** The last self-test in full. */
function SelfTestDetail({ value }: { value: unknown }) {
  if (!value || typeof value !== "object") return <p className="text-sm text-muted-foreground">No self-test yet.</p>;
  const v = value as Partial<SelfTestView>;
  return (
    <KeyValue
      items={[
        ["Result", <SelfTestBadge value={v} />],
        ["Name tested", <SafeText mono>{v.name}</SafeText>],
        ["Expected", escapeControl(v.expect ?? "—")],
        ["Got", v.verdict ? escapeControl(v.verdict) : "no verdict"],
        ...(v.why ? ([["Why no verdict", <SafeText>{v.why}</SafeText>]] as [string, React.ReactNode][]) : []),
        ...(v.reason ? ([["Reason", <SafeText>{v.reason}</SafeText>]] as [string, React.ReactNode][]) : []),
        ...(v.detail !== undefined && v.detail !== null ? ([["Detail", <JsonBlock value={v.detail} className="max-h-32" />]] as [string, React.ReactNode][]) : []),
        ["Run by", escapeControl(SELF_TEST_TRIGGER[v.trigger ?? ""] ?? v.trigger ?? "—")],
        ["Next", v.next_at ? <TimeAgo value={v.next_at} /> : "—"],
      ]}
    />
  );
}

const SELF_TEST_TRIGGER: Record<string, string> = { schedule: "its schedule", save: "a save", manual: "Test now" };

/** A module config form, or a JSON editor while core doesn't list lookup modules yet. */
function LookupConfigForm({ module, value, onChange, disabled }: { module?: LookupModule; value: unknown; onChange: (v: unknown) => void; disabled?: boolean }) {
  const overrides = React.useMemo<Record<string, FieldOverride>>(
    () => ({
      "self_test.cron": ({ renderDefault, value: cron }) => {
        const text = typeof cron === "string" ? cron : "";
        const runs = text ? nextRuns(text, 3) : null;
        return (
          <div className="space-y-1">
            {renderDefault()}
            {text && !parseCron(text) ? (
              <p className="text-xs text-destructive">Not a cron expression this form can read (5 fields, UTC).</p>
            ) : runs && runs.length ? (
              <p className="text-xs text-muted-foreground">Next runs (UTC): {runs.map((d) => d.toISOString().slice(0, 16).replace("T", " ")).join(", ")}</p>
            ) : null}
          </div>
        );
      },
    }),
    [],
  );
  if (module) {
    const schema = module.config_schema as SchemaRoot;
    return <SchemaForm schema={schema} root={schema} value={value} onChange={onChange} overrides={overrides} disabled={disabled} idPrefix={`lcfg-${module.id}`} />;
  }
  return (
    <SchemaForm
      schema={{ description: "The module's config as JSON." }}
      value={value}
      onChange={onChange}
      disabled={disabled}
      idPrefix="lcfg-json"
    />
  );
}

function NewLookupProviderDialog({ modules, modulesUnavailable, onClose }: { modules: LookupModule[]; modulesUnavailable: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const save = useSaveEntity("lookup-providers");
  const [moduleId, setModuleId] = React.useState<string>("");
  const [presetId, setPresetId] = React.useState<string | null>(null);
  const [params, setParams] = React.useState<unknown>({});
  const [config, setConfig] = React.useState<unknown>({});
  const [category, setCategory] = React.useState<string>("security");
  const [name, setName] = React.useState("");
  const id = useDerivedId("lookup-providers", name);
  const module = modules.find((m) => m.id === moduleId);
  const preset = module?.presets?.find((p) => p.id === presetId);
  const presetSchema = preset?.params_schema as SchemaRoot | undefined;
  const build = useMutation({
    mutationFn: () => buildPreset(moduleId, presetId ?? "", params),
    onSuccess: (r) => {
      setConfig(r.config);
      if (r.category) setCategory(r.category);
      toast.success("The preset filled the config form.");
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent wide>
        <DialogHeader>
          <DialogTitle>New lookup provider</DialogTitle>
          <DialogDescription>Pick a module (any module, as often as needed) and fill its config, or start from one of its presets. Its settings follow on the provider's page.</DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate(
              {
                body: {
                  id: id.id,
                  name,
                  module: moduleId,
                  config: config as Record<string, unknown>,
                  category: category as LookupProviderDef["category"],
                  preset: presetId ? { id: presetId, params } : null,
                } as LookupProviderDef,
              },
              {
                onSuccess: (o) => {
                  onClose();
                  void navigate({ to: "/lookup-providers/$providerId", params: { providerId: o.id }, search: { tab: "settings" } });
                },
                onError: (err) => toast.error(errorMessage(err)),
              },
            );
          }}
        >
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="lp-name">Name</Label>
              <Input id="lp-name" value={name} onChange={(e) => setName(e.target.value)} required />
            </div>
            <IdField htmlId="lp-id" kind="lookup-providers" state={id} />
            <div className="space-y-1.5">
              <Label htmlFor="lp-module">Module</Label>
              {modules.length ? (
                <IdSelect
                  id="lp-module"
                  value={moduleId || null}
                  onChange={(v) => {
                    setModuleId(v ?? "");
                    setPresetId(null);
                    const m = modules.find((x) => x.id === v);
                    setConfig(m ? defaultValue(m.config_schema as SchemaRoot, m.config_schema as SchemaRoot) ?? {} : {});
                  }}
                  options={modules.map((m) => ({ value: m.id }))}
                />
              ) : (
                <Input id="lp-module" value={moduleId} onChange={(e) => setModuleId(e.target.value)} className="font-mono" placeholder="http_json or dns" required />
              )}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="lp-category">Category</Label>
              <IdSelect id="lp-category" value={category} onChange={(v) => setCategory(v ?? "security")} options={["security", "privacy", "mixed"].map((c) => ({ value: c }))} />
            </div>
          </div>
          {modulesUnavailable && (
            <p className="text-xs text-muted-foreground">Core's lookup modules couldn't be read, so the config is edited as JSON.</p>
          )}
          {module?.presets?.length ? (
            <Section title="From a preset" description="Its parameters build a full config that fills the form below, saved like one typed by hand.">
              <div className="space-y-3">
                <Label htmlFor="lp-preset" className="sr-only">
                  Preset
                </Label>
                <IdSelect id="lp-preset" value={presetId} onChange={(v) => setPresetId(v)} nullable noneLabel="No preset" options={module.presets.map((p) => ({ value: p.id, label: p.title }))} />
                {presetSchema && <SchemaForm schema={presetSchema} root={presetSchema} value={params} onChange={setParams} idPrefix="preset" />}
                {preset && (
                  <Button variant="outline" size="sm" onClick={() => build.mutate()} disabled={build.isPending}>
                    Fill the config from the preset
                  </Button>
                )}
              </div>
            </Section>
          ) : null}
          <Section title="Config">
            <LookupConfigForm module={module} value={config} onChange={setConfig} />
          </Section>
          <DialogFooter>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={!name.trim() || !id.valid || !moduleId || save.isPending}>
              Create
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------------------------

export function LookupProviderDetailPage() {
  const { providerId } = useParams({ strict: false }) as { providerId: string };
  const search = useSearch({ strict: false }) as { tab?: string };
  const navigate = useNavigate();
  const provider = useEntity("lookup-providers", providerId);
  const modules = useLookupModules();
  const tab = search.tab ?? "status";
  // Once loaded, a failed refetch keeps the page (and the entity form's draft) mounted; the form says so (core.md §12).
  if (provider.data === undefined) return provider.error ? <ErrorState error={provider.error} onRetry={() => void provider.refetch()} /> : <LoadingState rows={8} />;
  const p = provider.data;
  const mods = modulesOf(modules.data);
  const warnings = providerWarnings(p, mods);
  return (
    <div className="space-y-4">
      <PageHeader
        title={<SafeText>{p.name || p.id}</SafeText>}
        description={
          <span className="flex flex-wrap items-center gap-2">
            id <Mono>{p.id}</Mono> · module <Mono>{p.module}</Mono> <Badge variant="outline">{p.category}</Badge>
            {warnings.length > 0 && <Badge variant="warning">Unencrypted</Badge>}
            <span className="text-xs text-muted-foreground">cache generation <Mono>{p.cache_generation}</Mono></span>
          </span>
        }
        actions={<ProviderActions provider={p} />}
      />
      <Tabs value={tab} onValueChange={(t) => void navigate({ to: ".", search: (s: Record<string, unknown>) => ({ ...s, tab: t }), replace: true })}>
        <TabsList>
          <TabsTrigger value="status">Status</TabsTrigger>
          <TabsTrigger value="charts">Charts</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
        </TabsList>
        <TabsContent value="status">
          <ProviderStatusView provider={p} />
        </TabsContent>
        <TabsContent value="charts">
          <ProviderCharts id={p.id ?? ""} />
        </TabsContent>
        <TabsContent value="settings">
          <ProviderSettings provider={p} module={mods.find((m) => m.id === p.module)} onDeleted={() => void navigate({ to: "/lookup-providers" })} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

/**
 * Test now's `409` (lookups/api.rs `test_now`, core c58ba80): core tests the provider as core.db
 * holds it, once its lookup runtime has loaded that config, and answers `409 conflict` ("provider
 * is being reloaded") when it hasn't within a short wait: right after a save, or a reload that
 * failed. Nothing ran; trying again shortly is the remedy.
 */
export function isReloading(e: unknown): boolean {
  return e instanceof ApiError && e.status === 409;
}

function ProviderActions({ provider }: { provider: LookupProviderDef }) {
  const id = provider.id ?? "";
  const qc = useQueryClient();
  const edges = useEdges();
  const [edge, setEdge] = React.useState<string>("__all");
  const test = useMutation({
    // Core runs one self-test in its light lane with the committed config and answers with the
    // result (409 while its lookup runtime is still loading that config, 422 when the module names
    // no self-test for it, 503 while the light lane is full).
    mutationFn: () => unwrap(client.POST("/api/ui/v1/lookup-providers/{id}/test", { params: { path: { id } }, body: {} })),
    onSuccess: (r) => {
      const text = r.result === "pass" ? "passed" : r.result === "wrong" ? `got a wrong verdict (${r.verdict ?? "none"})` : `was inconclusive${r.why ? `: ${r.why}` : ""}`;
      (r.result === "pass" ? toast.success : toast.warning)(`Self-test of ${escapeControl(r.name)} ${escapeControl(text)}`);
      void qc.invalidateQueries({ queryKey: ["lookup-status", id] });
      invalidateConfig(qc, "lookup-providers");
    },
    // A reload in progress shows under the actions with Retry (it passes); anything else as a toast.
    onError: (e) => {
      if (!isReloading(e)) toast.error(errorMessage(e));
    },
  });
  const flush = useMutation({
    mutationFn: async () => {
      if (edge === "__all") {
        const r = await unwrap(client.POST("/api/ui/v1/lookup-providers/{id}/flush", { params: { path: { id } }, body: {} }));
        return `Cache generation moved on to ${r.cache_generation}: every edge and core start fresh.`;
      }
      await unwrap(client.POST("/api/ui/v1/edges/{id}/flush", { params: { path: { id: edge } }, body: { provider: id } }));
      return "Flush requested; pending until the edge applies it.";
    },
    onSuccess: (text) => {
      toast.success(text);
      invalidateConfig(qc, "lookup-providers");
      void qc.invalidateQueries({ queryKey: ["lookup-status", id] });
      void qc.invalidateQueries({ queryKey: ["edges"] });
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  return (
    <div className="flex flex-wrap items-center gap-2">
      {isReloading(test.error) && (
        <Alert variant="warning" className="basis-full" data-testid="test-now-reloading">
          <TriangleAlertIcon />
          <AlertTitle>Core is still loading this provider's saved settings</AlertTitle>
          <AlertDescription>
            <p>
              The self-test didn't run: core tests the provider as saved, and its lookups haven't picked up the last save yet (<SafeText>{errorMessage(test.error)}</SafeText>). This usually passes within seconds.
            </p>
            <Button size="sm" variant="outline" onClick={() => test.mutate()} disabled={test.isPending}>
              <RotateCwIcon /> Retry
            </Button>
          </AlertDescription>
        </Alert>
      )}
      <Button variant="outline" onClick={() => test.mutate()} disabled={test.isPending}>
        {test.isPending ? <Loader2Icon className="animate-spin" /> : <FlaskConicalIcon />} Test now
      </Button>
      <div className="flex items-center gap-1">
        <div className="w-48">
          <IdSelect
            value={edge}
            onChange={(v) => setEdge(v ?? "__all")}
            options={[{ value: "__all", label: "Every edge and core" }, ...(edges.data ?? []).map((e) => ({ value: e.id ?? "", label: `Edge ${e.name || e.id}` }))]}
          />
        </div>
        <Button variant="outline" onClick={() => flush.mutate()} disabled={flush.isPending}>
          <EraserIcon /> Flush cache
        </Button>
      </div>
    </div>
  );
}

function ProviderStatusView({ provider }: { provider: LookupProviderDef }) {
  const id = provider.id ?? "";
  // A provider just created can be missing from core's lookup runtime for a moment (404): retried.
  const st = useQuery({
    queryKey: ["lookup-status", id],
    queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/lookup-providers/{id}/status", { params: { path: { id } }, signal })),
    refetchInterval: 30_000,
    retry: 3,
  });
  return (
    <QueryView query={st} what="Provider status" rows={4}>
      {(s) => (
        <div className="grid gap-4 lg:grid-cols-2">
          <Section title="Self-test" description="Runs on core only: on its schedule, when the provider is saved, and from Test now. A test skips the verdict cache.">
            <div className="space-y-3">
              <SelfTestDetail value={s.last_self_test ?? provider.last_self_test} />
              {s.self_test !== undefined && s.self_test !== null && (
                <p className="text-xs text-muted-foreground">
                  The module's test for this config: <SafeText mono>{selfTestText(s.self_test)}</SafeText>
                </p>
              )}
            </div>
          </Section>
          <Section title="Calls on core" description="Async lookups, retries and re-checks core made since it started.">
            <KeyValue
              items={[
                ["Breaker", <Badge variant={s.breaker === "closed" ? "success" : "destructive"}>{escapeControl(s.breaker)}</Badge>],
                ["Paused after rejections", s.paused_until ? <>until <TimeAgo value={s.paused_until} /></> : "no"],
                ["Calls", `${formatNumber(s.calls)} (${formatNumber(s.errors)} errors, ${formatNumber(s.timeouts)} of them timeouts; ${formatNumber(s.rejected)} rejected)`],
                ["Error rate", formatPercent(s.error_rate)],
                ["Latency", s.latency_ms ? `p50 ${formatNumber(s.latency_ms.p50, 0)} ms, p99 ${formatNumber(s.latency_ms.p99, 0)} ms` : "—"],
                ["Async queue", `${formatNumber(s.queue)}${Object.keys(s.queue_by_reason).length ? ` (${Object.entries(s.queue_by_reason).map(([k, n]) => `${escapeControl(k)} ${formatNumber(n)}`).join(", ")})` : ""}`],
              ]}
            />
          </Section>
          <Section title="Verdicts on core" description="Stored verdicts of the current cache generation, the tombstones of expired ones, and the Blocks kept for alerts.">
            <KeyValue
              items={[
                ["Cache generation", <Mono>{escapeControl(s.cache_generation)}</Mono>],
                ["Verdicts", formatNumber(s.verdicts)],
                ["Tombstones", formatNumber(s.tombstones)],
                ["Blocks kept", formatNumber(s.blocks)],
              ]}
            />
          </Section>
          <Section title="Verdict set" description="What core publishes to edges for a sync provider: a base and deltas, against each edge's overlay budget.">
            {s.verdict_set ? (
              <KeyValue
                items={[
                  ["Head", <Mono>{escapeControl(s.verdict_set.head.slice(0, 16))}</Mono>],
                  ["Base", <>{formatNumber(s.verdict_set.base_records)} records, <TimeAgo value={s.verdict_set.base_at} /></>],
                  ["Deltas since", formatNumber(s.verdict_set.seq)],
                  ["Overlay", `${formatNumber(s.verdict_set.overlay_entries)} entries, ${formatBytes(s.verdict_set.overlay_bytes)}`],
                  ["Published", <TimeAgo value={s.verdict_set.published_at} />],
                ]}
              />
            ) : (
              <p className="text-sm text-muted-foreground">None published (an async-only provider, no verdicts yet, or core's clock isn't synchronised).</p>
            )}
          </Section>
        </div>
      )}
    </QueryView>
  );
}

function selfTestText(t: unknown): string {
  const v = (t ?? {}) as { name?: string; expect?: string; cron?: string };
  return [v.name, v.expect ? `expects ${v.expect}` : null, v.cron ? `cron ${v.cron}` : null].filter(Boolean).join(", ");
}

function ratio(hits: string, misses: string) {
  return (lines: ChartLine[]): ChartLine[] => {
    const out: DerivedLine[] = [];
    const byEdge = new Map<string, { h?: ChartLine; m?: ChartLine }>();
    for (const l of lines) {
      const k = l.edge ?? "";
      const e = byEdge.get(k) ?? {};
      if (l.name === hits) e.h = l;
      if (l.name === misses) e.m = l;
      byEdge.set(k, e);
    }
    for (const [, { h, m }] of byEdge) {
      if (!h || !m) continue;
      const mm = new Map((m.points ?? []).map(([t, v]) => [Number(t), v]));
      out.push({
        ...h,
        name: "hit ratio",
        sources: [h.name, m.name],
        points: (h.points ?? []).map(([t, v]) => {
          const miss = mm.get(Number(t));
          if (v === null || v === undefined || miss === null || miss === undefined) return [t, null];
          const total = Number(v) + Number(miss);
          return [t, total > 0 ? Number(v) / total : null];
        }),
      });
    }
    return out;
  };
}

/** Core's own lookup series carry the provider as a label (metrics/mod.rs CORE_SERIES): one provider's lines. */
export function forProvider(id: string) {
  return (lines: ChartLine[]) => lines.filter((l) => l.labels?.provider === id);
}

function ProviderCharts({ id }: { id: string }) {
  const { window, edge, allowed, setWindow, setEdge } = useWindowState("metrics");
  const s = (f: string) => `lookups.${id}.${f}`;
  const perEdge = (l: ChartLine) => (l.edge ? ` · ${l.edge}` : "");
  const mine = forProvider(id);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm text-muted-foreground">On the edges, from each edge's heartbeats. Choose "Each edge" for one line per edge.</p>
        <div className="flex gap-2">
          <WindowPicker value={window} onChange={setWindow} allowed={allowed} />
          <EdgeSelector value={edge} onChange={setEdge} allowEach />
        </div>
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <MetricPanel
          title="Calls, timeouts and errors"
          series={[s("calls"), s("timeouts"), s("errors"), s("late"), s("rejected")]}
          window={window}
          edge={edge}
          specs={["calls", "timeouts", "errors", "late", "rejected"].map((f) => ({ match: (l: ChartLine) => l.name === s(f), label: (l: ChartLine) => `${f}${perEdge(l)}` }))}
        />
        <MetricPanel
          title="Call duration"
          description="p50 and p99, next to the calls."
          series={[s("call_ms.p50"), s("call_ms.p99")]}
          window={window}
          edge={edge}
          format={(v) => `${formatNumber(v, 1)} ms`}
          specs={[
            { match: (l) => l.name === s("call_ms.p50"), label: (l) => `p50${perEdge(l)}` },
            { match: (l) => l.name === s("call_ms.p99"), label: (l) => `p99${perEdge(l)}` },
          ]}
        />
        <MetricPanel
          title="RAM tier hit ratio"
          series={[s("cache_hits"), s("cache_misses")]}
          window={window}
          edge={edge}
          transform={ratio(s("cache_hits"), s("cache_misses"))}
          format={(v) => formatPercent(v, 0)}
          specs={[{ match: () => true, label: (l) => `hit ratio${perEdge(l)}` }]}
        />
        <MetricPanel
          title="Verdict-set hits"
          series={[s("set_hits"), s("cache_misses")]}
          window={window}
          edge={edge}
          specs={[
            { match: (l) => l.name === s("set_hits"), label: (l) => `verdict set${perEdge(l)}` },
            { match: (l) => l.name === s("cache_misses"), label: (l) => `RAM misses${perEdge(l)}` },
          ]}
        />
        <MetricPanel
          title="RAM tier size"
          description="Entries and bytes against max_mib, with evictions."
          series={[s("entries"), s("bytes"), s("evictions")]}
          window={window}
          edge={edge}
          specs={[
            { match: (l) => l.name === s("entries"), label: (l) => `entries${perEdge(l)}` },
            { match: (l) => l.name === s("bytes"), label: (l) => `bytes${perEdge(l)}` },
            { match: (l) => l.name === s("evictions"), label: (l) => `evictions${perEdge(l)}` },
          ]}
        />
        <MetricPanel
          title="Breaker and pauses"
          series={[s("breaker_open"), s("paused")]}
          window={window}
          edge={edge}
          specs={[
            { match: (l) => l.name === s("breaker_open"), label: (l) => `breaker open${perEdge(l)}` },
            { match: (l) => l.name === s("paused"), label: (l) => `paused${perEdge(l)}` },
          ]}
        />
      </div>
      <h3 className="text-base font-semibold">On core</h3>
      <p className="text-sm text-muted-foreground">Core's async lookups, retries and re-checks for this provider, and the verdict set it publishes.</p>
      <div className="grid gap-4 xl:grid-cols-2">
        <MetricPanel
          title="Core's calls"
          series={["lookup_calls", "lookup_timeouts", "lookup_errors", "lookup_rejected"]}
          window={window}
          edge="all"
          transform={mine}
          specs={[
            { match: (l) => l.name === "lookup_calls", label: "calls" },
            { match: (l) => l.name === "lookup_timeouts", label: "timeouts" },
            { match: (l) => l.name === "lookup_errors", label: "errors" },
            { match: (l) => l.name === "lookup_rejected", label: "rejected" },
          ]}
        />
        <MetricPanel
          title="Core's call duration"
          series={["lookup_call_ms.p50", "lookup_call_ms.p99"]}
          window={window}
          edge="all"
          transform={mine}
          format={(v) => `${formatNumber(v, 1)} ms`}
          specs={[
            { match: (l) => l.name === "lookup_call_ms.p50", label: "p50" },
            { match: (l) => l.name === "lookup_call_ms.p99", label: "p99" },
          ]}
        />
        <MetricPanel title="Verdicts by result" series={["lookup_verdicts"]} window={window} edge="all" transform={mine} kind="stacked" specs={[{ match: () => true, label: (l) => l.labels?.result ?? "?" }]} />
        <MetricPanel
          title="Queue and drops"
          description="Items waiting in core's lookup queue, and those dropped by reason."
          series={["lookup_queue", "lookup_dropped"]}
          window={window}
          edge="all"
          transform={mine}
          specs={[
            { match: (l) => l.name === "lookup_queue", label: "queued" },
            { match: (l) => l.name === "lookup_dropped", label: (l) => `dropped: ${l.labels?.reason ?? "?"}` },
          ]}
        />
        <MetricPanel
          title="Re-checks"
          series={["rechecks", "recheck_blocks"]}
          window={window}
          edge="all"
          transform={mine}
          specs={[
            { match: (l) => l.name === "rechecks", label: (l) => `re-checks: ${l.labels?.result ?? "?"}` },
            { match: (l) => l.name === "recheck_blocks", label: "Blocks found" },
          ]}
        />
        <MetricPanel
          title="Verdict set"
          description="Records in the published set and what its chain costs an edge's overlay budget."
          series={["verdict_set_records", "verdict_set_overlay_bytes"]}
          window={window}
          edge="all"
          transform={mine}
          specs={[
            { match: (l) => l.name === "verdict_set_records", label: "records" },
            { match: (l) => l.name === "verdict_set_overlay_bytes", label: "overlay bytes" },
          ]}
        />
        <MetricPanel
          title="Verdict-set publishes"
          description="Bases and deltas core published to the edges."
          series={["verdict_set_bases", "verdict_set_deltas"]}
          window={window}
          edge="all"
          transform={mine}
          specs={[
            { match: (l) => l.name === "verdict_set_bases", label: "bases" },
            { match: (l) => l.name === "verdict_set_deltas", label: "deltas" },
          ]}
        />
        <MetricPanel
          title="Core's breaker and pause"
          series={["lookup_breaker_open", "lookup_paused"]}
          window={window}
          edge="all"
          transform={mine}
          specs={[
            { match: (l) => l.name === "lookup_breaker_open", label: "breaker open" },
            { match: (l) => l.name === "lookup_paused", label: "paused" },
          ]}
        />
      </div>
    </div>
  );
}

function ProviderSettings({ provider, module, onDeleted }: { provider: LookupProviderDef; module?: LookupModule; onDeleted: () => void }) {
  const [clear, setClear] = React.useState(false);
  const bundles = useEntities("bundles");
  const overrides = React.useMemo<Record<string, FieldOverride>>(() => {
    const picker = (label: string): FieldOverride =>
      function Picker({ value, onChange, disabled, id }) {
        const v = (value as string[] | undefined) ?? [];
        return (
          <div className="flex flex-wrap gap-3 rounded-md border p-2" id={id} role="group" aria-label={label}>
            {(bundles.data ?? []).map((b) => (
              <label key={b.id} className="flex items-center gap-1.5 text-sm">
                <Checkbox checked={v.includes(b.id ?? "")} disabled={disabled} onCheckedChange={(on) => onChange(on ? [...v, b.id] : v.filter((x) => x !== b.id))} />
                <span className="font-mono text-xs">{b.id}</span>
              </label>
            ))}
          </div>
        );
      };
    return {
      "scope.include_bundles": picker("Include bundles"),
      "scope.exclude_bundles": picker("Exclude bundles"),
      "cache.block_ttl_s": ({ renderDefault, value }) => (
        <div className="space-y-1">
          {renderDefault()}
          {typeof value === "number" && value > 30 * 86400 && <p className="text-xs text-destructive">At most 30 days.</p>}
        </div>
      ),
    };
  }, [bundles.data]);
  return (
    <div className="space-y-4">
      <PresetCheck provider={provider} />
      <Section title="Provider settings" description="The settings the LookupClient applies on edge and core alike.">
        <EntityForm
          kind="lookup-providers"
          id={provider.id}
          order={["module", "category", "config", "fail_mode", "sync_timeout_ms", "async_timeout_ms"]}
          readOnly={["module", "preset"]}
          hidden={["config"]}
          overrides={overrides}
          saveFlags={{ clear_cached_verdicts: clear || undefined }}
          beforeSave={(v) => {
            const ttls = v.cache ?? {};
            if ([ttls.block_ttl_s, ttls.clean_ttl_s, ttls.unknown_ttl_s, ttls.error_ttl_s].some((t) => typeof t === "number" && t > 30 * 86400)) {
              toast.error("A verdict TTL is at most 30 days.");
              return null;
            }
            return v;
          }}
          header={(v, set) => (
            <Section title="Module config" description={`The ${escapeControl(v.module ?? "")} module's config. \${secret:name} references resolve against secrets.`}>
              <LookupConfigForm module={module} value={v.config ?? {}} onChange={(c) => set({ ...v, config: c as Record<string, unknown> })} />
            </Section>
          )}
          extraActions={
            <label className="flex items-center gap-2 text-sm">
              <Checkbox checked={clear} onCheckedChange={(on) => setClear(on === true)} /> Clear cached verdicts on save
            </label>
          }
          onDeleted={onDeleted}
        />
      </Section>
    </div>
  );
}

/** Re-apply preset: when the preset the config was built from now builds a different one. */
function PresetCheck({ provider }: { provider: LookupProviderDef }) {
  const preset = provider.preset as { id?: string; params?: unknown } | null | undefined;
  const save = useModifyEntity("lookup-providers");
  const check = useMutation({
    mutationFn: () => buildPreset(provider.module ?? "", preset?.id ?? "", preset?.params ?? {}),
  });
  React.useEffect(() => {
    if (preset?.id) check.mutate();
    // Once per provider and preset.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [provider.id, preset?.id]);
  if (!preset?.id || !check.data) return null;
  const differs = JSON.stringify(check.data.config) !== JSON.stringify(provider.config);
  if (!differs) return null;
  return (
    <Section title="The preset changed" description={`Preset ${escapeControl(preset.id)} now builds a different config than the one saved.`}>
      <div className="grid gap-3 md:grid-cols-2">
        <div>
          <h4 className="mb-1 text-xs font-medium text-muted-foreground">Saved</h4>
          <JsonBlock value={provider.config} className="max-h-48" />
        </div>
        <div>
          <h4 className="mb-1 text-xs font-medium text-muted-foreground">The preset now</h4>
          <JsonBlock value={check.data.config} className="max-h-48" />
        </div>
      </div>
      <Button
        className="mt-3"
        variant="outline"
        disabled={save.isPending}
        onClick={() =>
          save.mutate(
            { id: provider.id ?? "", change: (p) => ({ ...p, config: check.data.config as Record<string, unknown> }) },
            { onSuccess: () => toast.success("Preset re-applied"), onError: (e) => toast.error(errorMessage(e)) },
          )
        }
      >
        <RotateCcwIcon /> Re-apply preset
      </Button>
    </Section>
  );
}
