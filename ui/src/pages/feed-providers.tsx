import * as React from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { AlertTriangleIcon, BanIcon, LinkIcon, PackagePlusIcon, PlusIcon, RefreshCwIcon, Trash2Icon } from "lucide-react";
import { PageHeader, Section } from "@/components/common/page";
import { DataTable, type DataTableColumn } from "@/components/common/data-table";
import { QueryView, RefetchError } from "@/components/common/states";
import { Mono, RichText, SafeText } from "@/components/common/text";
import { TimeAgo } from "@/components/common/time";
import { Confirm } from "@/components/common/confirm";
import { IssueList } from "@/components/common/entity-editor";
import { IdSelect } from "@/components/common/ordered-picker";
import { SchemaForm } from "@/components/schema-form/schema-form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  invalidateConfig,
  qk,
  useDownloadModules,
  useEntities,
  useProviderStatuses,
  useModifyEntity,
  entityWrite,
  useReviewQueue,
  useSaveEntity,
} from "@/api/queries";
import { IdField, useDerivedId } from "@/components/common/id-field";
import { client, unwrap } from "@/api/http";
import { ApiError, errorMessage } from "@/api/errors";
import type { FeedProviderDef, Issue, ModuleInfo, ProviderStatus, ReviewItem } from "@/api/types";
import { defaultValue, validate, type FieldErrors, type SchemaRoot } from "@/lib/schema";
import { escapeControl } from "@/lib/text";
import { openapiRoot } from "@/lib/openapi";
import { deleteEntity } from "@/api/entities";

export function FeedProvidersPage() {
  const [adding, setAdding] = React.useState<"module" | "preset" | "url" | null>(null);
  return (
    <div className="space-y-5">
      <PageHeader
        title="Feed providers"
        description="A feed provider is a configured download module: where files come from and when to check them. Each file its files selects is one feed; one check covers them all."
        actions={
          <>
            <Button variant="outline" onClick={() => setAdding("url")}>
              <LinkIcon /> Paste a feed URL
            </Button>
            <Button variant="outline" onClick={() => setAdding("preset")}>
              <PackagePlusIcon /> From a preset
            </Button>
            <Button onClick={() => setAdding("module")}>
              <PlusIcon /> New provider
            </Button>
          </>
        }
      />
      <ReviewQueue />
      <ProviderTable />
      {adding === "module" && <NewProviderDialog onClose={() => setAdding(null)} />}
      {adding === "preset" && <PresetDialog onClose={() => setAdding(null)} />}
      {adding === "url" && <AddUrlDialog onClose={() => setAdding(null)} />}
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// New feeds awaiting review come first (core.md §12).

function ReviewQueue() {
  const q = useReviewQueue();
  const items = q.data ?? [];
  if (!q.isPending && !q.error && items.length === 0) return null;
  return (
    <Section title={`New feeds awaiting review${items.length ? ` (${items.length})` : ""}`} description="Each new file a provider selects becomes a feed in no bundle. Nothing reaches an edge or a browser list until a bundle takes it.">
      <QueryView query={q} rows={3}>
        {(list) => (
          <ul className="divide-y">
            {list.map((it) => (
              <ReviewRow key={it.feed} item={it} />
            ))}
          </ul>
        )}
      </QueryView>
    </Section>
  );
}

function ReviewRow({ item }: { item: ReviewItem }) {
  const qc = useQueryClient();
  const [bundleOpen, setBundleOpen] = React.useState(false);
  const disable = useModifyEntity("feeds");
  const del = useMutation({
    mutationFn: () => entityWrite("feeds", item.feed, () => deleteEntity("feeds", item.feed)),
    onSuccess: () => {
      toast.success("Feed deleted; its file was added to the provider's exclude");
      invalidateConfig(qc, "feeds");
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  return (
    <li className="flex flex-wrap items-center justify-between gap-2 py-2">
      <div className="min-w-0">
        <Link to="/feeds/$feedId" params={{ feedId: item.feed }} className="font-medium hover:underline">
          <SafeText>{item.name || item.feed}</SafeText>
        </Link>
        <div className="text-xs text-muted-foreground">
          {item.provider && (
            <>
              <SafeText>{item.provider}</SafeText> ·{" "}
            </>
          )}
          <SafeText mono>{item.file}</SafeText> · since <TimeAgo value={item.since} />
        </div>
      </div>
      <div className="flex gap-2">
        <Button size="sm" onClick={() => setBundleOpen(true)}>
          Add to bundle…
        </Button>
        <Button
          size="sm"
          variant="outline"
          onClick={() =>
            disable.mutate(
              { id: item.feed, change: (f) => (f.enabled === false ? null : { ...f, enabled: false }) },
              { onSuccess: () => toast.success("Feed disabled"), onError: (e) => toast.error(errorMessage(e)) },
            )
          }
          disabled={disable.isPending}
        >
          <BanIcon /> Disable
        </Button>
        <Confirm title="Delete this feed?" description="Its file goes into the provider's exclude, so it doesn't come back." destructive confirmLabel="Delete" onConfirm={() => del.mutate()}>
          <Button size="sm" variant="outline" className="text-destructive" disabled={del.isPending}>
            <Trash2Icon /> Delete
          </Button>
        </Confirm>
      </div>
      {bundleOpen && <AddToBundleDialog feed={item.feed} onClose={() => setBundleOpen(false)} />}
    </li>
  );
}

/**
 * Adds a feed to a bundle, taking every rule type it stores (rule_types null). The bundle is read
 * fresh and written back one add at a time (`modifyEntity`), so two quick adds never drop one.
 */
export function AddToBundleDialog({ feed, onClose }: { feed: string; onClose: () => void }) {
  const bundles = useEntities("bundles");
  const save = useModifyEntity("bundles");
  const [bundle, setBundle] = React.useState<string | null>(null);
  const candidates = (bundles.data ?? []).filter((b) => !(b.feeds ?? []).some((f) => f.feed === feed));
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add to bundle</DialogTitle>
          <DialogDescription>
            Adds <Mono>{escapeControl(feed)}</Mono> to a bundle, taking every rule type it stores. Edit the bundle to choose rule types or a tier.
          </DialogDescription>
        </DialogHeader>
        <IdSelect value={bundle} onChange={setBundle} options={candidates.map((b) => ({ value: b.id ?? "", label: `${b.id} (${b.action})` }))} />
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            disabled={!bundle || save.isPending}
            onClick={() => {
              if (!bundle) return;
              save.mutate(
                { id: bundle, change: (b) => ((b.feeds ?? []).some((f) => f.feed === feed) ? null : { ...b, feeds: [...(b.feeds ?? []), { feed, rule_types: null }] }) },
                {
                  onSuccess: (o) => {
                    toast.success(o ? `Added to ${escapeControl(bundle)}` : `Already in ${escapeControl(bundle)}`);
                    onClose();
                  },
                  onError: (e) => toast.error(errorMessage(e)),
                },
              );
            }}
          >
            Add
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------------------------

function ProviderTable() {
  const providers = useEntities("feed-providers");
  const statuses = useProviderStatuses();
  const navigate = useNavigate();
  const byId = React.useMemo(() => new Map((statuses.data ?? []).map((s) => [s.provider, s])), [statuses.data]);
  type Row = FeedProviderDef & { st?: ProviderStatus };
  const rows: Row[] = (providers.data ?? []).map((p) => ({ ...p, st: byId.get(p.id ?? "") }));
  // A provider without a status (still reading, unreadable, not listed) shows no figures and its
  // health as unknown, never as a healthy provider with no feeds.
  const reading = statuses.isPending;
  const columns = React.useMemo<DataTableColumn<Row>[]>(
    () => [
      {
        id: "name",
        header: "Provider",
        accessorFn: (p) => p.name || p.id,
        cell: ({ row }) => (
          <span className="flex items-center gap-2">
            <Link to="/feed-providers/$providerId" params={{ providerId: row.original.id ?? "" }} className="font-medium hover:underline" onClick={(e) => e.stopPropagation()}>
              <SafeText>{row.original.name || row.original.id}</SafeText>
            </Link>
            {!row.original.enabled && <Badge variant="outline">disabled</Badge>}
            {row.original.system && <Badge variant="outline">system</Badge>}
          </span>
        ),
      },
      { id: "module", header: "Module", accessorFn: (p) => p.module, cell: ({ getValue }) => <Mono>{String(getValue() ?? "")}</Mono> },
      { id: "trigger", header: "Trigger", accessorFn: (p) => p.trigger?.kind ?? "dynamic" },
      { id: "feeds", header: "Feeds", accessorFn: (p) => p.st?.feeds.length ?? -1, cell: ({ row }) => row.original.st?.feeds.length ?? <span className="text-muted-foreground">—</span> },
      { id: "last", header: "Last check", accessorFn: (p) => p.st?.last_check ?? "", cell: ({ row }) => <TimeAgo value={row.original.st?.last_check} /> },
      { id: "next", header: "Next check", accessorFn: (p) => p.st?.next_check ?? "", cell: ({ row }) => (row.original.st?.checking ? <Badge variant="secondary">checking</Badge> : <TimeAgo value={row.original.st?.next_check} />) },
      {
        id: "health",
        header: "Health",
        accessorFn: (p) => (!p.st ? -1 : p.st.failing_since ? 2 : p.st.listing_incomplete ? 1 : 0),
        cell: ({ row }) =>
          !row.original.st ? (
            reading ? (
              <span className="text-xs text-muted-foreground">reading…</span>
            ) : (
              <Badge variant="outline">unknown</Badge>
            )
          ) : row.original.st.failing_since ? (
            <Badge variant="destructive">failing since <TimeAgo value={row.original.st.failing_since} /></Badge>
          ) : row.original.st.listing_incomplete ? (
            <Badge variant="warning">listing incomplete</Badge>
          ) : row.original.st.paused_until ? (
            <Badge variant="outline">paused (rate limit)</Badge>
          ) : (
            <Badge variant="secondary">ok</Badge>
          ),
      },
      { id: "k", header: "k", accessorFn: (p) => p.st?.k ?? "", cell: ({ getValue }) => String(getValue() || "—") },
    ],
    [reading],
  );
  const retry = () => void statuses.refetch();
  return (
    <QueryView query={providers} rows={5}>
      {() => (
        <div className="space-y-2">
          {statuses.error &&
            (statuses.data ? (
              <RefetchError error={statuses.error} onRetry={retry} />
            ) : (
              <div role="alert" className="flex flex-wrap items-center gap-2 rounded-lg border border-destructive/40 bg-destructive/5 px-3 py-2 text-sm">
                <AlertTriangleIcon className="size-4 shrink-0 text-destructive" aria-hidden />
                <span className="text-destructive">Couldn't read the providers' status: {errorMessage(statuses.error)}.</span>
                <Button variant="outline" size="sm" className="ml-auto" onClick={retry}>
                  <RefreshCwIcon /> Retry
                </Button>
              </div>
            ))}
          <DataTable
            label="Feed providers"
            data={rows}
            columns={columns}
            searchable
            searchPlaceholder="Filter providers…"
            onRowClick={(p) => void navigate({ to: "/feed-providers/$providerId", params: { providerId: p.id ?? "" } })}
            empty="No feed providers yet. Add one from a preset, by pasting a feed URL, or from a module."
          />
        </div>
      )}
    </QueryView>
  );
}

// ---------------------------------------------------------------------------------------------
// Adding

/** A module's config form (its Config JSON Schema), with x-picket-warning fields. */
export function ModuleConfigForm({
  module,
  value,
  onChange,
  errors,
  disabled,
}: {
  module: ModuleInfo | undefined;
  value: unknown;
  onChange: (v: unknown) => void;
  errors?: FieldErrors;
  disabled?: boolean;
}) {
  if (!module) return <p className="text-sm text-muted-foreground">Pick a module first.</p>;
  const schema = module.config_schema as SchemaRoot;
  return <SchemaForm schema={schema} root={schema} value={value} onChange={onChange} errors={errors} disabled={disabled} idPrefix={`cfg-${module.id}`} />;
}

/**
 * The settings a feed is created with: a provider's one file's (a module whose providers have one
 * fixed file: http, alphaMountain), or a feed's added by URL. Any feed setting (format, modes …);
 * the identity fields and the name are core's (the feed takes its provider's name).
 */
function FeedTemplateForm({ value, onChange, disabled, idPrefix }: { value: Record<string, unknown>; onChange: (v: Record<string, unknown>) => void; disabled?: boolean; idPrefix: string }) {
  return (
    <SchemaForm
      schema={{ $ref: "#/components/schemas/FeedDef" }}
      root={openapiRoot}
      value={value}
      onChange={(v) => onChange((v ?? {}) as Record<string, unknown>)}
      hidden={["id", "name", "provider", "file", "system"]}
      mode="create"
      disabled={disabled}
      idPrefix={idPrefix}
    />
  );
}

/** The feed settings a new provider of `module` starts with: its one file's defaults, else adblock. */
function feedDefaults(module: ModuleInfo | undefined): Record<string, unknown> {
  const d = module?.default_feed;
  return d && typeof d === "object" ? { ...(d as Record<string, unknown>) } : { format: "adblock" };
}

function NewProviderDialog({ onClose }: { onClose: () => void }) {
  const modules = useDownloadModules();
  const navigate = useNavigate();
  const save = useSaveEntity("feed-providers");
  const [name, setName] = React.useState("");
  const id = useDerivedId("feed-providers", name);
  const [moduleId, setModuleId] = React.useState<string>("");
  const [config, setConfig] = React.useState<unknown>({});
  const [feed, setFeed] = React.useState<Record<string, unknown>>({ format: "adblock" });
  const [errors, setErrors] = React.useState<FieldErrors>({});
  const [warnings, setWarnings] = React.useState<Issue[]>([]);
  const module = modules.data?.find((m) => m.id === moduleId);
  const pickModule = (m: string) => {
    setModuleId(m);
    const mi = modules.data?.find((x) => x.id === m);
    setConfig(mi ? (defaultValue(mi.config_schema as SchemaRoot, mi.config_schema as SchemaRoot) ?? {}) : {});
    setFeed(feedDefaults(mi));
  };
  // A module whose providers have one fixed file: that file's feed is created with the provider,
  // with the settings given here (a hosts or netset list parsed as what it is).
  const fixedFile = module?.fixed_file ?? null;
  const submit = () => {
    if (!module) return;
    const local = validate(module.config_schema as SchemaRoot, config, module.config_schema as SchemaRoot);
    const prefixed: FieldErrors = Object.fromEntries(Object.entries(local).map(([k, v]) => [k, v]));
    setErrors(prefixed);
    if (Object.keys(local).length) return;
    save.mutate(
      {
        body: {
          id: id.id,
          name,
          module: moduleId,
          config: config as Record<string, unknown>,
          files: fixedFile ? [{ match: fixedFile, feed }] : [],
        } as FeedProviderDef,
      },
      {
        onSuccess: (o) => {
          setWarnings(o.warnings ?? []);
          toast.success(`Created provider ${escapeControl(o.id)}`);
          if ((o.warnings ?? []).length === 0) {
            onClose();
            // A module that lists files is picked from on the Files tab; another's one file is read by its feed at once.
            void navigate({ to: "/feed-providers/$providerId", params: { providerId: o.id }, search: { tab: module?.lists_files ? "files" : "overview" } });
          }
        },
        onError: (e) => {
          if (e instanceof ApiError) {
            const fe = e.fieldErrors();
            setErrors(Object.fromEntries(Object.entries(fe).map(([k, v]) => [k.replace(/^config\./, ""), v])));
          }
          toast.error(errorMessage(e));
        },
      },
    );
  };
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent wide>
        <DialogHeader>
          <DialogTitle>New feed provider</DialogTitle>
          <DialogDescription>Name it, pick a download module and fill its config. For a module that lists files, pick its files afterwards on its Files tab; an http provider is one URL, read by its one feed.</DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="np-name">Name</Label>
              <Input id="np-name" value={name} onChange={(e) => setName(e.target.value)} required />
            </div>
            <IdField htmlId="np-id" kind="feed-providers" state={id} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="np-module">Download module</Label>
            <Select value={moduleId} onValueChange={pickModule}>
              <SelectTrigger id="np-module" className="w-full">
                <SelectValue placeholder="Choose a module…" />
              </SelectTrigger>
              <SelectContent>
                {(modules.data ?? []).map((m) => (
                  <SelectItem key={m.id} value={m.id}>
                    {m.id} {m.lists_files ? "(lists files: globs allowed)" : "(one file)"}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {module && (
              <p className="text-xs text-muted-foreground">
                <RichText text={(module.config_schema as { description?: string })?.description} />
              </p>
            )}
          </div>
          {module && <ModuleConfigForm module={module} value={config} onChange={setConfig} errors={errors} disabled={save.isPending} />}
          {fixedFile && (
            <div className="space-y-1.5" aria-label="Its feed">
              <p className="text-sm font-medium">Its feed</p>
              <p className="text-xs text-muted-foreground">The provider's one file is read by one feed, created with it: its settings (format, modes …).</p>
              <FeedTemplateForm value={feed} onChange={setFeed} disabled={save.isPending} idPrefix="np-feed" />
            </div>
          )}
          <IssueList issues={warnings} title="Created, with warnings" />
          <DialogFooter>
            <Button variant="ghost" onClick={onClose}>
              {warnings.length ? "Close" : "Cancel"}
            </Button>
            <Button type="submit" disabled={!name.trim() || !id.valid || !module || save.isPending}>
              Create provider
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function PresetDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const presets = useQuery({ queryKey: qk.presets, queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/feed-presets", { signal })) });
  const install = useMutation({
    mutationFn: (id: string) => unwrap(client.POST("/api/ui/v1/feed-presets/{id}", { params: { path: { id } } })),
    onSuccess: (r) => {
      toast.success(`Installed: ${r.feeds.map(escapeControl).join(", ")}${r.bundle_added ? " (added to its bundle)" : ""}`);
      invalidateConfig(qc);
      void qc.invalidateQueries({ queryKey: qk.presets });
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent wide>
        <DialogHeader>
          <DialogTitle>Feed presets</DialogTitle>
          <DialogDescription>Each creates an editable feed provider with its feeds (or a manual feed), and adds them to its bundle.</DialogDescription>
        </DialogHeader>
        <QueryView query={presets} rows={4}>
          {(list) => (
            <ul className="divide-y">
              {list.map((p) => (
                <li key={p.id} className="flex items-start justify-between gap-3 py-3">
                  <div className="min-w-0">
                    <div className="font-medium">
                      {p.title} {p.installed && <Badge variant="secondary">installed</Badge>}
                    </div>
                    <p className="text-sm text-muted-foreground">
                      <RichText text={p.description} />
                    </p>
                    {p.bundle && (
                      <p className="text-xs text-muted-foreground">
                        Bundle: <Mono>{p.bundle}</Mono>
                      </p>
                    )}
                  </div>
                  <Button size="sm" variant={p.installed ? "outline" : "default"} disabled={install.isPending} onClick={() => install.mutate(p.id)}>
                    {p.installed ? "Restore" : "Install"}
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </QueryView>
      </DialogContent>
    </Dialog>
  );
}

function AddUrlDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [url, setUrl] = React.useState("");
  const [name, setName] = React.useState("");
  const [feed, setFeed] = React.useState<Record<string, unknown>>({ format: "adblock" });
  const [result, setResult] = React.useState<{ provider: string; created: boolean; existing: boolean; feed?: string | null; notice?: string | null; warnings: Issue[] } | null>(null);
  const add = useMutation({
    mutationFn: () =>
      unwrap(
        client.POST("/api/ui/v1/feed-providers-add-url", {
          body: { url: url.trim(), name: name.trim() || null, feed },
        }),
      ),
    onSuccess: (r) => {
      invalidateConfig(qc);
      setResult({ provider: r.provider, created: r.created_provider, existing: r.existing ?? false, feed: r.feed, notice: r.notice, warnings: r.outcome.warnings ?? [] });
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const valid = /^https:\/\/\S+$/i.test(url.trim());
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add a feed by URL</DialogTitle>
          <DialogDescription>A GitHub file goes to the provider of its repository and branch; any other URL is an http provider of its own (the one of that URL, if there is one). An existing feed is kept.</DialogDescription>
        </DialogHeader>
        {result ? (
          <div className="space-y-3 text-sm">
            {result.existing && result.feed ? (
              <p>
                Already added: feed{" "}
                <Link to="/feeds/$feedId" params={{ feedId: result.feed }} className="font-medium hover:underline" onClick={onClose}>
                  <SafeText mono>{result.feed}</SafeText>
                </Link>{" "}
                of provider{" "}
                <Link to="/feed-providers/$providerId" params={{ providerId: result.provider }} className="font-medium hover:underline" onClick={onClose}>
                  <SafeText>{result.provider}</SafeText>
                </Link>
                ; nothing changed.
              </p>
            ) : (
              <p>
                {result.created ? "Created provider" : "Provider"}{" "}
                <Link to="/feed-providers/$providerId" params={{ providerId: result.provider }} className="font-medium hover:underline" onClick={onClose}>
                  <SafeText>{result.provider}</SafeText>
                </Link>
                {result.feed ? (
                  <>
                    , feed{" "}
                    <Link to="/feeds/$feedId" params={{ feedId: result.feed }} className="font-medium hover:underline" onClick={onClose}>
                      <SafeText mono>{result.feed}</SafeText>
                    </Link>
                    .
                  </>
                ) : (
                  ": its feed comes with the file's first listing."
                )}
              </p>
            )}
            {result.notice && (
              <p className="rounded-md border border-warning/60 bg-warning/10 p-2">
                <RichText text={result.notice} />
              </p>
            )}
            <IssueList issues={result.warnings} title="Warnings" />
            <DialogFooter>
              <Button
                onClick={() => {
                  onClose();
                  void navigate({ to: "/feed-providers/$providerId", params: { providerId: result.provider } });
                }}
              >
                Open the provider
              </Button>
            </DialogFooter>
          </div>
        ) : (
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              add.mutate();
            }}
          >
            <div className="space-y-1.5">
              <Label htmlFor="au-url">Feed URL</Label>
              <Input id="au-url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://raw.githubusercontent.com/owner/repo/main/list.txt" className="font-mono" required />
              {url && !valid && <p className="text-xs text-destructive">An https:// URL.</p>}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="au-name">Feed name (optional)</Label>
              <Input id="au-name" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="space-y-1.5" aria-label="The feed's settings">
              <p className="text-sm font-medium">The feed's settings</p>
              <p className="text-xs text-muted-foreground">Format, modes …: what the list is, so it's read as such (a feed added again takes these).</p>
              <FeedTemplateForm value={feed} onChange={setFeed} disabled={add.isPending} idPrefix="au-feed" />
            </div>
            <DialogFooter>
              <Button variant="ghost" onClick={onClose}>
                Cancel
              </Button>
              <Button type="submit" disabled={!valid || add.isPending}>
                Add feed
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
