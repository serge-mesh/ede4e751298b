import * as React from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { FilePlusIcon, TriangleAlertIcon, UploadIcon } from "lucide-react";
import { PageHeader } from "@/components/common/page";
import { DataTable, type DataTableColumn } from "@/components/common/data-table";
import { QueryView } from "@/components/common/states";
import { Mono, SafeText } from "@/components/common/text";
import { TimeAgo } from "@/components/common/time";
import { InfoTip } from "@/components/common/info-tip";
import { RulePolicyControls } from "@/components/common/rule-policy";
import { TagInput } from "@/components/common/tag-input";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { IdField, useDerivedId } from "@/components/common/id-field";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { downloadCap, invalidateConfig, useEntities, useFeedStatuses, useSaveEntity } from "@/api/queries";
import { request } from "@/api/http";
import { errorMessage, hasIssues } from "@/api/errors";
import type { FeedDef, FeedStatus, Imported } from "@/api/types";
import { fieldDescription } from "@/lib/openapi";
import { formatBytes, formatCompact } from "@/lib/format";
import { escapeControl } from "@/lib/text";
import {
  EMPTY_SOURCE,
  HEAD_BYTES,
  HEADER_LINES,
  KIND_LABEL,
  declaresSettings,
  hasSource,
  importBody,
  importSizeProblem,
  inspectFile,
  inspectImport,
  type DeclaredSettings,
  type ImportKind,
  type ImportSourceValue,
} from "@/lib/import-file";

export const FORMATS = ["adblock", "hosts", "plain", "misp-warninglist"] as const;
export const CATEGORIES = ["security", "privacy", "mixed"] as const;

type Row = FeedDef & { st?: FeedStatus };

export function FeedsPage() {
  const feeds = useEntities("feeds");
  const statuses = useFeedStatuses();
  const navigate = useNavigate();
  const [dialog, setDialog] = React.useState<"new" | "import" | null>(null);
  const byId = React.useMemo(() => new Map((statuses.data ?? []).map((s) => [s.feed, s])), [statuses.data]);
  const rows: Row[] = (feeds.data ?? []).map((f) => ({ ...f, st: byId.get(f.id ?? "") }));
  const columns = React.useMemo<DataTableColumn<Row>[]>(
    () => [
      {
        id: "name",
        header: "Feed",
        accessorFn: (f) => f.name || f.id,
        cell: ({ row }) => (
          <span className="flex flex-wrap items-center gap-2">
            <Link to="/feeds/$feedId" params={{ feedId: row.original.id ?? "" }} className="font-medium hover:underline" onClick={(e) => e.stopPropagation()}>
              <SafeText>{row.original.name || row.original.id}</SafeText>
            </Link>
            {!row.original.enabled && <Badge variant="outline">disabled</Badge>}
            {row.original.system && <Badge variant="outline">system</Badge>}
          </span>
        ),
      },
      {
        id: "provider",
        header: "Provider",
        accessorFn: (f) => f.provider ?? "",
        cell: ({ row }) =>
          row.original.provider ? (
            <Link to="/feed-providers/$providerId" params={{ providerId: row.original.provider }} className="hover:underline" onClick={(e) => e.stopPropagation()}>
              <SafeText>{row.original.provider}</SafeText>
            </Link>
          ) : null,
      },
      { id: "format", header: "Format", accessorFn: (f) => f.format, cell: ({ getValue }) => <Mono>{String(getValue() ?? "")}</Mono> },
      { id: "category", header: "Category", accessorFn: (f) => f.category },
      {
        id: "entries",
        header: "Entries",
        accessorFn: (f) => (f.st?.totals.dns ?? 0) + (f.st?.totals.ip ?? 0) + (f.st?.totals.browser ?? 0),
        cell: ({ row }) => {
          const t = row.original.st?.totals;
          if (!t) return "—";
          return (
            <span className="text-xs tabular-nums" title={`dns ${t.dns ?? 0}, ip ${t.ip ?? 0}, browser ${t.browser ?? 0}`}>
              {formatCompact(t.dns)} / {formatCompact(t.ip)} / {formatCompact(t.browser)}
            </span>
          );
        },
      },
      {
        id: "hits",
        header: "Hits (24 h)",
        accessorFn: (f) => f.st?.hits_24h.decisive ?? 0,
        cell: ({ row }) => {
          const h = row.original.st?.hits_24h;
          return h ? (
            <span className="text-xs tabular-nums" title="decisive / also matched">
              {formatCompact(h.decisive)} / {formatCompact(h.also_matched)}
            </span>
          ) : (
            "—"
          );
        },
      },
      { id: "change", header: "Last change", accessorFn: (f) => f.st?.last_change ?? "", cell: ({ row }) => <TimeAgo value={row.original.st?.last_change} /> },
      {
        id: "status",
        header: "Status",
        accessorFn: (f) => (f.st?.failures ? 3 : f.st?.held_run ? 2 : f.st?.busy ? 1 : 0),
        cell: ({ row }) => {
          const s = row.original.st;
          if (!s) return "—";
          if (s.failures > 0) return <Badge variant="destructive">{s.failures} failed checks</Badge>;
          if (s.held_run) return <Badge variant="warning">held by a gate</Badge>;
          if (s.busy) return <Badge variant="secondary">busy</Badge>;
          return <Badge variant="secondary">ok</Badge>;
        },
      },
    ],
    [],
  );
  return (
    <div>
      <PageHeader
        title="Feeds"
        description="One file of rules each: a file a feed provider selects, or a manual feed stored on core. Its bundles decide its use."
        actions={
          <>
            <Button variant="outline" onClick={() => setDialog("import")}>
              <UploadIcon /> Import…
            </Button>
            <Button onClick={() => setDialog("new")}>
              <FilePlusIcon /> New manual feed
            </Button>
          </>
        }
      />
      <QueryView query={feeds} rows={6}>
        {() => (
          <DataTable
            label="Feeds"
            data={rows}
            columns={columns}
            searchable
            searchPlaceholder="Filter feeds…"
            onRowClick={(f) => void navigate({ to: "/feeds/$feedId", params: { feedId: f.id ?? "" } })}
            empty="No feeds yet."
          />
        )}
      </QueryView>
      {dialog === "new" && <NewManualFeedDialog onClose={() => setDialog(null)} />}
      {dialog === "import" && <ImportNewDialog onClose={() => setDialog(null)} />}
    </div>
  );
}

function NewManualFeedDialog({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const save = useSaveEntity("feeds");
  const [name, setName] = React.useState("");
  const id = useDerivedId("feeds", name);
  const [format, setFormat] = React.useState<FeedDef["format"]>("adblock");
  const [category, setCategory] = React.useState<FeedDef["category"]>("mixed");
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New manual feed</DialogTitle>
          <DialogDescription>Its file is stored on core and edited here. Add it to a bundle to use it.</DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate(
              { body: { id: id.id, name, format, category, provider: null, file: null } as FeedDef },
              {
                onSuccess: (o) => {
                  toast.success(`Created ${escapeControl(o.id)}`);
                  onClose();
                  void navigate({ to: "/feeds/$feedId", params: { feedId: o.id }, search: { tab: "file" } });
                },
                onError: (err) => toast.error(errorMessage(err)),
              },
            );
          }}
        >
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="nm-name">Name</Label>
              <Input id="nm-name" value={name} onChange={(e) => setName(e.target.value)} required />
            </div>
            <IdField htmlId="nm-id" kind="feeds" state={id} />
            <div className="space-y-1.5">
              <Label htmlFor="nm-format">Format</Label>
              <Select value={format} onValueChange={(v) => setFormat(v as FeedDef["format"])}>
                <SelectTrigger id="nm-format" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {FORMATS.map((f) => (
                    <SelectItem key={f} value={f}>
                      {f}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="nm-cat">Category</Label>
              <Select value={category} onValueChange={(v) => setCategory(v as FeedDef["category"])}>
                <SelectTrigger id="nm-cat" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CATEGORIES.map((c) => (
                    <SelectItem key={c} value={c}>
                      {c}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={!name.trim() || !id.valid || save.isPending}>
              Create
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** The settings an export declares, as the dialog shows them (feeds.md §4). */
function DeclaredView({ d }: { d: DeclaredSettings }) {
  const json = (v: unknown) => (v === undefined ? "—" : escapeControl(JSON.stringify(v)));
  const rows: [string, React.ReactNode][] = [
    ["Feed", d.id ? <Mono>{escapeControl(d.id)}</Mono> : "—"],
    ["Name", d.name ? <SafeText>{d.name}</SafeText> : "—"],
    ["Format", d.format ? <Mono>{escapeControl(d.format)}</Mono> : "—"],
    ["Format options", <Mono>{json(d.format_options)}</Mono>],
    ["Category", d.category ? escapeControl(d.category) : "—"],
    ["warn_on", <Mono>{json(d.warn_on)}</Mono>],
    ["Rule policy", <Mono>{json(d.rule_policy)}</Mono>],
  ];
  if (d.misp_type) rows.push(["MISP type", <Mono>{escapeControl(d.misp_type)}</Mono>]);
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 rounded-md border p-2 text-xs" aria-label="What the file declares">
      {rows.map(([k, v]) => (
        <React.Fragment key={k}>
          <dt className="text-muted-foreground">{k}</dt>
          <dd className="min-w-0 break-all">{v}</dd>
        </React.Fragment>
      ))}
    </dl>
  );
}

/**
 * A file picker or pasted text. A chosen file is never put into the text box: its head is read
 * once to tell what it is, and its body built once when sent (lib/import-file.ts).
 */
export function ImportSource({
  value,
  onChange,
  accept = ".json,.txt,.list,text/plain,application/json",
  pastePlaceholder = "A JSON export, a file export or a plain list",
  showKind = true,
}: {
  value: ImportSourceValue;
  onChange: (v: ImportSourceValue) => void;
  accept?: string;
  pastePlaceholder?: string;
  /** Say what kind of feed import it is (not for a config restore). */
  showKind?: boolean;
}) {
  const [reading, setReading] = React.useState(false);
  /** Bumped by each choice: an inspection applies only while its file is still the one chosen. */
  const choice = React.useRef(0);
  const info = value.info;
  return (
    <div className="space-y-2">
      <div className="space-y-1.5">
        <Label htmlFor="imp-file">File</Label>
        <Input
          id="imp-file"
          type="file"
          accept={accept}
          onChange={async (e) => {
            const n = ++choice.current;
            const f = e.target.files?.[0];
            if (!f) {
              setReading(false);
              onChange(EMPTY_SOURCE);
              return;
            }
            // Not sendable until inspected (hasSource), so an earlier file can't be sent meanwhile.
            onChange({ file: f, text: "", info: null });
            setReading(true);
            try {
              const inspected = await inspectFile(f);
              if (n === choice.current) onChange({ file: f, text: "", info: inspected });
            } finally {
              if (n === choice.current) setReading(false);
            }
          }}
        />
      </div>
      {!value.file && (
        <div className="space-y-1.5">
          <Label htmlFor="imp-text">…or paste</Label>
          <Textarea
            id="imp-text"
            value={value.text}
            onChange={(e) => {
              const text = e.target.value;
              onChange({ file: null, text, info: text ? inspectImport(text.slice(0, HEAD_BYTES), text.length <= HEAD_BYTES) : null });
            }}
            rows={6}
            className="font-mono text-xs"
            placeholder={pastePlaceholder}
          />
        </div>
      )}
      {reading && <p className="text-xs text-muted-foreground">Reading the file…</p>}
      {info && hasSource(value) && (
        <p className="text-xs text-muted-foreground">
          {value.file ? `${escapeControl(value.file.name)}: ` : ""}
          {showKind ? `${KIND_LABEL[info.kind]}, ` : ""}
          {value.file ? formatBytes(value.file.size) : `${formatCompact(value.text.length)} characters`}.
        </p>
      )}
    </div>
  );
}

const LINE_FORMATS = ["adblock", "hosts", "plain"] as const;

/** The settings Import… lets the admin pick for a file that declares none (feeds.md §4). */
export interface PickedSettings {
  id: string;
  name: string;
  format: string;
  category: string;
  domainsAs: string;
  /** Each switch set explicitly; unset ones take the manual-feed default (keep). */
  rulePolicy?: FeedDef["rule_policy"];
  /** The warn bundles; null follows the category. */
  warnOn?: string[] | null;
}

/** True for a file read as a plain list (a line-format list, or JSON that isn't an export). */
const isPlainList = (kind: ImportKind) => kind === "list" || kind === "json";

/**
 * The query of `POST feeds/import` (api.md §7). An export brings its own name, format,
 * format_options, rule policy, category and warn_on (feeds.md §4), and core refuses (`422`) a
 * query setting that differs from one it declares, so they are sent only for a file that declares
 * none: a plain list (format, category, domains_as, rule_policy, warn_on) or a MISP list without
 * `picket_feed` (category, warn_on; its values are names and addresses, which no rule policy
 * covers).
 */
export function importNewQuery(kind: ImportKind, v: PickedSettings): Record<string, string | undefined> {
  const base = { id: v.id || undefined, name: v.name || undefined };
  const warnOn = v.warnOn === undefined || v.warnOn === null ? undefined : v.warnOn.join(",");
  if (isPlainList(kind)) {
    const rp = v.rulePolicy ?? {};
    return {
      ...base,
      format: v.format,
      category: v.category,
      domains_as: v.format === "plain" ? v.domainsAs : undefined,
      warn_on: warnOn,
      redirects: rp.redirects ?? undefined,
      client_rules: rp.client_rules ?? undefined,
      browser_changes: rp.browser_changes ?? undefined,
    };
  }
  if (kind === "misp-list") return { ...base, category: v.category, warn_on: warnOn };
  return base;
}

const FIELD_LABEL: Record<string, string> = {
  format: "Format",
  format_options: "Format options",
  category: "Category",
  warn_on: "warn_on",
  rule_policy: "Rule policy",
  id: "Id",
  name: "Name",
};

/**
 * Core's refusal of an import that names its problems (`422`, code `validation`): each issue with
 * its field, e.g. a setting picked here that the file declares otherwise, or one that isn't the
 * feed's (feeds.md §4).
 */
export function ImportIssues({ error }: { error: unknown }) {
  if (!hasIssues(error)) return null;
  return (
    <Alert variant="destructive">
      <TriangleAlertIcon />
      <AlertTitle>Core refused the import</AlertTitle>
      <AlertDescription>
        <ul className="list-disc space-y-0.5 pl-4" aria-label="Import issues">
          {error.issues.map((i, n) => (
            <li key={n}>
              {i.field && !i.message.startsWith(`${i.field}:`) ? <span className="font-medium">{FIELD_LABEL[i.field] ?? escapeControl(i.field)}: </span> : null}
              <SafeText>{i.message}</SafeText>
            </li>
          ))}
        </ul>
        <p>Nothing changed. A file that declares its settings keeps them; change the feed afterwards on its Settings tab.</p>
      </AlertDescription>
    </Alert>
  );
}

/** warn_on for a new feed: follow the category (null), or the warn bundles named (none: no checks). */
function WarnOnPicker({ value, onChange, category }: { value: string[] | null; onChange: (v: string[] | null) => void; category: string }) {
  const bundles = useEntities("bundles");
  const warn = (bundles.data ?? []).filter((b) => b.action === "warn").map((b) => b.id ?? "");
  const follows = value === null;
  return (
    <div className="space-y-1.5 sm:col-span-2">
      <div className="flex items-center gap-1.5">
        <Label htmlFor="imp-warn-follow">warn_on</Label>
        <InfoTip text={fieldDescription("FeedDef", "warn_on")} label="About warn_on" />
      </div>
      <label className="flex items-center gap-2 text-sm">
        <Switch id="imp-warn-follow" checked={follows} onCheckedChange={(on) => onChange(on ? null : category === "security" ? ["warn-common"] : [])} aria-label="warn_on follows the category" />
        Follows the category ({category === "security" ? "warn-common" : "none"})
      </label>
      {!follows && <TagInput id="imp-warn" value={value} onChange={onChange} suggestions={warn} placeholder="Warn bundles (none: not checked)" />}
    </div>
  );
}

function ImportNewDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [src, setSrc] = React.useState<ImportSourceValue>(EMPTY_SOURCE);
  const [name, setName] = React.useState("");
  const [format, setFormat] = React.useState<string>("plain");
  const [category, setCategory] = React.useState<string>("mixed");
  const [domainsAs, setDomainsAs] = React.useState<string>("exact");
  const [rulePolicy, setRulePolicy] = React.useState<FeedDef["rule_policy"]>({});
  const [warnOn, setWarnOn] = React.useState<string[] | null>(null);
  const kind = src.info?.kind ?? "list";
  const declared = src.info?.declared ?? null;
  const fileStem = src.file?.name.replace(/\.[^.]*$/, "") ?? "";
  const id = useDerivedId("feeds", name || declared?.name || fileStem, declared?.id && !name ? declared.id : undefined);
  const m = useMutation({
    mutationFn: async () => {
      // A file core couldn't take is refused before it is read (api.md §7).
      const tooLarge = await importSizeProblem(src, await downloadCap(qc));
      if (tooLarge) throw new Error(tooLarge);
      // The body first: for a file the head didn't cover, building it reads the rest, and the
      // kind found there picks the query (feeds.md §4: an export's own settings win).
      const { body, kind: sent } = await importBody(src);
      return request<Imported>("POST", "/feeds/import", { query: importNewQuery(sent, { id: id.id, name, format, category, domainsAs, rulePolicy, warnOn }), body });
    },
    onSuccess: (r) => {
      toast.success(`Imported into a new manual feed ${escapeControl(r.feed)}${r.entries ? ` (${r.entries} entries)` : ""}`);
      invalidateConfig(qc, "feeds");
      onClose();
      void navigate({ to: "/feeds/$feedId", params: { feedId: r.feed } });
    },
    // Core's issues (a picked setting the file declares otherwise) are shown in the dialog.
    onError: (e) => {
      if (!hasIssues(e)) toast.error(errorMessage(e));
    },
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent wide>
        <DialogHeader>
          <DialogTitle>Import into a new manual feed</DialogTitle>
          <DialogDescription>
            Takes a JSON export, a file export or a plain list. An export brings its name, format, format options, rule policy, category and warn_on; pick them for a plain list.
            Every rule type is set to replace, and the id must be free.
          </DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            m.mutate();
          }}
        >
          <ImportSource
            value={src}
            onChange={(v) => {
              setSrc(v);
              m.reset();
            }}
          />
          {declared && declaresSettings(kind) && (
            <div className="space-y-1">
              <p className="text-sm">The new feed takes these settings from the file:</p>
              <DeclaredView d={declared} />
            </div>
          )}
          <div className="grid gap-4 sm:grid-cols-2">
            <IdField htmlId="imp-id" kind="feeds" state={id} label="New feed id" />
            <div className="space-y-1.5">
              <Label htmlFor="imp-name">Name (optional)</Label>
              <Input id="imp-name" value={name} onChange={(e) => setName(e.target.value)} placeholder={declared?.name ?? undefined} />
            </div>
            {isPlainList(kind) && (
              <>
                <div className="space-y-1.5">
                  <Label htmlFor="imp-format">Format</Label>
                  <Select value={format} onValueChange={setFormat}>
                    <SelectTrigger id="imp-format" className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {LINE_FORMATS.map((f) => (
                        <SelectItem key={f} value={f}>
                          {f}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                {format === "plain" && (
                  <div className="space-y-1.5">
                    <Label htmlFor="imp-domains">Names match</Label>
                    <Select value={domainsAs} onValueChange={setDomainsAs}>
                      <SelectTrigger id="imp-domains" className="w-full">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="exact">exact (AdGuard semantics)</SelectItem>
                        <SelectItem value="subdomains">with their subdomains</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                )}
              </>
            )}
            {(isPlainList(kind) || kind === "misp-list") && (
              <div className="space-y-1.5">
                <Label htmlFor="imp-cat">Category</Label>
                <Select value={category} onValueChange={setCategory}>
                  <SelectTrigger id="imp-cat" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {CATEGORIES.map((c) => (
                      <SelectItem key={c} value={c}>
                        {c}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
          </div>
          {(isPlainList(kind) || kind === "misp-list") && hasSource(src) && (
            <div className="grid gap-4 sm:grid-cols-2">
              <WarnOnPicker value={warnOn} onChange={setWarnOn} category={category} />
              {isPlainList(kind) && (
                <div className="space-y-1.5 sm:col-span-2">
                  <Label>Rule policy</Label>
                  <RulePolicyControls value={rulePolicy} onChange={setRulePolicy} manual browserMode="replace" />
                </div>
              )}
            </div>
          )}
          {src.info?.partial && hasSource(src) && (
            <p className="text-xs text-muted-foreground">
              Only the file's first {formatBytes(HEAD_BYTES)} were read to tell what it is; the rest is read when it is sent.{" "}
              {kind === "list" || kind === "file-export" ? (
                <>
                  Its comment header goes on past them: if it says <Mono>picket-feed-export</Mono> within its first {HEADER_LINES} lines, it is a file export and brings its own settings
                  (nothing picked here is sent).
                </>
              ) : (
                <>
                  If it holds <Mono>picket_feed</Mono> further on, it is a MISP export and brings its own settings (nothing picked here is sent); if it holds <Mono>list</Mono>, it is a
                  MISP warninglist and only the category is sent.
                </>
              )}
            </p>
          )}
          <ImportIssues error={m.error} />
          <DialogFooter>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={!hasSource(src) || !id.valid || m.isPending}>
              Import
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
