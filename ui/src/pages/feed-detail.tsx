import * as React from "react";
import { Link, useNavigate, useParams, useSearch } from "@tanstack/react-router";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient, type QueryClient } from "@tanstack/react-query";
import { Text } from "@codemirror/state";
import { toast } from "sonner";
import { DownloadIcon, FileDownIcon, InfoIcon, Loader2Icon, RotateCcwIcon, SaveIcon, SearchIcon, TriangleAlertIcon, UploadIcon } from "lucide-react";
import { KeyValue, PageHeader, Section, Stat } from "@/components/common/page";
import { useDraft } from "@/components/common/drafts";
import { ErrorState, LoadingState, QueryView, RefetchError } from "@/components/common/states";
import { Mono, SafeText } from "@/components/common/text";
import { TimeAgo } from "@/components/common/time";
import { EntityForm } from "@/components/common/entity-editor";
import { CodeEditor, type CodeEditorHandle } from "@/components/common/code-editor";
import { AppendRuleButton } from "@/components/common/append-rule";
import { InfoTip } from "@/components/common/info-tip";
import { WindowPicker } from "@/components/common/window-picker";
import { MetricPanel } from "@/components/charts/metric-panel";
import { FieldShell } from "@/components/schema-form/schema-form";
import { RulePolicyControls } from "@/components/common/rule-policy";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { downloadCap, useEntities, useEntity, invalidateConfig, qk } from "@/api/queries";
import { beforeRestoreEvent, feedRunsOf, isRestore, useUiEvent } from "@/api/events";
import { nextOrder } from "@/api/order";
import { client, download, request, unwrap } from "@/api/http";
import { ApiError, NO_SUCH_ENDPOINT, errorMessage, hasIssues } from "@/api/errors";
import type { FeedDef, FeedFile, FeedStatus, Imported, JobEvent, QueryParams, RunRow } from "@/api/types";
import { fieldDescription } from "@/lib/openapi";
import { formatBytes, formatNumber, formatSeconds, formatTime } from "@/lib/format";
import { escapeControl, utf8Length } from "@/lib/text";
import { deepEqual } from "@/lib/merge";
import { EMPTY_SOURCE, hasSource, importBody, importSizeProblem, type ImportKind, type ImportSourceValue } from "@/lib/import-file";
import { ImportIssues, ImportSource } from "./feeds";
import { AddToBundleDialog } from "./feed-providers";
import { useWindowState } from "./dashboard";
import { createLine, learn, movedPast, pageWrite, placeable, recordSave, restored, timeOrder, type Line, type Save, type SaveNotice } from "./manual-line";

export function FeedDetailPage() {
  const { feedId } = useParams({ strict: false }) as { feedId: string };
  return <FeedDetail key={feedId} feedId={feedId} />;
}

function FeedDetail({ feedId }: { feedId: string }) {
  const search = useSearch({ strict: false }) as { tab?: string };
  const navigate = useNavigate();
  const feed = useEntity("feeds", feedId);
  const bundles = useEntities("bundles");
  const [importing, setImporting] = React.useState(false);
  const [toBundle, setToBundle] = React.useState(false);
  const qc = useQueryClient();
  /** The saves of a manual feed this page knows of (manual-line.ts): kept across its tabs, dropped with the page. */
  const [line] = React.useState(createLine);
  // A restore replaced core's data: a read of the file still out is sent again (its answer would
  // be the replaced file), what the page knew of the file's saves goes, and an open editor reads
  // the file (or takes that read).
  useUiEvent((ev) => {
    if (!isRestore(ev)) return;
    rereadFileOut(qc, feedId);
    restored(line);
  });
  // Once loaded, a failed refetch keeps the page mounted: the editor's text and the settings form's
  // draft stay (the form says the refetch failed; core.md §12).
  if (feed.data === undefined) return feed.error ? <ErrorState error={feed.error} onRetry={() => void feed.refetch()} /> : <LoadingState rows={8} />;
  const f = feed.data;
  const manual = !f.provider;
  const tab = search.tab ?? (manual ? "file" : "overview");
  const inBundles = (bundles.data ?? []).filter((b) => (b.feeds ?? []).some((x) => x.feed === f.id));
  return (
    <div className="space-y-4">
      <PageHeader
        title={<SafeText>{f.name || f.id}</SafeText>}
        description={
          <span className="flex flex-wrap items-center gap-2">
            id <Mono>{f.id}</Mono>
            {manual ? (
              <Badge variant="secondary">manual</Badge>
            ) : (
              <>
                · provider{" "}
                <Link to="/feed-providers/$providerId" params={{ providerId: f.provider ?? "" }} className="hover:underline">
                  <SafeText>{f.provider}</SafeText>
                </Link>{" "}
                · file <SafeText mono>{f.file}</SafeText>
              </>
            )}
            <Badge variant="outline">{f.format}</Badge>
            <Badge variant="outline">{f.category}</Badge>
            {!f.enabled && <Badge variant="outline">disabled</Badge>}
            {f.system && <Badge variant="outline">system</Badge>}
            {inBundles.length === 0 ? (
              <Badge variant="warning">in no bundle</Badge>
            ) : (
              inBundles.map((b) => (
                <Link key={b.id} to="/bundles/$bundleId" params={{ bundleId: b.id ?? "" }}>
                  <Badge variant="secondary">{escapeControl(b.id ?? "")}</Badge>
                </Link>
              ))
            )}
          </span>
        }
        actions={
          <>
            <Button variant="outline" onClick={() => setToBundle(true)}>
              Add to bundle…
            </Button>
            <ExportButtons feed={f} />
            <Button variant="outline" onClick={() => setImporting(true)}>
              <UploadIcon /> Import…
            </Button>
          </>
        }
      />
      <Tabs value={tab} onValueChange={(t) => void navigate({ to: ".", search: { tab: t }, replace: true })}>
        <TabsList>
          {manual && <TabsTrigger value="file">File</TabsTrigger>}
          <TabsTrigger value="overview">Status</TabsTrigger>
          <TabsTrigger value="entries">Entries</TabsTrigger>
          <TabsTrigger value="runs">Runs</TabsTrigger>
          {!manual && <TabsTrigger value="checks">Check history</TabsTrigger>}
          <TabsTrigger value="metrics">Metrics</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
        </TabsList>
        {manual && (
          <TabsContent value="file">
            <ManualFileEditor feed={f} line={line} />
          </TabsContent>
        )}
        <TabsContent value="overview">
          <FeedOverview feed={f} />
        </TabsContent>
        <TabsContent value="entries">
          <Entries feedId={f.id ?? ""} />
        </TabsContent>
        <TabsContent value="runs">
          <Runs feedId={f.id ?? ""} />
        </TabsContent>
        {!manual && (
          <TabsContent value="checks">
            <FeedChecks feedId={f.id ?? ""} />
          </TabsContent>
        )}
        <TabsContent value="metrics">
          <FeedMetrics feedId={f.id ?? ""} />
        </TabsContent>
        <TabsContent value="settings">
          <FeedSettings feed={f} bundleNames={inBundles.map((b) => b.id ?? "")} onDeleted={() => void navigate({ to: "/feeds" })} />
        </TabsContent>
      </Tabs>
      {importing && <ImportIntoDialog feed={f} line={line} onClose={() => setImporting(false)} />}
      {toBundle && <AddToBundleDialog feed={f.id ?? ""} onClose={() => setToBundle(false)} />}
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// Export and import (feeds.md §4)

function ExportButtons({ feed }: { feed: FeedDef }) {
  const id = feed.id ?? "";
  const size = useQuery({
    queryKey: qk.feed(id, "export-size"),
    queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/feeds/{id}/export-size", { params: { path: { id } }, signal })),
  });
  const s = size.data;
  const tooBig = s && (s.json_bytes > s.body_cap || s.file_bytes > s.file_cap);
  const run = async (asFile: boolean) => {
    try {
      await download(`/feeds/${encodeURIComponent(id)}/export`, asFile ? { as: "file" } : undefined, `${id}.${asFile && feed.format !== "misp-warninglist" ? "txt" : "json"}`);
    } catch (e) {
      toast.error(errorMessage(e));
    }
  };
  return (
    <>
      <Button variant="outline" onClick={() => void run(false)} title={s ? `${s.entries} entries, about ${formatBytes(s.json_bytes)}` : undefined}>
        <DownloadIcon /> Export
      </Button>
      <Button variant="outline" onClick={() => void run(true)} title={s ? `About ${formatBytes(s.file_bytes)} as a file` : undefined}>
        <FileDownIcon /> Export as file
      </Button>
      {tooBig && (
        <InfoTip
          label="Export size warning"
          text={`This export is about ${formatBytes(s.json_bytes)} (import bound ${formatBytes(s.body_cap)}) and would make a file of about ${formatBytes(s.file_bytes)} (download cap ${formatBytes(s.file_cap)}): importing it back would be refused.`}
          className="text-warning"
        />
      )}
    </>
  );
}

/** An export's size and the file it would make, with a warning past either limit (feeds.md §4). */
function ExportSizeLine({ feedId }: { feedId: string }) {
  const q = useQuery({
    queryKey: qk.feed(feedId, "export-size"),
    queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/feeds/{id}/export-size", { params: { path: { id: feedId } }, signal })),
  });
  const s = q.data;
  if (!s) return null;
  const jsonOver = s.json_bytes > s.body_cap;
  const fileOver = s.file_bytes > s.file_cap;
  return (
    <p className={jsonOver || fileOver ? "flex items-center gap-1.5 text-sm text-warning" : "text-sm text-muted-foreground"}>
      {(jsonOver || fileOver) && <TriangleAlertIcon className="size-4" aria-hidden />}
      Export: {formatNumber(s.entries)} entries, about {formatBytes(s.json_bytes)} as JSON (import bound {formatBytes(s.body_cap)}), about {formatBytes(s.file_bytes)} as a file (download
      cap {formatBytes(s.file_cap)}).{jsonOver || fileOver ? " Importing it back would be refused." : ""}
    </p>
  );
}

/** A manual feed's file, or null while it has none (404 from a core that serves the endpoint). */
export async function fetchManualFile(id: string, signal?: AbortSignal): Promise<FeedFile | null> {
  try {
    return await unwrap(client.GET("/api/ui/v1/feeds/{id}/file", { params: { path: { id } }, signal }));
  } catch (e) {
    if (e instanceof ApiError && e.status === 404 && e.message !== NO_SUCH_ENDPOINT) return null;
    throw e;
  }
}

/**
 * A read of a manual feed's file still out when a restore lands is cancelled and sent again
 * (TanStack's refetch replaces a read only for a query that already has data): whoever awaits it
 * (the editor's first download, before any editor is open to tell; a reload) gets the restored
 * file, and the replaced file's answer never becomes the editor's text or base.
 */
function rereadFileOut(qc: QueryClient, id: string) {
  const key = qk.manualFile(id);
  if (qc.getQueryState(key)?.fetchStatus !== "fetching") return;
  void qc.cancelQueries({ queryKey: key, exact: true }, { silent: true });
  void qc.refetchQueries({ queryKey: key, exact: true, type: "active" });
}

/** A feed's newest runs, newest first. */
async function feedRuns(id: string): Promise<RunRow[]> {
  return (await unwrap(client.GET("/api/ui/v1/feeds/{id}/runs", { params: { path: { id }, query: { limit: 20 } } }))).items;
}

/**
 * An import's `base_version` (api.md §7): the manual file's version the page shows (the editor
 * keeps it in the cache); without it, or once it may be stale (a `feed_run` while the editor was
 * closed, a 409), the feed's status says the file's version without its content.
 */
async function importBaseVersion(qc: QueryClient, id: string): Promise<string | null> {
  const state = qc.getQueryState<FeedFile | null>(qk.manualFile(id));
  if (state?.data !== undefined && !state.isInvalidated) return state.data?.version ?? null;
  const st = await unwrap(client.GET("/api/ui/v1/feeds/{id}/status", { params: { path: { id } } }));
  return st.version ?? null;
}

/**
 * The query settings of `POST feeds/{id}/import` (api.md §7) where they apply: a plain list (or
 * JSON that isn't an export) is read in the feed's format, so the dialog sends the format (and a
 * `plain` feed's `domains_as`) it showed, and core refuses the import (`422`) if the feed's
 * changed meanwhile; a MISP warninglist without `picket_feed` is one only for a
 * `misp-warninglist` feed. An export declares its own settings, which core compares with the
 * feed's.
 */
export function importIntoQuery(kind: ImportKind, feed: Pick<FeedDef, "format" | "format_options">): { format?: string; domains_as?: string } {
  if (kind === "misp-list") return { format: "misp-warninglist" };
  if (kind !== "list" && kind !== "json") return {};
  return { format: feed.format, domains_as: feed.format === "plain" ? (feed.format_options?.domains_as ?? "exact") : undefined };
}

const DISABLED_NOTICE = "The feed is disabled, so no run reads the file until it is enabled.";

function ImportIntoDialog({ feed, line, onClose }: { feed: FeedDef; line: Line; onClose: () => void }) {
  const qc = useQueryClient();
  const manual = !feed.provider;
  const id = feed.id ?? "";
  const [src, setSrc] = React.useState<ImportSourceValue>(EMPTY_SOURCE);
  const [mode, setMode] = React.useState<"replace" | "merge">(manual ? "replace" : "merge");
  const kind = src.info?.kind ?? "list";
  const m = useMutation({
    mutationFn: async () => {
      // A file core couldn't take is refused before it is read (api.md §7).
      const tooLarge = await importSizeProblem(src, await downloadCap(qc));
      if (tooLarge) throw new Error(tooLarge);
      if (!manual) {
        const { body, kind: sent } = await importBody(src);
        return request<Imported>("POST", `/feeds/${encodeURIComponent(id)}/import`, { query: { mode, ...importIntoQuery(sent, feed) }, body });
      }
      // A save of the page (manual-line.ts): as it lands, the line takes it and an open editor
      // reloads (or warns while it holds edits) and shows its run; one opened later reads the
      // file again.
      return pageWrite(
        line,
        async () => {
          const base = await importBaseVersion(qc, id);
          const { body, kind: sent } = await importBody(src);
          return request<Imported>("POST", `/feeds/${encodeURIComponent(id)}/import`, { query: { mode, base_version: base ?? undefined, ...importIntoQuery(sent, feed) }, body });
        },
        (r) => {
          if (r.changed && r.version) {
            void qc.invalidateQueries({ queryKey: qk.manualFile(id), refetchType: "none" });
            recordSave(line, { version: r.version, at: r.saved_at ?? null, content: null });
          }
          return r;
        },
      );
    },
    onSuccess: (r) => {
      // A disabled feed gets no run (feeds.md §1): its saves are ingested once it is enabled.
      toast.success(
        !manual
          ? "Import run queued."
          : !r.changed
            ? "Nothing changed: the file already holds this."
            : feed.enabled
              ? "Imported: the run's result follows."
              : `Imported. ${DISABLED_NOTICE}`,
      );
      invalidateConfig(qc, "feeds");
      void qc.invalidateQueries({ queryKey: ["feeds", id] });
      onClose();
    },
    onError: (e) => {
      if (manual && e instanceof ApiError && e.status === 409) {
        // A stale base_version (api.md §7): the cached file is older than core's; the next try
        // reads the version again.
        void qc.invalidateQueries({ queryKey: qk.manualFile(id), refetchType: "none" });
        toast.error("The file changed since this page read it (a save, an import or an append elsewhere). Import again to use the current file.");
        return;
      }
      // Core's issues (a setting that isn't the feed's) are shown in the dialog.
      if (!hasIssues(e)) toast.error(errorMessage(e));
    },
  });
  const pinned = hasSource(src) ? importIntoQuery(kind, feed) : {};
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent wide>
        <DialogHeader>
          <DialogTitle>Import into {escapeControl(feed.name || id)}</DialogTitle>
          <DialogDescription>
            {manual
              ? "Replace the file with an export or a plain list, or merge into it: imported lines keep their first-seen dates, duplicates collapse and the earlier date wins."
              : "Merge an export into this provider feed, e.g. to seed an aggregate feed: entries of types it keeps in aggregate mode are inserted with their dates; other types are skipped. Replacing a provider feed is refused, since its next download would undo it."}{" "}
            The format and format options must match the feed's.
          </DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            m.mutate();
          }}
        >
          {manual && (
            <div className="flex gap-4 text-sm" role="radiogroup" aria-label="Import mode">
              {(["replace", "merge"] as const).map((x) => (
                <label key={x} className="flex items-center gap-2">
                  <input type="radio" name="mode" checked={mode === x} onChange={() => setMode(x)} /> {x === "replace" ? "Replace the file" : "Merge into the file"}
                </label>
              ))}
            </div>
          )}
          <ImportSource
            value={src}
            onChange={(v) => {
              setSrc(v);
              m.reset();
            }}
          />
          {pinned.format && (
            <p className="text-xs text-muted-foreground">
              Read as <Mono>{pinned.format}</Mono>
              {pinned.domains_as ? (
                <>
                  {" "}
                  with names matching <Mono>{pinned.domains_as}</Mono>
                </>
              ) : null}
              {kind === "misp-list" ? ": a MISP warninglist goes only into a misp-warninglist feed." : ", the feed's format."}
            </p>
          )}
          <ImportIssues error={m.error} />
          <DialogFooter>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={!hasSource(src) || m.isPending}>
              Import
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------------------------
// Manual feed editor

interface FileMeta {
  version: string;
  saved_at: string;
  size: number;
}

const metaOf = (f: FeedFile): FileMeta => ({ version: f.version, saved_at: f.saved_at, size: f.size });
const saveOf = (f: FeedFile | null): Save => (f ? { version: f.version, at: f.saved_at } : { version: null, at: null });

/**
 * The save a run read (a stored run with its `updated_at`, or a `feed_run` event with its
 * `saved_at`), when it is a manual feed's download run of a save (feeds.md §1): a re-ingest, an
 * expiry or a confirmation (`source_run`) applies an earlier download.
 */
function savedBy(r: { kind?: string | null; source_run?: number | null; version?: string | null }, at: string | null | undefined): Save | null {
  if (r.kind !== "download" || r.source_run != null || !r.version || !at) return null;
  return { version: r.version, at };
}

/** A save waiting for its run: the page's save of this version at this save time. */
interface Waiting {
  version: string;
  at: string | null;
}

interface EditorHandlers {
  onRun: (r: RunRow) => void;
  onFile: (f: FeedFile | null) => void;
  onStatus: (st: FeedStatus) => void;
  onPageSave: (n: SaveNotice) => void;
  onSaved: (m: FileMeta, snapshot: Text) => void;
  onIdle: (st: FeedStatus, items: RunRow[]) => void;
  onJob: (j: JobEvent, seen: number) => void;
  checkMoved: (fresh?: FeedFile | null, ours?: boolean) => void;
  onRestored: (reread: boolean) => void;
}

const RESTORE_DISCARDED = "A restore replaced the file before this save's run: the save was discarded.";
const RESTORE_UNCHECKED = "A restore replaced the file before this save's run, and the file couldn't be read to check whether the save survived: reload it to see.";

function ManualFileEditor({ feed, line }: { feed: FeedDef; line: Line }) {
  const id = feed.id ?? "";
  const file = useQuery<FeedFile | null>({
    queryKey: qk.manualFile(id),
    queryFn: ({ signal }) => fetchManualFile(id, signal),
    // Up to the download cap: read when the editor opens (again after the usual staleness, or
    // after a feed_run while it was closed, so a change made elsewhere shows) or when the editor
    // asks; never on focus, on reconnect or by the events that refresh feed views (its key is
    // outside the `feeds` prefix).
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  });
  if (file.data === undefined) return file.error ? <ErrorState error={file.error} onRetry={() => void file.refetch()} /> : <LoadingState rows={8} />;
  // Once open, a failed read never closes the editor (its text may be a draft): it says so above it.
  return (
    <div className="space-y-4">
      {file.error && <RefetchError error={file.error} onRetry={() => void file.refetch()} />}
      <ManualFileEditorInner
        key={id}
        feed={feed}
        line={line}
        latest={file.data}
        reload={async (join) => {
          const r = await file.refetch({ cancelRefetch: !join });
          if (r.error) throw r.error;
          return r.data ?? null;
        }}
      />
    </div>
  );
}

/**
 * The editor (core.md §12, feeds.md §1). Its base is the save the text was edited from: the one
 * a save returned (api.md §7 `base_version`, with its `saved_at`), never one read afterwards, so
 * another writer's change after the save makes the next save a 409 instead of being dropped.
 * Runs, events, file reads and the feed's status say which save core holds, by save time
 * (manual-line.ts); when that is later than the text's base (another writer's save, or a save of
 * the page made outside this editor) a clean editor takes the file and a dirty one says so. After
 * a save the page shows the run of that save, or of a later save that took its place, waiting for
 * it (event, or polling with backoff) however long the run takes, and says so when core makes no
 * run.
 */
function ManualFileEditorInner({ feed, line, latest, reload }: { feed: FeedDef; line: Line; latest: FeedFile | null; reload: (join?: boolean) => Promise<FeedFile | null> }) {
  const id = feed.id ?? "";
  const qc = useQueryClient();
  const editor = React.useRef<CodeEditorHandle>(null);
  const [initial] = React.useState(() => latest?.content ?? "");
  const [base, setBaseState] = React.useState<FileMeta | null>(latest ? metaOf(latest) : null);
  const [dirty, setDirtyState] = React.useState(false);
  // Unsaved text: its tab keeps it while another shows (components/common/drafts.tsx).
  useDraft(dirty);
  const [conflict, setConflict] = React.useState(false);
  const [elsewhere, setElsewhere] = React.useState<string | null>(null);
  const [waiting, setWaitingState] = React.useState<Waiting | null>(null);
  const [slow, setSlow] = React.useState(false);
  const [retryAt, setRetryAt] = React.useState<string | null>(null);
  const [running, setRunning] = React.useState(false);
  const [result, setResult] = React.useState<RunRow | null>(null);
  const [notice, setNotice] = React.useState<string | null>(null);
  const [reloading, setReloading] = React.useState(false);
  // What the async handlers read: kept in step with the state above.
  const baseRef = React.useRef(base);
  /** The save the "changed elsewhere" banner was shown for: not shown again after Keep editing. */
  const bannerAt = React.useRef<string | null | undefined>(undefined);
  const dirtyRef = React.useRef(false);
  const waitingRef = React.useRef<Waiting | null>(null);
  const reloadingRef = React.useRef(false);
  /** The line moved while a reload ran: it is checked again after it. */
  const recheck = React.useRef(false);
  /** The wait a restore found (a save waiting for its run): the file read after the restore decides it (`endRestoredWait`). */
  const restoredWait = React.useRef<Waiting | null>(null);
  /** The file the page held when a restore came (shown or not yet): what the restore replaced, never placed (`onFile`). */
  const replacedFile = React.useRef<FeedFile | null | undefined>(undefined);
  /** Polls at once while a save waits (a job of the feed ended, or its end may have been missed). */
  const pollNow = React.useRef<(() => void) | null>(null);
  /** When the run shown as running now was reported to start, in the page's order of reports and reads (api/order.ts). */
  const runningSeen = React.useRef(0);
  /** The handlers below, as of the last render, for the async code (events, polls, writes). */
  const handlers = React.useRef<EditorHandlers | null>(null);
  /** Reads the newest runs and places them, oldest first. */
  const checkRuns = React.useCallback(async (): Promise<RunRow[] | null> => {
    const era = line.era;
    let items: RunRow[];
    try {
      items = await feedRuns(id);
    } catch {
      return null;
    }
    // Read before a restore: runs it deleted, of saves later than the restored file's.
    if (line.era !== era) return null;
    // A write of the page in flight may make runs of a save whose time the page doesn't know yet.
    if (!placeable(line)) return null;
    for (const r of [...items].reverse()) handlers.current?.onRun(r);
    handlers.current?.checkMoved();
    return items;
  }, [id, line]);

  const setBase = (m: FileMeta | null) => {
    baseRef.current = m;
    setBaseState(m);
  };
  const setWaiting = (w: Waiting | null) => {
    waitingRef.current = w;
    setWaitingState(w);
    setSlow(false);
    setRetryAt(null);
    setRunning(false);
  };
  const finish = (run: RunRow | null, text: string | null) => {
    setWaiting(null);
    setResult(run);
    setNotice(text);
  };
  const wait = (w: Waiting) => {
    if (!feed.enabled) {
      // A disabled feed gets no run (feeds.md §1): its saves are ingested once it is enabled.
      finish(null, DISABLED_NOTICE);
      return;
    }
    setResult(null);
    setNotice(null);
    setWaiting(w);
  };

  const adopt = (fresh: FeedFile | null) => {
    editor.current?.load(fresh?.content ?? "");
    setBase(fresh ? metaOf(fresh) : null);
    setConflict(false);
    setElsewhere(null);
  };
  const showBanner = (s: Save) => {
    if (bannerAt.current === s.at) return;
    bannerAt.current = s.at;
    setElsewhere(s.version ?? "none");
    // An import's base_version reads the version again rather than take this text's.
    void qc.invalidateQueries({ queryKey: qk.manualFile(id), refetchType: "none" });
  };
  /**
   * The newest save core holds is later than this text's base: a clean editor takes the file
   * (`fresh`, when the page has it, else read), a dirty one keeps its text and says so. `ours`: a
   * save of the page, so no "changed elsewhere" toast.
   */
  const checkMoved = (fresh?: FeedFile | null, ours = false) => {
    const last = line.newest;
    if (!last || !movedPast(line, baseRef.current?.saved_at)) return;
    if (reloadingRef.current) {
      recheck.current = true;
      return;
    }
    if (dirtyRef.current) showBanner(last);
    else if (fresh !== undefined && timeOrder(fresh?.saved_at, last.at) === 0) {
      adopt(fresh);
      if (!ours) toast.info("The file changed elsewhere: reloaded.");
    } else void doReload(ours ? "ours" : "elsewhere");
  };
  /**
   * The file read after a restore that found a save waiting for its run (`restoredWait`), if that
   * wait still runs: unless the file is that save (made after the restore), the restore discarded
   * the save, and no run of it comes. `fresh`: undefined when the file couldn't be read: then the
   * page can't tell, says so, and stops waiting (a run of the save, if it stood, isn't shown).
   */
  const endRestoredWait = (fresh: FeedFile | null | undefined) => {
    const w = restoredWait.current;
    restoredWait.current = null;
    if (!w || w !== waitingRef.current) return;
    if (fresh === undefined) finish(null, RESTORE_UNCHECKED);
    else if (!(fresh && fresh.version === w.version && timeOrder(fresh.saved_at, w.at) === 0)) finish(null, RESTORE_DISCARDED);
  };
  /**
   * Reads the file and takes it; `auto` when the line moved (not the Reload button), `restored`
   * after a restore: the line forgot its saves (manual-line.ts `restored`) and takes this file's,
   * whatever its save time; a text not based on it is replaced when clean, else the banner says the
   * file changed (a save would be refused). A restore while a reload is out sends its read again
   * (FeedDetail `rereadFileOut`): that reload gets the restored file and takes it as `restored`.
   */
  const doReload = async (auto?: "ours" | "elsewhere" | "restored"): Promise<boolean> => {
    if (reloadingRef.current) return false;
    reloadingRef.current = true;
    setReloading(true);
    const doc = editor.current?.doc();
    const era = line.era;
    try {
      // The read is placed as any (onFile, as the query's data changes). After a restore, a read
      // still out is the restored file's (rereadFileOut): it is joined, not sent again.
      const fresh = await reload(auto === "restored");
      if (auto === "restored" || line.era !== era) {
        learn(line, saveOf(fresh));
        endRestoredWait(fresh);
        const b = baseRef.current;
        if ((b?.version ?? null) === (fresh?.version ?? null) && (b?.saved_at ?? null) === (fresh?.saved_at ?? null)) return true;
        if (dirtyRef.current || (editor.current && doc && editor.current.doc() !== doc)) {
          showBanner(saveOf(fresh));
          return false;
        }
        adopt(fresh);
        toast.info("A restore replaced the file: reloaded.");
        return true;
      }
      // Applies only to the text it started from: text typed meanwhile stays, and the page says
      // the file changed. (A save during the download needs typing, or is refused with a 409:
      // the file moved.)
      if (editor.current && doc && editor.current.doc() !== doc) {
        if (line.newest && movedPast(line, baseRef.current?.saved_at)) showBanner(line.newest);
        return false;
      }
      adopt(fresh);
      if (auto === "elsewhere") toast.info("The file changed elsewhere: reloaded.");
      return true;
    } catch (e) {
      toast.error(errorMessage(e));
      if (auto === "restored" || line.era !== era) endRestoredWait(undefined);
      // The file moved and couldn't be read: the text stays, and the banner offers Reload.
      if (auto && line.newest && movedPast(line, baseRef.current?.saved_at)) showBanner(line.newest);
      return false;
    } finally {
      reloadingRef.current = false;
      setReloading(false);
      if (recheck.current) {
        recheck.current = false;
        void checkRuns();
      }
    }
  };

  /** One stored run: the save it read, by its time, and whether it ends the wait. */
  const onRun = (r: RunRow) => {
    const s = savedBy(r, r.updated_at);
    if (!s) return;
    learn(line, s);
    const w = waitingRef.current;
    if (!w) return;
    const order = timeOrder(s.at, w.at);
    if (order === 0) finish(r, null);
    else if (order > 0) {
      // Saves run one at a time and each run reads the file as it is then: a newer save before
      // this one's run started means only the newer file gets a run.
      finish(r, `The file changed again before this save's run started, so the run read the newer file (version ${s.version?.slice(0, 16)}).`);
    }
  };
  /**
   * The file the editor opened on, then each read of it (an inline Retry, a reload). One the page
   * held when a restore came is what the restore replaced (a save it overtook, a read that landed
   * just before it): its save isn't placed (reads still out then are sent again: FeedDetail).
   */
  const onFile = (f: FeedFile | null) => {
    if (placeable(line) && f !== replacedFile.current) learn(line, saveOf(f));
    checkMoved(f);
  };
  /** The feed's status, read by a poll: its file's version and save time without the content. */
  const onStatus = (st: FeedStatus) => {
    if (!placeable(line)) return;
    learn(line, { version: st.version ?? null, at: st.saved_at ?? null });
    checkMoved();
  };
  /**
   * A save of the page: this editor's own (its text is already based on it), an import, or a save
   * this editor's earlier instance made and that landed after a tab switch closed it. Every open
   * editor shows its run; one whose text isn't based on it takes it or says the file changed.
   */
  const onPageSave = (n: SaveNotice) => {
    wait({ version: n.version, at: n.at });
    const known = n.content !== null && n.at !== null ? { version: n.version, content: n.content, saved_at: n.at, size: utf8Length(n.content) } : undefined;
    checkMoved(known, true);
  };
  /** This editor's own save landed: the text it sent is the new base (its run is waited for as any save of the page's). */
  const onSaved = (m: FileMeta, snapshot: Text) => {
    setConflict(false);
    setElsewhere(null);
    setBase(m);
    editor.current?.markClean(snapshot);
  };
  /**
   * Core shows the feed idle and stored no run for the save waited on: say why (feeds.md §1). A
   * disabled feed gets none. No run is coming when the newest run already read the file core
   * holds (an import's aside; a pending retry then finds nothing to do). Else a run that couldn't
   * start (a full heavy lane) or failed is tried again at `manual_retry_at`, or the run is about
   * to start (core frees the feed just before it starts a save queued behind its run): keep
   * waiting.
   */
  const onIdle = (st: FeedStatus, items: RunRow[]) => {
    const w = waitingRef.current;
    // After a restore, the file read after it decides first (endRestoredWait).
    if (!w || w === restoredWait.current) return;
    if (!st.enabled) {
      finish(null, DISABLED_NOTICE);
      return;
    }
    setRetryAt(st.manual_retry_at ?? null);
    const newestRun = items.find((r) => !!r.blob && r.kind !== "import");
    if (!(st.version && newestRun?.blob?.startsWith(st.version))) return;
    finish(
      newestRun,
      timeOrder(st.saved_at, w.at) > 0
        ? `The file changed again before this save's run started, and run ${newestRun.id} already read the newer text, so core made no new run.`
        : `Core made no new run: run ${newestRun.id} already read this text, so its result stands.`,
    );
  };
  /** A heavy job of this feed started or ended (a `job` event): an end is checked at once. */
  const onJob = (j: JobEvent, seen: number) => {
    if (!waitingRef.current) return;
    if (j.phase === "start") runningSeen.current = seen;
    setRunning(j.phase === "start");
    if (j.phase === "end") pollNow.current?.();
  };
  /** A restore: the file is read again and taken as it is; a save waiting for its run waits for that read (endRestoredWait). */
  const onRestored = (reread: boolean) => {
    restoredWait.current = waitingRef.current;
    replacedFile.current = qc.getQueryData<FeedFile | null>(qk.manualFile(id));
    // A save's answer told of the restore (`reread`; the restore event re-sends a read itself,
    // FeedDetail): a reload already out may have been answered before core took that save, so it
    // is sent again, and the file read that decides the wait is newer than the save.
    if (reread && reloadingRef.current) rereadFileOut(qc, id);
    void doReload("restored");
  };
  React.useEffect(() => {
    handlers.current = { onRun, onFile, onStatus, onPageSave, onSaved, onIdle, onJob, checkMoved, onRestored };
  });

  // The file the editor opened on, then each read of it while open.
  React.useEffect(() => {
    handlers.current?.onFile(latest);
  }, [latest]);

  React.useEffect(() => {
    // Runs stored since the file was read (or while the editor was closed).
    void checkRuns();
    const onNotice = (n: SaveNotice) => handlers.current?.onPageSave(n);
    // A write of the page that started no wait (failed, or changed nothing): runs stored while it
    // was in flight weren't placed (manual-line.ts).
    const onRecheck = () => void checkRuns();
    // A restore: the file is read again and taken as it is.
    const onRestored = (reread: boolean) => handlers.current?.onRestored(reread);
    line.listeners.add(onNotice);
    line.rechecks.add(onRecheck);
    line.restores.add(onRestored);
    return () => {
      line.listeners.delete(onNotice);
      line.rechecks.delete(onRecheck);
      line.restores.delete(onRestored);
    };
  }, [line, checkRuns]);

  useUiEvent((ev) => {
    // `lagged` and `resync`: events may have been missed (api/events.ts). While a save waits, its
    // poll reads the feed's status too, which ends a run whose end was missed.
    if (ev.type === "lagged" || ev.type === "resync") return void (pollNow.current ? pollNow.current() : checkRuns());
    if (ev.type === "job") {
      // Any run of the feed (feed_ingest, feed_reingest, …): a save's run waits behind it.
      const j = ev.data as JobEvent | null;
      if (typeof j?.kind === "string" && j.kind.startsWith("feed_") && j.target === id) handlers.current?.onJob(j, nextOrder());
      // Core dropped job reports before this one (JobEvent.dropped): this feed's end may be among them.
      if (typeof j?.dropped === "number" && j.dropped > 0) pollNow.current?.();
      return;
    }
    // Runs stored since the previous event (coalesced). Until the `restore` event of a restore
    // whose answer came first, they were stored before it (api/events.ts beforeRestoreEvent): the
    // restored file is what core holds. One that lists only some may have left this feed's out:
    // its runs are read and placed.
    if (ev.type !== "feed_run" || beforeRestoreEvent(qc)) return;
    const { runs, truncated } = feedRunsOf(ev.data);
    if (truncated) return void checkRuns();
    // Each of this feed's runs names the save it read (version, saved_at): placed without a
    // request; the runs are read only when one may be the run a save waits for (its result is
    // the stored row).
    let read = false;
    for (const d of runs) {
      if (d.feed !== id) continue;
      const s = savedBy(d, d.saved_at);
      if (!s) continue;
      if (placeable(line) && learn(line, s)) handlers.current?.checkMoved();
      const w = waitingRef.current;
      if (w && timeOrder(s.at, w.at) >= 0) read = true;
    }
    if (read) void checkRuns();
  });

  // Poll with backoff while a save waits for its run, in case the event stream is down; each poll
  // reads the feed's status first, so a feed core shows idle has stored every run it made.
  React.useEffect(() => {
    if (!waiting) return;
    let stop = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let delay = 2000;
    let polls = 0;
    let inFlight = false;
    const tick = async () => {
      if (inFlight) return;
      inFlight = true;
      clearTimeout(timer);
      try {
        const sent = nextOrder();
        const era = line.era;
        const read = await unwrap(client.GET("/api/ui/v1/feeds/{id}/status", { params: { path: { id } } })).catch(() => null);
        if (stop) return;
        const items = await checkRuns();
        if (stop || waitingRef.current !== waiting) return;
        // Read before a restore: the replaced file's version and save time, its busy state.
        const st = line.era === era ? read : null;
        // Read after the run shown as running was reported to start, and the feed isn't busy: that
        // run ended, though its end never came (a reconnect, `lagged`, `dropped`: api.md §7).
        if (st && !st.busy && sent > runningSeen.current) setRunning(false);
        if (st) handlers.current?.onStatus(st);
        if (st && items && !st.busy) handlers.current?.onIdle(st, items);
        else setRetryAt(null);
        if (stop || waitingRef.current !== waiting) return;
        polls++;
        if (polls >= 3) setSlow(true);
        timer = setTimeout(() => void tick(), delay);
        delay = Math.min(delay * 2, 30_000);
      } finally {
        inFlight = false;
      }
    };
    pollNow.current = () => void tick();
    void tick();
    return () => {
      stop = true;
      clearTimeout(timer);
      pollNow.current = null;
    };
  }, [waiting, checkRuns, id, line]);

  const save = useMutation({
    mutationFn: async () => {
      const snapshot = editor.current?.doc() ?? Text.of([initial]);
      const content = snapshot.toString();
      const sent = baseRef.current?.version ?? null;
      return pageWrite(
        line,
        () => unwrap(client.PUT("/api/ui/v1/feeds/{id}/file", { params: { path: { id } }, body: { content, base_version: sent } })),
        (r) => {
          // As it lands, whether or not this editor is still open (a tab switch closes it): the
          // line and the cache take the save (core's save time with it), this editor marks the
          // text it sent clean, and any other open editor of the feed takes the new file or says
          // it changed (manual-line.ts).
          const m: FileMeta = { version: r.version, saved_at: r.saved_at ?? baseRef.current?.saved_at ?? "", size: utf8Length(content) };
          qc.setQueryData<FeedFile>(qk.manualFile(id), { ...m, content });
          handlers.current?.onSaved(m, snapshot);
          if (r.changed) recordSave(line, { version: r.version, at: r.saved_at ?? null, content });
          return r;
        },
      );
    },
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: ["feeds", id] });
      if (!r.changed) toast.info("Nothing changed: the file already holds this text.");
      else toast.success(feed.enabled ? "Saved. The run's result follows." : "Saved.");
    },
    onError: (e) => {
      // Runs stored meanwhile are read again as the write ends (pageWrite, manual-line.ts).
      if (e instanceof ApiError && e.status === 409) setConflict(true);
      toast.error(errorMessage(e));
    },
  });
  return (
    <div className="space-y-4">
      {conflict && (
        <Alert variant="destructive">
          <TriangleAlertIcon />
          <AlertTitle>The file changed since you opened it</AlertTitle>
          <AlertDescription>
            <p>Someone saved, imported or appended to it in the meantime. Reload to see their version (your edits are lost), or copy your text first.</p>
            <Button size="sm" variant="outline" disabled={reloading} onClick={() => void doReload()}>
              <RotateCcwIcon /> Reload the file
            </Button>
          </AlertDescription>
        </Alert>
      )}
      {!conflict && elsewhere && (
        <Alert variant="warning">
          <TriangleAlertIcon />
          <AlertTitle>The file changed elsewhere</AlertTitle>
          <AlertDescription>
            <p>
              Someone saved, imported or appended to it (version <Mono>{elsewhere.slice(0, 16)}</Mono>) while you were editing. Your text isn't based on it: saving it is refused until you
              reload. Copy what you want to keep, then reload.
            </p>
            <span className="flex flex-wrap gap-2">
              <Button size="sm" variant="outline" disabled={reloading} onClick={() => void doReload()}>
                <RotateCcwIcon /> Reload the file
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setElsewhere(null)}>
                Keep editing
              </Button>
            </span>
          </AlertDescription>
        </Alert>
      )}
      <Section
        title="File"
        description={
          base ? (
            <>
              Version <Mono>{base.version.slice(0, 16)}</Mono>, saved {formatTime(base.saved_at)}, {formatBytes(base.size)}. A save is the download: it runs the feed's gates like any
              download.
            </>
          ) : (
            "No file yet."
          )
        }
        actions={
          <>
            {dirty && (
              <Button variant="ghost" onClick={() => editor.current?.revert()}>
                Discard
              </Button>
            )}
            <Button onClick={() => save.mutate()} disabled={!dirty || save.isPending}>
              {save.isPending ? <Loader2Icon className="animate-spin" /> : <SaveIcon />} Save
            </Button>
          </>
        }
      >
        <CodeEditor
          ref={editor}
          initial={initial}
          onDirtyChange={(d) => {
            dirtyRef.current = d;
            setDirtyState(d);
          }}
          ariaLabel={`File of ${feed.name || id}`}
        />
      </Section>
      {notice && (
        <Alert>
          <InfoIcon />
          <AlertDescription>{notice}</AlertDescription>
        </Alert>
      )}
      {(waiting || result) && <RunResult run={waiting ? null : result} slow={slow} retryAt={retryAt} running={running} />}
    </div>
  );
}

/** A run's result after a save or import (core.md §12). */
export function RunResult({ run, slow, retryAt, running }: { run: RunRow | null; slow?: boolean; retryAt?: string | null; running?: boolean }) {
  if (!run) {
    return (
      <Section title="Run">
        <p className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2Icon className="size-4 animate-spin" /> Waiting for the run's result…
        </p>
        {retryAt ? (
          <p className="mt-1 text-xs text-muted-foreground">
            Core is idle and has stored no run for this save yet: its run couldn't start (the heavy lane was full, or starting failed). Core tries it again at {formatTime(retryAt)}.
          </p>
        ) : running ? (
          <p className="mt-1 text-xs text-muted-foreground">A run of this feed is running now; core stores it when it ends.</p>
        ) : (
          slow && <p className="mt-1 text-xs text-muted-foreground">Still waiting: core runs one heavy job at a time, and stores a run when it ends. Its result appears here then.</p>
        )}
      </Section>
    );
  }
  const dropped = Object.entries(run.policy_dropped ?? {}).filter(([, n]) => n > 0);
  return (
    <Section title={`Run ${run.id}`} description={run.kind ? `${run.kind} run` : undefined} actions={<RunStatusBadge run={run} />}>
      <div className="space-y-3">
        {run.gate && (
          <Alert variant="warning">
            <TriangleAlertIcon />
            <AlertTitle>{run.status === "held" ? "Held by a sanity gate" : "Rejected by a sanity gate"}</AlertTitle>
            <AlertDescription>
              <span>
                Gate <Mono>{escapeControl(run.gate)}</Mono>
                {run.error ? `: ${escapeControl(run.error)}` : ""}.
                {run.status === "held" ? " The next fetch after confirm_after applies it if the source still serves it." : ""}
              </span>
            </AlertDescription>
          </Alert>
        )}
        <CountsTable run={run} />
        {run.parse && (
          <p className="text-sm text-muted-foreground">
            {formatNumber(run.parse.lines)} lines, {formatNumber(run.parse.rule_lines)} rule lines, {formatNumber(run.parse.kept)} kept, {formatNumber(run.parse.errors)} parse errors.
          </p>
        )}
        {run.parse?.error_samples && run.parse.error_samples.length > 0 && (
          <div>
            <h4 className="mb-1 text-sm font-medium">First parse errors</h4>
            <ul className="space-y-1 text-xs">
              {run.parse.error_samples.map((e, i) => (
                <li key={i} className="rounded bg-muted px-2 py-1">
                  line {e.line_no}: {escapeControl(e.reason)} — <SafeText mono>{e.text}</SafeText>
                </li>
              ))}
            </ul>
          </div>
        )}
        {dropped.length > 0 && (
          <p className="text-sm">
            rule_policy dropped: {dropped.map(([k, n]) => `${escapeControl(k)} ${formatNumber(n)}`).join(", ")}
          </p>
        )}
      </div>
    </Section>
  );
}

function RunStatusBadge({ run }: { run: RunRow }) {
  const s = run.status ?? "?";
  const v = s === "applied" ? "success" : s === "held" ? "warning" : s === "rejected" ? "destructive" : "secondary";
  return <Badge variant={v}>{s}</Badge>;
}

function CountsTable({ run }: { run: RunRow }) {
  const types = ["dns", "ip", "browser"] as const;
  return (
    <Table aria-label="Counts per rule type">
      <TableHeader>
        <TableRow>
          <TableHead>Rule type</TableHead>
          <TableHead className="text-right">Added</TableHead>
          <TableHead className="text-right">Removed</TableHead>
          <TableHead className="text-right">Total</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {types.map((t) => (
          <TableRow key={t}>
            <TableCell>{t}</TableCell>
            <TableCell className="text-right tabular-nums">{formatNumber(run.added?.[t] ?? 0)}</TableCell>
            <TableCell className="text-right tabular-nums">{formatNumber(run.removed?.[t] ?? 0)}</TableCell>
            <TableCell className="text-right tabular-nums">{formatNumber(run.total?.[t] ?? 0)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

// ---------------------------------------------------------------------------------------------

function FeedOverview({ feed }: { feed: FeedDef }) {
  const id = feed.id ?? "";
  const status = useQuery({
    queryKey: qk.feed(id, "status"),
    queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/feeds/{id}/status", { params: { path: { id } }, signal })),
  });
  const schedule = useQuery({
    queryKey: qk.feed(id, "schedule"),
    queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/feeds/{id}/schedule", { params: { path: { id } }, signal })),
    enabled: !!feed.provider,
  });
  return (
    <QueryView query={status} rows={6}>
      {(s) => (
        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-4">
            <Stat label="dns entries" value={formatNumber(s.totals.dns)} />
            <Stat label="ip entries" value={formatNumber(s.totals.ip)} />
            <Stat label="browser entries" value={formatNumber(s.totals.browser)} />
            <Stat label="Hits (24 h)" value={`${formatNumber(s.hits_24h.decisive)} / ${formatNumber(s.hits_24h.also_matched)}`} hint="decisive / also matched" />
          </div>
          <div className="grid gap-4 lg:grid-cols-2">
            <Section title="Status">
              <KeyValue
                items={[
                  ...(feed.provider
                    ? ([
                        ["Last check", <TimeAgo value={s.last_check} />],
                        ["Last good check", <TimeAgo value={s.last_ok} />],
                        ["Last download", <TimeAgo value={s.last_download} />],
                        ["Next check", <TimeAgo value={s.next_check} />],
                        ["Checks in 24 h", `${s.checks_24h} (${s.failures_24h} failed)`],
                        ["Failing", s.failures ? <span className="text-destructive">{s.failures} in a row, since {formatTime(s.failing_since)}</span> : "no"],
                        ["Rate-limit pause", s.paused_until ? formatTime(s.paused_until) : "none"],
                      ] as [string, React.ReactNode][])
                    : []),
                  ...(feed.provider
                    ? []
                    : ([
                        [
                          "File",
                          s.version ? (
                            <span>
                              version <Mono>{s.version.slice(0, 16)}</Mono>, saved <TimeAgo value={s.saved_at} />
                            </span>
                          ) : (
                            "no file yet"
                          ),
                        ],
                        ["Run retry", s.manual_retry_at ? <span className="text-warning">its run couldn't start or failed; core tries again at {formatTime(s.manual_retry_at)}</span> : "none"],
                      ] as [string, React.ReactNode][])),
                  ["Last change", <span><TimeAgo value={s.last_change} /> ({formatSeconds(s.since_last_change_s)} ago)</span>],
                  ["Changes in 7 days", s.changes_7d],
                  ["Busy", s.busy ? "a check or run is in progress" : "no"],
                  ["Held run", s.held_run ? <Badge variant="warning">run {s.held_run} waits for confirmation</Badge> : "none"],
                ]}
              />
            </Section>
            {feed.provider && (
              <Section title="Learned schedule" description="When a change to this feed is likely, learned from every successful check.">
                <KeyValue
                  items={[
                    ["Pattern", <SafeText>{s.pattern}</SafeText>],
                    ["Next ask", <TimeAgo value={s.next_ask} />],
                    ["Median detection delay", formatSeconds(s.median_delay_s)],
                    ["p90 detection delay", formatSeconds(s.p90_delay_s)],
                    ["k", schedule.data?.k ?? s.k ?? "—"],
                    ["Period", schedule.data?.period_s ? formatSeconds(schedule.data.period_s) : "none"],
                    ["Kind", schedule.data?.kind ?? "—"],
                  ]}
                />
              </Section>
            )}
          </div>
          <ExportSizeLine feedId={id} />
          {s.latest_run && <RunResult run={s.latest_run} />}
        </div>
      )}
    </QueryView>
  );
}

/**
 * The name or address an entry decides, for its one-click Allow (feeds.md §6), or null when it
 * decides no single one (patterns, regexes, `$badfilter`, CIDRs, browser rules) or no allow rule
 * can name it. `key` is core's storage key (picket-rules `Kind`): the reversed name for names and
 * hosts mappings (`org.example` for `||example.org^`), the address for IP literals and ranges.
 * Only an IPv4 address has an allow form (`@@||10.0.0.1^`); an IPv6 one (from a `plain` list, or
 * a block rule `|https://[2001:db8::1]^`) has none: `@@||2001:db8::1^` is a pattern over the
 * address text (rules.md §1).
 */
export function entryName(e: { kind: string; key: string }): string | null {
  switch (e.kind) {
    case "name":
    case "host_mapping":
      return e.key.split(".").reverse().join(".");
    case "ip_literal":
    case "ip_range":
      return e.key.includes("/") || e.key.includes(":") ? null : e.key;
    default:
      return null;
  }
}

function Entries({ feedId }: { feedId: string }) {
  const [q, setQ] = React.useState("");
  const [applied, setApplied] = React.useState("");
  const [type, setType] = React.useState<NonNullable<QueryParams<"listFeedEntries">["rule_type"]> | "all">("all");
  const query = useInfiniteQuery({
    queryKey: qk.feed(feedId, `entries:${type}:${applied}`),
    queryFn: ({ pageParam, signal }) =>
      unwrap(
        client.GET("/api/ui/v1/feeds/{id}/entries", {
          params: { path: { id: feedId }, query: { cursor: pageParam, limit: 200, q: applied || undefined, rule_type: type === "all" ? undefined : type } },
          signal,
        }),
      ),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (p) => p.next_cursor ?? undefined,
  });
  const items = query.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <Section title="Entries" description="The feed's open entries, as first seen. Allow appends an allow line to a manual feed.">
      <form
        className="mb-3 flex flex-wrap gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          setApplied(q.trim());
        }}
      >
        <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search entries" className="h-9 max-w-xs" aria-label="Search entries" />
        <Select value={type} onValueChange={(v) => setType(v as typeof type)}>
          <SelectTrigger size="sm" aria-label="Rule type">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All types</SelectItem>
            <SelectItem value="dns">dns</SelectItem>
            <SelectItem value="ip">ip</SelectItem>
            <SelectItem value="browser">browser</SelectItem>
          </SelectContent>
        </Select>
        <Button type="submit" variant="outline" size="sm">
          <SearchIcon /> Search
        </Button>
      </form>
      {query.isPending ? (
        <LoadingState rows={6} />
      ) : query.error ? (
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      ) : (
        <>
          <Table aria-label="Entries">
            <TableHeader>
              <TableRow>
                <TableHead>Rule</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Kind</TableHead>
                <TableHead>First seen</TableHead>
                <TableHead>Line</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-sm text-muted-foreground">
                    No entries.
                  </TableCell>
                </TableRow>
              )}
              {items.map((e) => (
                <TableRow key={e.id}>
                  <TableCell className="max-w-md">
                    <SafeText mono>{e.raw}</SafeText>
                    {e.dropped_at && <Badge variant="outline" className="ml-2">missing since {formatTime(e.dropped_at)}</Badge>}
                  </TableCell>
                  <TableCell>{e.rule_type}</TableCell>
                  <TableCell className="text-xs">{e.kind}</TableCell>
                  <TableCell className="text-xs">{formatTime(e.first_seen_at)}</TableCell>
                  <TableCell className="text-xs tabular-nums">{e.line_no ?? "—"}</TableCell>
                  <TableCell className="text-right">{entryName(e) !== null && <AppendRuleButton action="allow" name={entryName(e) ?? ""} />}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {query.hasNextPage && (
            <Button className="mt-3" variant="outline" onClick={() => void query.fetchNextPage()} disabled={query.isFetching}>
              Load more
            </Button>
          )}
        </>
      )}
    </Section>
  );
}

function Runs({ feedId }: { feedId: string }) {
  const q = useInfiniteQuery({
    queryKey: qk.feed(feedId, "runs"),
    queryFn: ({ pageParam, signal }) => unwrap(client.GET("/api/ui/v1/feeds/{id}/runs", { params: { path: { id: feedId }, query: { cursor: pageParam, limit: 50 } }, signal })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (p) => p.next_cursor ?? undefined,
  });
  const [open, setOpen] = React.useState<number | null>(null);
  const items = q.data?.pages.flatMap((p) => p.items) ?? [];
  if (q.isPending) return <LoadingState rows={6} />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  return (
    <Section title="Runs" description="One per change to the feed's entries: a download, a re-ingest after a settings edit, an expiry sweep or an import.">
      <Table aria-label="Runs">
        <TableHeader>
          <TableRow>
            <TableHead>Run</TableHead>
            <TableHead>Kind</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>When</TableHead>
            <TableHead className="text-right">Added</TableHead>
            <TableHead className="text-right">Removed</TableHead>
            <TableHead className="text-right">Total</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.length === 0 && (
            <TableRow>
              <TableCell colSpan={7} className="text-center text-sm text-muted-foreground">
                No runs yet.
              </TableCell>
            </TableRow>
          )}
          {items.map((r) => {
            const sum = (c?: { dns?: number; ip?: number; browser?: number }) => (c?.dns ?? 0) + (c?.ip ?? 0) + (c?.browser ?? 0);
            return (
              <React.Fragment key={r.id}>
                <TableRow className="cursor-pointer" tabIndex={0} onClick={() => setOpen(open === r.id ? null : r.id)} onKeyDown={(e) => e.key === "Enter" && setOpen(open === r.id ? null : r.id)}>
                  <TableCell>{r.id}</TableCell>
                  <TableCell>{r.kind ?? "—"}</TableCell>
                  <TableCell>
                    <RunStatusBadge run={r} />
                  </TableCell>
                  <TableCell className="text-xs">{formatTime(r.updated_at ?? r.downloaded_at)}</TableCell>
                  <TableCell className="text-right tabular-nums">{formatNumber(sum(r.added))}</TableCell>
                  <TableCell className="text-right tabular-nums">{formatNumber(sum(r.removed))}</TableCell>
                  <TableCell className="text-right tabular-nums">{formatNumber(sum(r.total))}</TableCell>
                </TableRow>
                {open === r.id && (
                  <TableRow>
                    <TableCell colSpan={7}>
                      <RunDetailView feedId={feedId} run={r} />
                    </TableCell>
                  </TableRow>
                )}
              </React.Fragment>
            );
          })}
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

function RunDetailView({ feedId, run }: { feedId: string; run: RunRow }) {
  const q = useQuery({
    queryKey: qk.feed(feedId, `run:${run.id}`),
    queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/feeds/{id}/runs/{run}", { params: { path: { id: feedId, run: String(run.id) } }, signal })),
  });
  return (
    <div className="space-y-3 py-2">
      <RunResult run={run} />
      <QueryView query={q} rows={2}>
        {(d) =>
          d.policy_drops.length === 0 ? null : (
            <div>
              <h4 className="mb-1 text-sm font-medium">Rules rule_policy dropped (first 100)</h4>
              <ul className="space-y-1 text-xs">
                {d.policy_drops.map((p) => (
                  <li key={p.id}>
                    <Badge variant="outline">{escapeControl(p.option)}</Badge> <SafeText mono>{p.raw}</SafeText>
                  </li>
                ))}
              </ul>
            </div>
          )
        }
      </QueryView>
    </div>
  );
}

function FeedChecks({ feedId }: { feedId: string }) {
  const q = useInfiniteQuery({
    queryKey: qk.feed(feedId, "checks"),
    queryFn: ({ pageParam, signal }) => unwrap(client.GET("/api/ui/v1/feeds/{id}/checks", { params: { path: { id: feedId }, query: { cursor: pageParam, limit: 100 } }, signal })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (p) => p.next_cursor ?? undefined,
  });
  const items = q.data?.pages.flatMap((p) => p.items) ?? [];
  if (q.isPending) return <LoadingState rows={6} />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  return (
    <Section title="Check history" description="Kept for 60 days.">
      <Table aria-label="Feed checks">
        <TableHeader>
          <TableRow>
            <TableHead>When</TableHead>
            <TableHead>Result</TableHead>
            <TableHead>Changed</TableHead>
            <TableHead>Method</TableHead>
            <TableHead className="text-right">Bytes</TableHead>
            <TableHead className="text-right">Duration</TableHead>
            <TableHead>Error</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.length === 0 && (
            <TableRow>
              <TableCell colSpan={7} className="text-center text-sm text-muted-foreground">
                No checks yet.
              </TableCell>
            </TableRow>
          )}
          {items.map((c) => (
            <TableRow key={c.id}>
              <TableCell className="whitespace-nowrap text-xs">{formatTime(c.t)}</TableCell>
              <TableCell>{c.ok ? <Badge variant="success">ok</Badge> : <Badge variant="destructive">failed</Badge>}</TableCell>
              <TableCell>{c.changed === null || c.changed === undefined ? "—" : c.changed ? "yes" : "no"}</TableCell>
              <TableCell className="text-xs">
                <SafeText>{c.method}</SafeText>
              </TableCell>
              <TableCell className="text-right tabular-nums">{formatBytes(c.bytes)}</TableCell>
              <TableCell className="text-right tabular-nums">{c.duration_ms !== null && c.duration_ms !== undefined ? `${formatNumber(c.duration_ms)} ms` : "—"}</TableCell>
              <TableCell className="max-w-sm text-xs">
                <SafeText>{c.error}</SafeText>
              </TableCell>
            </TableRow>
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

function FeedMetrics({ feedId }: { feedId: string }) {
  const { window, allowed, setWindow } = useWindowState("metrics");
  const mine = (l: { labels?: Record<string, string> }) => l.labels?.feed === feedId;
  const filter = (ls: { labels?: Record<string, string> }[]) => ls.filter(mine);
  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <WindowPicker value={window} onChange={setWindow} allowed={allowed} />
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <MetricPanel title="Entries per rule type" series={["feed_records_total"]} window={window} edge="all" transform={filter as never} specs={[{ match: () => true, label: (l) => l.labels?.type ?? "total" }]} />
        <MetricPanel
          title="Records added and deleted"
          series={["feed_records_added", "feed_records_deleted"]}
          window={window}
          edge="all"
          transform={filter as never}
          specs={[
            { match: (l) => l.name === "feed_records_added", label: (l) => `added ${l.labels?.type ?? ""}` },
            { match: (l) => l.name === "feed_records_deleted", label: (l) => `deleted ${l.labels?.type ?? ""}` },
          ]}
        />
        <MetricPanel
          title="Checks, parse errors and held runs"
          series={["feed_checks", "feed_parse_errors", "feed_held_runs"]}
          window={window}
          edge="all"
          transform={filter as never}
          specs={[
            { match: (l) => l.name === "feed_checks", label: (l) => `checks ${l.labels?.result ?? ""}` },
            { match: (l) => l.name === "feed_parse_errors", label: "parse errors" },
            { match: (l) => l.name === "feed_held_runs", label: "held runs" },
          ]}
        />
        <MetricPanel title="Hits" description="From attribution: decisive and also-matched." series={["feed_hits"]} window={window} edge="all" transform={filter as never} specs={[{ match: () => true, label: (l) => l.labels?.role ?? "hits" }]} />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// Settings, with the rule policy switches (core.md §12, feeds.md §8)

/** An edit whose re-ingest replaces the feed's open entries in every mode (feeds.md §3). */
export function replacesEntries(draft: FeedDef, saved: FeedDef): boolean {
  return draft.format !== saved.format || !deepEqual(draft.format_options ?? {}, saved.format_options ?? {});
}

function ReplaceWarning({ feed }: { feed: FeedDef }) {
  return (
    <div className="space-y-2">
      <p>
        A new format or format options re-ingest the latest applied file ({feed.provider ? "the last download" : "the last save"}) as a new run, and that run's entries replace the feed's
        open entries in every mode: entries collected under the old settings close.{feed.provider ? " An aggregate feed loses the history that isn't in its latest file." : ""} Export
        first to keep them{feed.provider ? "; Import… can merge them back" : ""}.
      </p>
      <span className="flex flex-wrap items-center gap-2">
        <ExportButtons feed={feed} />
      </span>
    </div>
  );
}

function FeedSettings({ feed, bundleNames, onDeleted }: { feed: FeedDef; bundleNames: string[]; onDeleted: () => void }) {
  const manual = !feed.provider;
  return (
    <Section title="Feed settings" description={manual ? "A manual feed's settings; its file is edited on the File tab." : "The provider and file are fixed: the provider's files decide them."}>
      <EntityForm
        kind="feeds"
        id={feed.id}
        hidden={["rule_policy"]}
        readOnly={["provider", "file"]}
        order={["enabled", "format", "category", "provider", "file", "modes", "format_options", "warn_on", "sanity"]}
        header={(v, set) => (
          <FieldShell id="rule-policy" label="Rule policy" name="rule_policy" description={fieldDescription("FeedDef", "rule_policy")} block>
            <RulePolicyControls value={v.rule_policy} manual={manual} browserMode={v.modes?.browser?.mode ?? "drop"} onChange={(rp) => set({ ...v, rule_policy: rp })} />
          </FieldShell>
        )}
        footer={(v, saved) =>
          saved && replacesEntries(v, saved) ? (
            <Alert variant="warning">
              <TriangleAlertIcon />
              <AlertTitle>Saving replaces the feed's entries</AlertTitle>
              <AlertDescription>
                <ReplaceWarning feed={feed} />
              </AlertDescription>
            </Alert>
          ) : null
        }
        confirmSave={(v, saved) =>
          saved && replacesEntries(v, saved)
            ? { title: "Replace the feed's entries?", description: <ReplaceWarning feed={feed} />, confirmLabel: "Save and replace them" }
            : null
        }
        onDeleted={onDeleted}
        deleteDescription={
          bundleNames.length ? (
            <span>
              It is removed from {bundleNames.length === 1 ? "bundle" : "bundles"} {bundleNames.map(escapeControl).join(", ")}.
              {!manual && " Its file goes into the provider's exclude, so it doesn't come back."}
            </span>
          ) : !manual ? (
            "Its file goes into the provider's exclude, so it doesn't come back."
          ) : undefined
        }
      />
    </Section>
  );
}
