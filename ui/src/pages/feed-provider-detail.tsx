import * as React from "react";
import { Link, useNavigate, useParams, useSearch } from "@tanstack/react-router";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArrowDownIcon, ArrowUpIcon, FileIcon, FolderIcon, PlusIcon, RefreshCwIcon, SearchIcon, XIcon } from "lucide-react";
import { KeyValue, PageHeader, Section } from "@/components/common/page";
import { ErrorState, LoadingState, PagedListError, QueryView } from "@/components/common/states";
import { Mono, SafeText } from "@/components/common/text";
import { TimeAgo } from "@/components/common/time";
import { EntityForm } from "@/components/common/entity-editor";
import { SchemaForm, type FieldOverride } from "@/components/schema-form/schema-form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { JobBadge } from "@/components/common/job-progress";
import { JOB_KIND, reportOver, useJobReports } from "@/api/events";
import { readOrder } from "@/api/order";
import { entityWrite, invalidateConfig, invalidateProviders, qk, useDownloadModules, useEntities, useEntity, useFeedStatuses, useFeedStatusesRead, useSecrets } from "@/api/queries";
import { client, unwrap } from "@/api/http";
import { errorMessage, type ApiError } from "@/api/errors";
import type { SaveFlags } from "@/api/entities";
import type { FeedProviderDef, KChoiceRecord, ProviderFile } from "@/api/types";
import type { ProviderSearch } from "@/lib/search";
import { openapiRoot, queryRange, rangeProblem, rangeText } from "@/lib/openapi";
import { defaultValue, type SchemaRoot } from "@/lib/schema";
import { formatNumber, formatPercent, formatSeconds, formatTime } from "@/lib/format";
import { escapeControl } from "@/lib/text";
import { ModuleConfigForm } from "./feed-providers";

export function FeedProviderDetailPage() {
  const { providerId } = useParams({ strict: false }) as { providerId: string };
  const search = useSearch({ strict: false }) as { tab?: string };
  const navigate = useNavigate();
  const provider = useEntity("feed-providers", providerId);
  /** When Check now last started (or queued) a check: its progress shows from then. */
  const [checkSince, setCheckSince] = React.useState<number | null>(null);
  const modules = useDownloadModules();
  // Once loaded, a failed refetch keeps the page (and the entity form's draft) mounted; the form says so (core.md §12).
  if (provider.data === undefined) return provider.error ? <ErrorState error={provider.error} onRetry={() => void provider.refetch()} /> : <LoadingState rows={8} />;
  const p = provider.data;
  // The Files tab is for a module that lists files (github); an http or alphaMountain provider has
  // one fixed file, read by its one feed (a link to the tab shows the overview). When the modules
  // can't be read (or this one is unknown), the tab shows: nothing is hidden on a guess.
  const info = modules.data?.find((m) => m.id === p.module);
  const listsFiles = modules.data ? info?.lists_files !== false : modules.isError;
  const oneFile = !!info?.fixed_file;
  const url = typeof (p.config as { url?: unknown } | undefined)?.url === "string" ? (p.config as { url: string }).url : null;
  const tab = search.tab === "files" && !listsFiles ? "overview" : (search.tab ?? "overview");
  return (
    <div className="space-y-4">
      <PageHeader
        title={<SafeText>{p.name || p.id}</SafeText>}
        description={
          <span className="flex flex-wrap items-center gap-2">
            id <Mono>{p.id}</Mono> · module <Mono>{p.module}</Mono> · trigger <Mono>{p.trigger?.kind ?? "dynamic"}</Mono>
            {p.module === "http" && url && (
              <>
                · url <SafeText mono>{url}</SafeText>
              </>
            )}
            {!p.enabled && <Badge variant="outline">disabled</Badge>}
            {p.system && <Badge variant="outline">system</Badge>}
          </span>
        }
        actions={<CheckNowButton id={p.id ?? ""} onStarted={() => setCheckSince(Date.now())} />}
      />
      {checkSince !== null && <CheckProgress id={p.id ?? ""} since={checkSince} />}
      <Tabs value={tab} onValueChange={(t) => void navigate({ to: ".", search: { tab: t }, replace: true })}>
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          {listsFiles && <TabsTrigger value="files">Files</TabsTrigger>}
          <TabsTrigger value="feeds">Feeds</TabsTrigger>
          <TabsTrigger value="checks">Check history</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
          {(p.trigger?.kind ?? "dynamic") === "dynamic" && <TabsTrigger value="backtest">Backtest</TabsTrigger>}
        </TabsList>
        <TabsContent value="overview">
          <ProviderOverview id={p.id ?? ""} url={p.module === "http" ? url : null} oneFile={oneFile} />
        </TabsContent>
        {listsFiles && (
          <TabsContent value="files">
            <ProviderFilesView provider={p} />
          </TabsContent>
        )}
        <TabsContent value="feeds">
          <ProviderFeeds id={p.id ?? ""} />
        </TabsContent>
        <TabsContent value="checks">
          <ProviderChecks id={p.id ?? ""} />
        </TabsContent>
        <TabsContent value="settings">
          <ProviderSettings provider={p} onDeleted={() => void navigate({ to: "/feed-providers" })} />
        </TabsContent>
        <TabsContent value="backtest">
          <Backtest id={p.id ?? ""} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function CheckNowButton({ id, onStarted }: { id: string; onStarted: () => void }) {
  const qc = useQueryClient();
  const m = useMutation({
    mutationFn: () => unwrap(client.POST("/api/ui/v1/feed-providers/{id}/check", { params: { path: { id } } })),
    onSuccess: (r) => {
      if (r.result === "started") toast.success("Check started: it covers every enabled feed of the provider.");
      else if (r.result === "queued") toast.info("A check is in progress; another runs when it ends.");
      else toast.info(`Scheduled for ${formatTime(r.at)} (min_interval or the module's rate-limit pause).`);
      if (r.result === "started" || r.result === "queued") onStarted();
      invalidateProviders(qc);
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  return (
    <Button onClick={() => m.mutate()} disabled={m.isPending}>
      <RefreshCwIcon className={m.isPending ? "animate-spin" : undefined} /> Check now
    </Button>
  );
}

/** A run report a later status read ended (its end was missed): ended, outcome unknown. */
const ENDED = { phase: "end", outcome: null, ms: null } as const;

/**
 * The check Check now asked for, and the runs of the provider's feeds since: a check sends no event
 * of its own, so the provider's status is read every 3 s until one read after the click says no
 * check runs; each feed's run (heavy job `feed_ingest`) shows as its `job` events report it, and a
 * run whose end was missed (api.md §7) as ended once a feed status read after its start says the
 * feed isn't busy (a reconnect, `lagged` or `dropped` re-reads them).
 */
function CheckProgress({ id, since }: { id: string; since: number }) {
  const feeds = useEntities("feeds");
  const mine = new Map((feeds.data ?? []).filter((f) => f.provider === id).map((f) => [f.id ?? "", f.name || f.id || ""]));
  const runs = useJobReports(since, (j) => j.kind === JOB_KIND.feedRun && mine.has(j.target));
  const statuses = useFeedStatusesRead().data;
  const busy = new Map((statuses ?? []).map((s) => [s.feed, s.busy]));
  const read = readOrder(statuses);
  const status = useQuery({
    queryKey: qk.provider(id, "status"),
    queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/feed-providers/{id}/status", { params: { path: { id } }, signal })),
    refetchInterval: (q) => (q.state.data?.checking !== false || q.state.dataUpdatedAt < since ? 3000 : false),
  });
  const done = status.data?.checking === false && status.dataUpdatedAt >= since;
  return (
    <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground" aria-label="Check progress">
      <span>Check asked for at {formatTime(since)}:</span>
      {done ? <Badge variant="success">check done</Badge> : <Badge variant="secondary">checking</Badge>}
      {runs.length > 0 && <span>· runs of its feeds:</span>}
      {runs.map((r) => (
        <span key={r.job} className="flex items-center gap-1">
          <SafeText>{mine.get(r.target) ?? r.target}</SafeText> <JobBadge j={reportOver(r, read, busy.get(r.target)) ? ENDED : r} />
        </span>
      ))}
    </div>
  );
}

/** `url`: an http provider's; `oneFile`: its module's providers have one fixed file, read by one feed. */
function ProviderOverview({ id, url, oneFile }: { id: string; url: string | null; oneFile: boolean }) {
  const q = useQuery({
    queryKey: qk.provider(id, "status"),
    queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/feed-providers/{id}/status", { params: { path: { id } }, signal })),
  });
  return (
    <QueryView query={q} rows={6}>
      {(s) => (
        <div className="grid gap-4 lg:grid-cols-2">
          <Section title="Status">
            <KeyValue
              items={[
                ...(url ? [["URL", <SafeText mono>{url}</SafeText>] as [string, React.ReactNode]] : []),
                ...(oneFile
                  ? [
                      [
                        "Feed",
                        s.feeds.length ? (
                          <Link to="/feeds/$feedId" params={{ feedId: s.feeds[0] }} className="hover:underline">
                            <SafeText mono>{s.feeds[0]}</SafeText>
                          </Link>
                        ) : (
                          "none"
                        ),
                      ] as [string, React.ReactNode],
                    ]
                  : []),
                ["Trigger", <Mono>{s.trigger}</Mono>],
                ["Checking", s.checking ? <Badge variant="secondary">a check is running</Badge> : "no"],
                ["Last check", <TimeAgo value={s.last_check} />],
                ["Last good check", <TimeAgo value={s.last_ok} />],
                ["Next check", <TimeAgo value={s.next_check} />],
                ["Checks in 24 h", `${s.checks_24h} (${s.failures_24h} failed)`],
                ["Failing", s.failing_since ? <span className="text-destructive">since {formatTime(s.failing_since)}</span> : "no"],
                ["Rate-limit pause", s.paused_until ? <>until {formatTime(s.paused_until)}</> : "none"],
                ["k", s.k ?? "—"],
                ...(s.k_choice ? [["Planning budget", <PlanningBudget choice={s.k_choice} />] as [string, React.ReactNode]] : []),
                ["Listing", s.listing ? `${s.listing.files} files${s.listing.whole ? "" : " (limited to what files can select)"}` : "—"],
                ["Listing incomplete", s.listing_incomplete ? <Badge variant="warning">yes: it can't add feeds</Badge> : "no"],
              ]}
            />
          </Section>
          {s.sqs && (
            <Section title="SQS trigger" description="Checks on each message, and at least every backstop.">
              <KeyValue
                items={[
                  ["Queue", s.sqs.queue ? <SafeText mono>{s.sqs.queue}</SafeText> : "—"],
                  ["Last receive", <TimeAgo value={s.sqs.last_receive_at} />],
                  ["Last message", <TimeAgo value={s.sqs.last_message_at} />],
                  ["Messages", formatNumber(s.sqs.messages)],
                  ["Last error", s.sqs.last_error ? <span><SafeText>{s.sqs.last_error}</SafeText> <TimeAgo value={s.sqs.last_error_at} /></span> : "none"],
                  ["Receives failing", s.sqs.receive_failing_since ? <>since {formatTime(s.sqs.receive_failing_since)}</> : "no"],
                  ["Deletes failing", s.sqs.delete_failing_since ? <>since {formatTime(s.sqs.delete_failing_since)}</> : "no"],
                  ["Nudged", <TimeAgo value={s.nudged_at} />],
                ]}
              />
            </Section>
          )}
        </div>
      )}
    </QueryView>
  );
}

const FORMATS = ["adblock", "hosts", "plain", "misp-warninglist"];

function fileFormat(feed: unknown): string | null {
  if (!feed || typeof feed !== "object") return null;
  const f = (feed as { format?: unknown }).format;
  return typeof f === "string" ? f : null;
}

/** The Files tab's page sizes: a folder's entries (folders and files together), and search matches. */
const FOLDER_PAGE = 500;
const SEARCH_PAGE = 100;

/** A path's folder: up to and including its last `/` (`""`: the root). */
function folderOf(path: string): string {
  return path.slice(0, path.lastIndexOf("/") + 1);
}

/** The folders on the way down to `prefix` (a folder, ending in `/`), each with its own prefix. */
function crumbs(prefix: string): { name: string; prefix: string }[] {
  const out: { name: string; prefix: string }[] = [];
  let at = 0;
  for (let i = prefix.indexOf("/"); i >= 0; i = prefix.indexOf("/", at)) {
    out.push({ name: prefix.slice(at, i), prefix: prefix.slice(0, i + 1) });
    at = i + 1;
  }
  return out;
}

/** A folder's or file's name inside folder `prefix`: what follows it, a folder's last `/` left out. */
function nameIn(prefix: string, key: string): string {
  const rest = key.slice(prefix.length);
  return rest.endsWith("/") ? rest.slice(0, -1) : rest;
}

/** A name as shown: a folder named nothing (from `a//b` or `/a`) reads "(empty)". */
function shownName(name: string): React.ReactNode {
  return name === "" ? <span className="text-muted-foreground">(empty)</span> : <SafeText mono>{name}</SafeText>;
}

function ProviderFilesView({ provider }: { provider: FeedProviderDef }) {
  const id = provider.id ?? "";
  const root = provider.name || id;
  // The folder and the search are in the URL (`?prefix=`, `?q=`), so Back walks up a folder or
  // out of a search (never leaving a search's results under a hidden breadcrumb), and both link.
  const search = useSearch({ strict: false }) as ProviderSearch;
  const prefix = search.prefix ?? "";
  const applied = search.q ?? "";
  const searching = applied !== "";
  const navigate = useNavigate();
  const go = (to: ProviderSearch) => void navigate({ to: "/feed-providers/$providerId", params: { providerId: id }, search: { tab: "files", ...to } });
  // The search box follows the URL's search (Back and Forward included); typing edits it.
  const [q, setQ] = React.useState(applied);
  const [boxFor, setBoxFor] = React.useState(applied);
  if (boxFor !== applied) {
    setBoxFor(applied);
    setQ(applied);
  }
  const qc = useQueryClient();
  // core lists S3 ListObjectsV2-style from the stored listing (up to 200,000 files): a folder's
  // folders and files merged in key order, both counting toward a page, or a search of every
  // path. Each page's folders and files append to their own list, so folders stay on top.
  const folder = useInfiniteQuery({
    queryKey: [...qk.provider(id, "listing"), "prefix", prefix],
    queryFn: ({ pageParam, signal }) =>
      unwrap(
        client.GET("/api/ui/v1/feed-providers/{id}/listing", {
          params: { path: { id }, query: { prefix: prefix || undefined, delimiter: "/", cursor: pageParam, limit: FOLDER_PAGE } },
          signal,
        }),
      ),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (p) => p.next_cursor ?? undefined,
    enabled: !searching,
  });
  const found = useInfiniteQuery({
    queryKey: [...qk.provider(id, "listing"), "q", applied],
    queryFn: ({ pageParam, signal }) =>
      unwrap(client.GET("/api/ui/v1/feed-providers/{id}/listing", { params: { path: { id }, query: { q: applied, cursor: pageParam, limit: SEARCH_PAGE } }, signal })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (p) => p.next_cursor ?? undefined,
    enabled: searching,
  });
  const view = searching ? found : folder;
  const pages = view.data?.pages ?? [];
  const listing = pages[0]?.listing;
  // Sorting by name is the browser's, over the current folder's loaded entries: folders and files
  // each by the name shown, so `hosts/` comes before `hosts-extra/` and `hosts.d/` though core's
  // key order (`/` after `-` and `.`) has it last. The direction chosen holds from folder to
  // folder (Back included) until it's chosen again.
  const [sortDesc, setSortDesc] = React.useState(false);
  const desc = !searching && sortDesc;
  const byName = <T,>(xs: T[], key: (x: T) => string): T[] => {
    if (searching) return xs;
    const named = xs.map((x) => [nameIn(prefix, key(x)), x] as const);
    named.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0) * (desc ? -1 : 1));
    return named.map(([, x]) => x);
  };
  const folders = byName(
    pages.flatMap((p) => p.prefixes),
    (f) => f.prefix,
  );
  const files = byName(
    pages.flatMap((p) => p.items),
    (f) => f.file,
  );
  const [format, setFormat] = React.useState("adblock");
  const add = useMutation({
    // It adds to the provider's `files`: in the provider's write queue, after any save of its form.
    mutationFn: (file: string) => entityWrite("feed-providers", id, () => unwrap(client.POST("/api/ui/v1/feed-providers/{id}/files", { params: { path: { id } }, body: { file, feed: { format } } }))),
    onSuccess: (o) => {
      toast.success(o.feeds_added?.length ? `Feed added: ${o.feeds_added.map(escapeControl).join(", ")}` : "Added to files");
      // Every `feed-providers` query reads again, the listing too: each loaded page, once.
      invalidateConfig(qc, "feed-providers");
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const folderLink = (to: string, label: React.ReactNode) => (
    <Link to="/feed-providers/$providerId" params={{ providerId: id }} search={{ tab: "files", prefix: to || undefined }} className="hover:underline">
      {label}
    </Link>
  );
  const fileCells = (f: ProviderFile) => (
    <>
      <TableCell>{f.selected ? <Badge variant="secondary">selected</Badge> : <span className="text-muted-foreground">no</span>}</TableCell>
      <TableCell>
        {f.feed ? (
          <Link to="/feeds/$feedId" params={{ feedId: f.feed }} className="hover:underline">
            <SafeText mono>{f.feed}</SafeText>
          </Link>
        ) : (
          <Button size="sm" variant="outline" disabled={add.isPending} onClick={() => add.mutate(f.file)}>
            <PlusIcon /> Add as feed
          </Button>
        )}
      </TableCell>
    </>
  );
  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="files" description="Globs (for a module that lists files) or paths; each selected file is a feed, with the entry's feed settings.">
          {(provider.files ?? []).length === 0 ? (
            <p className="text-sm text-muted-foreground">None yet: add files below or in Settings.</p>
          ) : (
            <ul className="space-y-1 text-sm">
              {(provider.files ?? []).map((f, i) => (
                <li key={i}>
                  <SafeText mono>{f.match}</SafeText>{" "}
                  {fileFormat(f.feed) && <Badge variant="outline">{escapeControl(fileFormat(f.feed) ?? "")}</Badge>}
                </li>
              ))}
            </ul>
          )}
        </Section>
        <Section title="exclude" description="Files never to make feeds of; a deleted provider feed's file goes here.">
          {(provider.exclude ?? []).length === 0 ? (
            <p className="text-sm text-muted-foreground">None.</p>
          ) : (
            <ul className="space-y-1 text-sm">
              {(provider.exclude ?? []).map((g) => (
                <li key={g}>
                  <SafeText mono>{g}</SafeText>
                </li>
              ))}
            </ul>
          )}
        </Section>
      </div>
      <Section
        title="Every file the provider lists"
        description="Its latest listing by folder, with each file's feed, or Add as feed, which adds the file to files."
        actions={
          <Select value={format} onValueChange={setFormat}>
            <SelectTrigger size="sm" aria-label="Format for added feeds">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {FORMATS.map((f) => (
                <SelectItem key={f} value={f}>
                  add as {f}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        }
      >
        <form
          className="mb-3 flex flex-wrap gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            go({ prefix: prefix || undefined, q: q.trim() || undefined });
          }}
        >
          <Input value={q} onChange={(e) => setQ(e.target.value)} maxLength={256} placeholder="Search every path" className="h-9 max-w-xs" aria-label="Search files" />
          <Button type="submit" variant="outline" size="sm">
            <SearchIcon /> Search
          </Button>
          {searching && (
            <Button variant="ghost" size="sm" onClick={() => go({ prefix: prefix || undefined })}>
              <XIcon /> Clear
            </Button>
          )}
        </form>
        {searching ? (
          <p className="mb-2 text-sm text-muted-foreground">
            Files of <SafeText>{root}</SafeText> whose path holds <SafeText mono>{applied}</SafeText>:
          </p>
        ) : (
          <Breadcrumb className="mb-2">
            <BreadcrumbList>
              <BreadcrumbItem>
                {prefix ? (
                  <BreadcrumbLink asChild>{folderLink("", <SafeText>{root}</SafeText>)}</BreadcrumbLink>
                ) : (
                  <BreadcrumbPage>
                    <SafeText>{root}</SafeText>
                  </BreadcrumbPage>
                )}
              </BreadcrumbItem>
              {crumbs(prefix).map((c, i, all) => (
                <React.Fragment key={c.prefix}>
                  <BreadcrumbSeparator />
                  <BreadcrumbItem>
                    {i === all.length - 1 ? (
                      <BreadcrumbPage>{shownName(c.name)}</BreadcrumbPage>
                    ) : (
                      <BreadcrumbLink asChild>{folderLink(c.prefix, shownName(c.name))}</BreadcrumbLink>
                    )}
                  </BreadcrumbItem>
                </React.Fragment>
              ))}
            </BreadcrumbList>
          </Breadcrumb>
        )}
        {view.data === undefined ? (
          view.error ? (
            <ErrorState error={view.error} onRetry={() => void view.refetch()} />
          ) : (
            <LoadingState rows={6} />
          )
        ) : (
          // Once rows show, a failed refresh or "Load more" keeps them (PagedListError).
          <div className="space-y-2">
            <PagedListError query={view} placement="top" what={searching ? "more matches" : "more files"} />
            {listing && !listing.whole && <Badge variant="outline">The module limited the listing to what files can select</Badge>}
            {!searching && view.hasNextPage && (
              <p className="text-xs text-muted-foreground">
                The folder holds more than the {formatNumber(folders.length + files.length)} entries loaded: sorting by name covers those; Load more for the rest.
              </p>
            )}
            {folders.length === 0 && files.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                {searching ? (
                  <>
                    No file's path holds <SafeText mono>{applied}</SafeText>.
                  </>
                ) : listing === null || listing === undefined ? (
                  // Before the first listing, a folder's link (one typed or shared) has nothing
                  // under it either: no listing is what to say.
                  "No listing yet: it arrives with the provider's next check."
                ) : prefix ? (
                  "Nothing under this folder in the latest listing."
                ) : (
                  "The latest listing holds no files."
                )}
              </p>
            ) : searching ? (
              <Table aria-label="Matching files">
                <TableHeader>
                  <TableRow>
                    <TableHead>File</TableHead>
                    <TableHead>Folder</TableHead>
                    <TableHead>Selected</TableHead>
                    <TableHead>Feed</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {files.map((f) => (
                    <TableRow key={f.file}>
                      <TableCell>
                        <span className="flex items-center gap-2">
                          <FileIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                          <SafeText mono>{f.file}</SafeText>
                        </span>
                      </TableCell>
                      <TableCell>{folderLink(folderOf(f.file), folderOf(f.file) ? <SafeText mono>{folderOf(f.file)}</SafeText> : <SafeText>{root}</SafeText>)}</TableCell>
                      {fileCells(f)}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <Table aria-label="Provider files">
                <TableHeader>
                  <TableRow>
                    <TableHead aria-sort={desc ? "descending" : "ascending"}>
                      <button type="button" className="inline-flex items-center gap-1 hover:text-foreground" onClick={() => setSortDesc(!desc)}>
                        Name
                        {desc ? <ArrowDownIcon className="size-3" /> : <ArrowUpIcon className="size-3" />}
                      </button>
                    </TableHead>
                    <TableHead>Selected</TableHead>
                    <TableHead>Feed</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {folders.map((f) => (
                    <TableRow key={f.prefix}>
                      <TableCell>
                        <span className="flex items-center gap-2">
                          <FolderIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                          {folderLink(
                            f.prefix,
                            <>
                              {shownName(nameIn(prefix, f.prefix))}/
                            </>,
                          )}
                        </span>
                      </TableCell>
                      <TableCell colSpan={2} className="text-xs text-muted-foreground">
                        {formatNumber(f.files)} {f.files === 1 ? "file" : "files"}, {formatNumber(f.feeds)} {f.feeds === 1 ? "feed" : "feeds"}
                      </TableCell>
                    </TableRow>
                  ))}
                  {files.map((f) => (
                    <TableRow key={f.file}>
                      <TableCell>
                        <span className="flex items-center gap-2">
                          <FileIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                          {shownName(nameIn(prefix, f.file))}
                        </span>
                      </TableCell>
                      {fileCells(f)}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
            <PagedListError query={view} placement="bottom" what={searching ? "more matches" : "more files"} />
            {view.hasNextPage && (
              <Button variant="outline" onClick={() => void view.fetchNextPage()} disabled={view.isFetching}>
                Load more
              </Button>
            )}
          </div>
        )}
      </Section>
    </div>
  );
}

function ProviderFeeds({ id }: { id: string }) {
  const statuses = useFeedStatuses();
  const feeds = (statuses.data ?? []).filter((f) => f.provider === id);
  return (
    <Section title="Feeds" description="Checked together with the provider; each keeps its own learned model.">
      <QueryView query={statuses} rows={4}>
        {() =>
          feeds.length === 0 ? (
            <p className="text-sm text-muted-foreground">No feeds yet.</p>
          ) : (
            <Table aria-label="Provider feeds">
              <TableHeader>
                <TableRow>
                  <TableHead>Feed</TableHead>
                  <TableHead>File</TableHead>
                  <TableHead>Last change</TableHead>
                  <TableHead>Pattern</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {feeds.map((f) => (
                  <TableRow key={f.feed}>
                    <TableCell>
                      <Link to="/feeds/$feedId" params={{ feedId: f.feed }} className="hover:underline">
                        <SafeText>{f.name || f.feed}</SafeText>
                      </Link>
                      {!f.enabled && <Badge variant="outline" className="ml-2">disabled</Badge>}
                    </TableCell>
                    <TableCell>
                      <SafeText mono>{f.file}</SafeText>
                    </TableCell>
                    <TableCell>
                      <TimeAgo value={f.last_change} />
                    </TableCell>
                    <TableCell className="text-xs">
                      <SafeText>{f.pattern}</SafeText>
                    </TableCell>
                    <TableCell>
                      {f.failures > 0 ? (
                        <Badge variant="destructive">{f.failures} failed</Badge>
                      ) : f.held_run ? (
                        <Badge variant="warning">held</Badge>
                      ) : f.busy ? (
                        <Badge variant="secondary">busy</Badge>
                      ) : (
                        <Badge variant="secondary">ok</Badge>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )
        }
      </QueryView>
    </Section>
  );
}

function ProviderChecks({ id }: { id: string }) {
  const q = useInfiniteQuery({
    queryKey: qk.provider(id, "checks"),
    queryFn: ({ pageParam, signal }) =>
      unwrap(client.GET("/api/ui/v1/feed-providers/{id}/checks", { params: { path: { id }, query: { cursor: pageParam, limit: 100 } }, signal })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (p) => p.next_cursor ?? undefined,
  });
  const items = q.data?.pages.flatMap((p) => p.items) ?? [];
  if (q.isPending) return <LoadingState rows={6} />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  return (
    <Section title="Check history" description="Kept for 60 days.">
      <Table aria-label="Provider checks">
        <TableHeader>
          <TableRow>
            <TableHead>When</TableHead>
            <TableHead>Cause</TableHead>
            <TableHead>Result</TableHead>
            <TableHead className="text-right">Duration</TableHead>
            <TableHead>Error</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.length === 0 && (
            <TableRow>
              <TableCell colSpan={5} className="text-center text-sm text-muted-foreground">
                No checks yet.
              </TableCell>
            </TableRow>
          )}
          {items.map((c) => (
            <TableRow key={c.id}>
              <TableCell className="whitespace-nowrap text-xs">{formatTime(c.t)}</TableCell>
              <TableCell>
                <Mono>{c.cause}</Mono>
              </TableCell>
              <TableCell>{c.ok ? <Badge variant="success">ok</Badge> : <Badge variant="destructive">failed</Badge>}</TableCell>
              <TableCell className="text-right tabular-nums">{c.duration_ms !== null && c.duration_ms !== undefined ? `${formatNumber(c.duration_ms)} ms` : "—"}</TableCell>
              <TableCell className="max-w-md text-xs">
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

/** The backtest's `days` and `k` as core bounds them (core 07acc1c: outside, 400). */
export const BACKTEST_DAYS = queryRange("/api/ui/v1/feed-providers/{id}/backtest", "days");
export const BACKTEST_K = queryRange("/api/ui/v1/feed-providers/{id}/backtest", "k");

/**
 * The backtest (feed-scheduling.md §6) over the last `days` of history (core's default 7, kept 60
 * days) for one `k`, or for each of 1, 2, 3 and 5 when left out. A value core would refuse (400),
 * or one the browser can't read as a number, is refused in the form, with the range, and nothing
 * is sent. Run always asks core (the history grows), one backtest at a time: core computes each in
 * full (one the page stops waiting for too), so Run is off, saying so, while the one shown is out.
 */
function Backtest({ id }: { id: string }) {
  const qc = useQueryClient();
  const [days, setDays] = React.useState("7");
  const [k, setK] = React.useState("");
  // The fields' `validity.badInput`, read on each input event: React's change event doesn't come
  // while the value stays "" ("-" typed into an empty field).
  const [daysUnreadable, setDaysUnreadable] = React.useState(false);
  const [kUnreadable, setKUnreadable] = React.useState(false);
  /** What the table shows: core's defaults until Run asks for other values. */
  const [asked, setAsked] = React.useState<{ days?: number; k?: number }>({});
  const daysProblem = rangeProblem(days, BACKTEST_DAYS, false, daysUnreadable);
  const kProblem = rangeProblem(k, BACKTEST_K, true, kUnreadable);
  const keyOf = (a: typeof asked) => [...qk.provider(id, "backtest"), a.days ?? null, a.k ?? null];
  const q = useQuery({
    queryKey: keyOf(asked),
    queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/feed-providers/{id}/backtest", { params: { path: { id }, query: asked }, signal })),
    // Read when shown and when Run asks; not on focus, nor on feed run events (api/events.ts).
    refetchOnWindowFocus: false,
  });
  const running = q.isFetching;
  const run = (e: React.FormEvent) => {
    e.preventDefault();
    if (daysProblem || kProblem || running) return;
    const next = { days: Number(days), k: k.trim() === "" ? undefined : Number(k) };
    // An answer kept for these values is stale: read again now if shown, else once it is.
    void qc.invalidateQueries({ queryKey: keyOf(next), exact: true });
    setAsked(next);
  };
  return (
    <Section title="Backtest" description="The provider's recorded history replayed through the learner with simulated checks, for each k.">
      <form className="mb-4 flex flex-wrap items-start gap-3" onSubmit={run} noValidate aria-label="Backtest settings">
        <div className="space-y-1">
          <Label htmlFor="backtest-days">Days</Label>
          <Input
            id="backtest-days"
            className="w-28"
            type="number"
            min={BACKTEST_DAYS.min}
            max={BACKTEST_DAYS.max}
            step={1}
            value={days}
            onChange={(e) => setDays(e.target.value)}
            onInput={(e) => setDaysUnreadable(e.currentTarget.validity.badInput)}
            aria-invalid={!!daysProblem || undefined}
            aria-describedby="backtest-days-help"
          />
          <p id="backtest-days-help" className={daysProblem ? "text-xs text-destructive" : "text-xs text-muted-foreground"}>
            {daysProblem ?? `${rangeText(BACKTEST_DAYS)}: the history replayed.`}
          </p>
        </div>
        <div className="space-y-1">
          <Label htmlFor="backtest-k">k</Label>
          <Input
            id="backtest-k"
            className="w-28"
            type="number"
            min={BACKTEST_K.min}
            max={BACKTEST_K.max}
            step="any"
            value={k}
            placeholder="1, 2, 3, 5"
            onChange={(e) => setK(e.target.value)}
            onInput={(e) => setKUnreadable(e.currentTarget.validity.badInput)}
            aria-invalid={!!kProblem || undefined}
            aria-describedby="backtest-k-help"
          />
          <p id="backtest-k-help" className={kProblem ? "text-xs text-destructive" : "text-xs text-muted-foreground"}>
            {kProblem ?? `${rangeText(BACKTEST_K)}; blank for each of 1, 2, 3 and 5.`}
          </p>
        </div>
        <Button type="submit" variant="outline" className="mt-5" disabled={!!daysProblem || !!kProblem || running}>
          {running ? "Running…" : "Run"}
        </Button>
      </form>
      <QueryView query={q} rows={4} empty={<p className="text-sm text-muted-foreground">Not enough history yet.</p>} isEmpty={(d) => d.length === 0}>
        {(rows) => (
          <Table aria-label="Backtest">
            <TableHeader>
              <TableRow>
                <TableHead>k</TableHead>
                <TableHead className="text-right">Changes</TableHead>
                <TableHead className="text-right">Caught within 2 min</TableHead>
                <TableHead className="text-right">Checks per day</TableHead>
                <TableHead className="text-right">Median delay</TableHead>
                <TableHead className="text-right">p90 delay</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((r) => (
                <TableRow key={r.k}>
                  <TableCell>{r.k}</TableCell>
                  <TableCell className="text-right tabular-nums">{r.changes}</TableCell>
                  <TableCell className="text-right tabular-nums">
                    {r.caught_2min} ({formatPercent(r.share_2min)})
                  </TableCell>
                  <TableCell className="text-right tabular-nums">{formatNumber(r.checks_per_day, 1)}</TableCell>
                  <TableCell className="text-right tabular-nums">{formatSeconds(r.median_delay_s)}</TableCell>
                  <TableCell className="text-right tabular-nums">{formatSeconds(r.p90_delay_s)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </QueryView>
    </Section>
  );
}

/**
 * The last weekly `k` choice against the per-provider planning budget (feed-scheduling.md §5).
 * The budget is a planning figure for the replayed schedule, not a request quota: when it slows the
 * provider, or no `k` fits it, each feed's estimated change in its share caught within 2 minutes
 * (alone against beside its siblings, over the replay window) shows here.
 */
export function PlanningBudget({ choice }: { choice: KChoiceRecord }) {
  const c = choice.choice;
  const perDay = (v: number | null | undefined) => (v == null ? "—" : formatNumber(v, 1));
  const verdict =
    c.budget === "within" ? (
      <>fits: {perDay(c.checks_per_day)} predicted checks a day of {formatNumber(choice.budget_per_day)}</>
    ) : c.budget === "slowed" ? (
      <Badge variant="warning">
        slowed from k {c.preferred} to {c.k}: {perDay(c.preferred_checks_per_day)} → {perDay(c.checks_per_day)} predicted checks a day of{" "}
        {formatNumber(choice.budget_per_day)}
      </Badge>
    ) : (
      <Badge variant="warning">
        no k fits: k {c.k} predicts {perDay(c.checks_per_day)} checks a day of {formatNumber(choice.budget_per_day)}
      </Badge>
    );
  return (
    <div className="space-y-1">
      <div>
        {verdict} <span className="text-muted-foreground">(replayed {formatTime(choice.window_start)} to {formatTime(choice.window_end)})</span>
      </div>
      {choice.feeds.length > 0 && (
        <ul aria-label="Estimated cost per feed" className="text-xs text-muted-foreground">
          {choice.feeds.map((f) => (
            <li key={f.feed}>
              <Mono>{f.feed}</Mono>: {formatPercent(f.standalone_share_2min)} alone, {formatPercent(f.grouped_share_2min)} grouped (
              {f.change_points >= 0 ? "+" : ""}
              {formatNumber(f.change_points, 1)} points, {f.changes} changes)
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Feed settings a `files` entry gives the feeds it adds (any feed setting; `format` required). */
const FEED_SETTINGS_HIDDEN = ["id", "name", "provider", "file", "system"];

function ProviderSettings({ provider, onDeleted }: { provider: FeedProviderDef; onDeleted: () => void }) {
  // providers.md §2: a provider can't be deleted while a feed uses it (core answers 409).
  const allFeeds = useEntities("feeds");
  const feeds = (allFeeds.data ?? []).filter((f) => f.provider === provider.id).map((f) => f.id ?? "");
  const modules = useDownloadModules();
  const secrets = useSecrets();
  const [conflict, setConflict] = React.useState<{ message: string; retry: (f: SaveFlags) => void } | null>(null);
  const overrides = React.useMemo<Record<string, FieldOverride>>(() => {
    const out: Record<string, FieldOverride> = {
      trigger: ({ renderDefault, value }) => {
        const kind = (value as { kind?: string } | undefined)?.kind;
        return (
          <div className="space-y-1">
            {renderDefault()}
            {kind === "sqs" && (
              <p className="text-xs text-muted-foreground">
                The AWS keys take only <Mono>{"${secret:name}"}</Mono> references
                {secrets.data?.length ? <> (secrets: {secrets.data.map((s) => escapeControl(s.name)).join(", ")})</> : null}. Set secret values under Settings → Secrets.
              </p>
            )}
          </div>
        );
      },
    };
    for (let i = 0; i < 64; i++) {
      out[`files.${i}.feed`] = ({ value, onChange, disabled }) => (
        <SchemaForm
          schema={{ $ref: "#/components/schemas/FeedDef" }}
          root={openapiRoot}
          value={value ?? { format: "adblock" }}
          onChange={onChange}
          hidden={FEED_SETTINGS_HIDDEN}
          mode="create"
          disabled={disabled}
          idPrefix={`file-${i}-feed`}
        />
      );
    }
    return out;
  }, [secrets.data]);
  return (
    <>
      <EntityForm
        kind="feed-providers"
        id={provider.id}
        order={["module", "enabled", "config", "trigger", "files", "exclude"]}
        overrides={overrides}
        header={(v, set) => (
          <ProviderConfigSection
            provider={v}
            onChange={(config) => set({ ...v, config: config as Record<string, unknown> })}
            onModule={(m) => {
              const mi = modules.data?.find((x) => x.id === m);
              set({ ...v, module: m, config: mi ? ((defaultValue(mi.config_schema as SchemaRoot, mi.config_schema as SchemaRoot) ?? {}) as Record<string, unknown>) : {} });
            }}
          />
        )}
        hidden={["config", "module"]}
        onDeleted={onDeleted}
        canDelete={feeds.length === 0}
        deleteDescription="This can't be undone."
        footer={() =>
          feeds.length > 0 ? (
            <p className="text-xs text-muted-foreground">
              A provider can't be deleted while a feed uses it ({feeds.map(escapeControl).join(", ")}). Delete its feeds first, or remove its files entries, which deletes their feeds
              after asking; Export keeps a feed's entries and dates.
            </p>
          ) : null
        }
        onConflict={(e: ApiError, retry) => setConflict({ message: e.message, retry })}
      />
      <AlertDialog open={!!conflict} onOpenChange={(o) => !o && setConflict(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete the feeds this edit stops selecting?</AlertDialogTitle>
            <AlertDialogDescription>{escapeControl(conflict?.message ?? "")}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Keep editing</AlertDialogCancel>
            <AlertDialogAction
              destructive
              onClick={() => {
                conflict?.retry({ delete_unselected: true });
                setConflict(null);
              }}
            >
              Save and delete them
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

function ProviderConfigSection({ provider, onChange, onModule }: { provider: FeedProviderDef; onChange: (c: unknown) => void; onModule: (m: string) => void }) {
  const modules = useDownloadModules();
  const module = modules.data?.find((m) => m.id === provider.module);
  return (
    <Section title="Module config" description="What the provider's files share, from the module's Config schema. Editing the module or its config makes the next check a first check.">
      <div className="mb-4 max-w-sm">
        <Select value={provider.module ?? ""} onValueChange={onModule}>
          <SelectTrigger aria-label="Download module" className="w-full">
            <SelectValue placeholder="Choose a module…" />
          </SelectTrigger>
          <SelectContent>
            {(modules.data ?? []).map((m) => (
              <SelectItem key={m.id} value={m.id}>
                {m.id}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <ModuleConfigForm module={module} value={provider.config ?? {}} onChange={onChange} />
    </Section>
  );
}

