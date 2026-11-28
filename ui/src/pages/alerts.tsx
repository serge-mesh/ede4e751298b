import * as React from "react";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { useInfiniteQuery, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { CheckIcon, DownloadIcon, ShieldPlusIcon, Trash2Icon } from "lucide-react";
import { PageHeader, Section, KeyValue } from "@/components/common/page";
import { ErrorState, LoadingState, PagedListError, QueryView, RefetchError } from "@/components/common/states";
import { JsonBlock, Mono, SafeText } from "@/components/common/text";
import { TimeAgo } from "@/components/common/time";
import { Confirm } from "@/components/common/confirm";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { qk, useAlertMutation, useAlerts, type AlertFilter } from "@/api/queries";
import { client, request, unwrap } from "@/api/http";
import { errorMessage } from "@/api/errors";
import { alertsOf, invalidateFresh, useUiEvent } from "@/api/events";
import type { Alert, PublicSuffixItem, PublicSuffixRule } from "@/api/types";
import { formatNumber, formatPercent, formatTime } from "@/lib/format";
import { escapeControl } from "@/lib/text";
import { queryEnum } from "@/lib/openapi";
import { saveBase64, saveJson } from "@/lib/bytes";

export function SeverityBadge({ severity }: { severity: string }) {
  const v = severity === "critical" ? "destructive" : severity === "warning" ? "warning" : "secondary";
  return <Badge variant={v}>{severity}</Badge>;
}

const ANY = "__any__";

function FilterSelect({ label, value, options, onChange }: { label: string; value?: string; options: string[]; onChange: (v?: string) => void }) {
  return (
    <Select value={value ?? ANY} onValueChange={(v) => onChange(v === ANY ? undefined : v)}>
      <SelectTrigger size="sm" aria-label={label}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={ANY}>Any {label.toLowerCase()}</SelectItem>
        {options.map((o) => (
          <SelectItem key={o} value={o}>
            {o}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

/** The alert kinds `GET alerts?kind` takes (core's OpenAPI document lists them), sorted. */
const ALERT_KINDS = queryEnum("/api/ui/v1/alerts", "kind").sort();

export function AlertsPage() {
  const [filter, setFilterState] = React.useState<AlertFilter>({ state: "open" });
  const q = useAlerts(filter);
  const [checked, setSelected] = React.useState<Set<number>>(new Set());
  const alerts = React.useMemo(() => q.data?.pages.flatMap((p) => p.items) ?? [], [q.data]);
  // A filter change clears the selection, and actions take only the selected rows on screen, so
  // nothing hidden (another filter's rows, an alert gone on refresh) is resolved or deleted.
  const setFilter = (f: (prev: AlertFilter) => AlertFilter) => {
    setFilterState(f);
    setSelected(new Set());
  };
  const selected = React.useMemo(() => new Set(alerts.filter((a) => checked.has(a.id)).map((a) => a.id)), [alerts, checked]);
  const bulkDelete = useAlertMutation((ids: number[]) => request("DELETE", "/alerts", { body: { ids } }));
  const resolve = useAlertMutation((id: number) => unwrap(client.POST("/api/ui/v1/alerts/{id}/resolve", { params: { path: { id: String(id) } } })));
  const navigate = useNavigate();
  const allSelected = alerts.length > 0 && alerts.every((a) => selected.has(a.id));
  const toggle = (id: number, on: boolean) =>
    setSelected((s) => {
      const n = new Set(s);
      if (on) n.add(id);
      else n.delete(id);
      return n;
    });
  return (
    <div>
      <PageHeader title="Alerts" description="Kept until deleted here. Condition alerts resolve when their condition clears; others on their matching success or by hand." />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <FilterSelect label="Type" value={filter.type} options={["security", "operational"]} onChange={(v) => setFilter((f) => ({ ...f, type: v as AlertFilter["type"] }))} />
        <FilterSelect label="Severity" value={filter.severity} options={["critical", "warning", "info"]} onChange={(v) => setFilter((f) => ({ ...f, severity: v as AlertFilter["severity"] }))} />
        <FilterSelect label="State" value={filter.state} options={["open", "resolved"]} onChange={(v) => setFilter((f) => ({ ...f, state: v as AlertFilter["state"] }))} />
        <FilterSelect label="Kind" value={filter.kind} options={ALERT_KINDS} onChange={(v) => setFilter((f) => ({ ...f, kind: v as AlertFilter["kind"] }))} />
        {selected.size > 0 && (
          <div className="ml-auto flex gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={async () => {
                const ids = [...selected];
                let failed = 0;
                for (const id of ids) {
                  try {
                    await resolve.mutateAsync(id);
                  } catch {
                    failed++;
                  }
                }
                setSelected(new Set());
                if (failed) toast.error(`${failed} could not be resolved`);
                else toast.success(`Resolved ${ids.length} alerts`);
              }}
            >
              <CheckIcon /> Resolve {selected.size}
            </Button>
            <Confirm
              title={`Delete ${selected.size} alerts?`}
              description="Deleted alerts and their evidence are gone for good."
              destructive
              confirmLabel="Delete"
              onConfirm={() =>
                bulkDelete.mutate([...selected], {
                  onSuccess: () => {
                    toast.success(`Deleted ${selected.size} alerts`);
                    setSelected(new Set());
                  },
                  onError: (e) => toast.error(errorMessage(e)),
                })
              }
            >
              <Button size="sm" variant="destructive">
                <Trash2Icon /> Delete {selected.size}
              </Button>
            </Confirm>
          </div>
        )}
      </div>
      {q.isPending ? (
        <LoadingState rows={8} />
      ) : q.error ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : (
        <div className="space-y-3">
          <div className="rounded-md border">
            <Table aria-label="Alerts">
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8">
                    <Checkbox
                      checked={allSelected}
                      aria-label="Select all"
                      onCheckedChange={(on) => setSelected(on ? new Set(alerts.map((a) => a.id)) : new Set())}
                    />
                  </TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Alert</TableHead>
                  <TableHead>Kind</TableHead>
                  <TableHead>About</TableHead>
                  <TableHead className="text-right">Count</TableHead>
                  <TableHead>Last seen</TableHead>
                  <TableHead>State</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {alerts.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={8} className="h-20 text-center text-sm text-muted-foreground">
                      No alerts match.
                    </TableCell>
                  </TableRow>
                )}
                {alerts.map((a) => (
                  <TableRow key={a.id} className="cursor-pointer" onClick={() => void navigate({ to: "/alerts/$alertId", params: { alertId: String(a.id) } })}>
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <Checkbox checked={selected.has(a.id)} aria-label={`Select alert ${a.id}`} onCheckedChange={(on) => toggle(a.id, on === true)} />
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={a.severity} />
                    </TableCell>
                    <TableCell className="max-w-md">
                      <Link
                        to="/alerts/$alertId"
                        params={{ alertId: String(a.id) }}
                        className="hover:underline"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <SafeText>{a.title}</SafeText>
                      </Link>
                      <div className="text-xs text-muted-foreground">{a.type}</div>
                    </TableCell>
                    <TableCell>
                      <Mono>{a.kind}</Mono>
                    </TableCell>
                    <TableCell className="text-xs" onClick={(e) => e.stopPropagation()}>
                      <AlertSubjects alert={a} />
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{a.count}</TableCell>
                    <TableCell className="text-xs">
                      <TimeAgo value={a.last_seen} />
                    </TableCell>
                    <TableCell>
                      <Badge variant={a.state === "open" ? "outline" : "secondary"}>{a.state}</Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          {q.hasNextPage && (
            <Button variant="outline" onClick={() => void q.fetchNextPage()} disabled={q.isFetching}>
              Load more
            </Button>
          )}
        </div>
      )}
    </div>
  );
}

const named = (v: unknown) => typeof v === "string" && v !== "";

/**
 * Alert kinds raised from logged records, whose `edge` is the records' edge: core leaves it null
 * once records from several edges raised the alert (core.md §9 record; alerts.rs `seen_on_edges`,
 * core c58ba80). Each says whether its details show the raise came from records with an edge,
 * so a null `edge` means several rather than none: `category_blocked` and a feed's
 * `category_answered` keep the latest record's `details.edge`; a lookup provider's
 * `category_answered` names no edge in its details, though each raise has its newest answer's
 * (lookups/answered.rs); `dnssec_bogus` lists its names' edges and `upstream_disagrees` the
 * latest check's records' (`details.edges`, empty when no record had one).
 */
const RECORD_KINDS: Record<string, (details: Record<string, unknown>) => boolean> = {
  category_blocked: (d) => named(d.edge),
  category_answered: (d) => named(d.edge) || d.by === "provider",
  dnssec_bogus: (d) => Array.isArray(d.edges) && d.edges.some(named),
  upstream_disagrees: (d) => Array.isArray(d.edges) && d.edges.some(named),
};

/** Whether an alert was raised from records of several edges (`edge` null where its records name one). */
export function seenOnSeveralEdges(a: Pick<Alert, "edge" | "kind" | "details">): boolean {
  const details = (a.details ?? {}) as Record<string, unknown>;
  const fromEdges = Object.hasOwn(RECORD_KINDS, a.kind) ? RECORD_KINDS[a.kind] : undefined;
  return !a.edge && !!fromEdges?.(details);
}

function AlertSubjects({ alert: a }: { alert: Alert }) {
  const parts: React.ReactNode[] = [];
  if (a.edge)
    parts.push(
      <Link key="e" to="/edges/$edgeId" params={{ edgeId: a.edge }} className="hover:underline">
        edge <SafeText>{a.edge}</SafeText>
      </Link>,
    );
  else if (seenOnSeveralEdges(a))
    parts.push(
      <span key="e" title="Records from more than one edge raised it; each copy below names its edge">
        several edges
      </span>,
    );
  if (a.feed_provider)
    parts.push(
      <Link key="p" to="/feed-providers/$providerId" params={{ providerId: a.feed_provider }} className="hover:underline">
        provider <SafeText>{a.feed_provider}</SafeText>
      </Link>,
    );
  if (a.feed)
    parts.push(
      <Link key="f" to="/feeds/$feedId" params={{ feedId: a.feed }} className="hover:underline">
        feed <SafeText>{a.feed}</SafeText>
      </Link>,
    );
  if (a.bundle)
    parts.push(
      <Link key="b" to="/bundles/$bundleId" params={{ bundleId: a.bundle }} className="hover:underline">
        bundle <SafeText>{a.bundle}</SafeText>
      </Link>,
    );
  if (parts.length === 0) return <span className="text-muted-foreground">—</span>;
  return <span className="flex flex-col gap-0.5">{parts}</span>;
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v ? v : undefined;
}

/** Copies one evidence page holds (core's default), and the most core gives in one (api.md §7). */
export const EVIDENCE_PAGE = 100;
export const EVIDENCE_PAGE_MAX = 500;
/** Pages a whole-evidence download reads at most (50,000 copies: far past alerts.evidence_per_alert). */
const EVIDENCE_PAGES_MAX = 100;

/**
 * `GET alerts/{id}/evidence?cursor&limit` (logs/query.rs `EvidenceView`, core c58ba80): a page of
 * copies, newest stored first (the order core stored them, not their event times: a backfill or an
 * edge's late spool stores older records later), with the answers they reference and the exact
 * `total` as that page was read; `next_cursor` leads to the copies stored before. The first page
 * also has the counts, examples, rule and the answers no copy references.
 */
const fetchEvidence = (id: number, cursor: string | undefined, limit: number, signal?: AbortSignal) =>
  unwrap(client.GET("/api/ui/v1/alerts/{id}/evidence", { params: { path: { id: String(id) }, query: { cursor, limit } }, signal }));
type Evidence = Awaited<ReturnType<typeof fetchEvidence>>;

/**
 * Loaded evidence pages as one view: the first page's counts, examples, rule and `incomplete`
 * (later pages leave them empty), every copy in order (newest stored first), each answer once, and
 * the last page's `total` (read last, so the latest) and `next_cursor` (the older copies).
 */
export function joinEvidence(pages: Evidence[]): Evidence {
  const [first] = pages;
  const last = pages[pages.length - 1];
  const seen = new Set<string>();
  const answers = pages.flatMap((p) => p.answers).filter((a) => !seen.has(a.answer_id) && !!seen.add(a.answer_id));
  return { ...first, items: pages.flatMap((p) => p.items), answers, total: last.total, next_cursor: last.next_cursor ?? null };
}

/** Whole-evidence reads a download makes at most while copies keep coming in (`fetchAllEvidence`). */
export const EVIDENCE_DOWNLOAD_TRIES = 3;

/** Every page of an alert's evidence, at most EVIDENCE_PAGE_MAX copies a page. */
async function fetchEvidencePages(id: number): Promise<Evidence[]> {
  const pages: Evidence[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < EVIDENCE_PAGES_MAX; i++) {
    const p = await fetchEvidence(id, cursor, EVIDENCE_PAGE_MAX);
    pages.push(p);
    if (!p.next_cursor) return pages;
    cursor = p.next_cursor;
  }
  throw new Error("The evidence has more pages than a download reads; try again.");
}

/**
 * Whether pages read one after another are one run of the alert's copies. Each page and its
 * `total` are one snapshot (logs/query.rs `evidence`), so one page is; across pages, copies stored
 * meanwhile come before the first page (ids only grow), and past alerts.evidence_per_alert core
 * drops older "latest" copies as new ones come. So the pages agree when every page counts the same
 * total, they hold that many copies, and the newest copy and the total are still the same after
 * the last page (a copy stored meanwhile would come first).
 */
async function oneRun(id: number, pages: Evidence[]): Promise<boolean> {
  const [first] = pages;
  const copies = pages.reduce((n, p) => n + p.items.length, 0);
  if (pages.some((p) => p.total !== first.total) || copies !== first.total) return false;
  if (pages.length === 1) return true;
  const head = await fetchEvidence(id, undefined, 1);
  return head.total === first.total && head.items.length > 0 && copyKey(head.items[0]) === copyKey(first.items[0]);
}

/**
 * Every page of an alert's evidence, joined (for the download). A read that copies came in
 * during (`oneRun`) is made again, at most EVIDENCE_DOWNLOAD_TRIES times; `consistent` is false
 * when the last read still wasn't one run (it may lack copies stored meanwhile, or hold copies core
 * has dropped since).
 */
export async function fetchAllEvidence(id: number): Promise<{ evidence: Evidence; consistent: boolean }> {
  let pages: Evidence[] = [];
  for (let t = 0; t < EVIDENCE_DOWNLOAD_TRIES; t++) {
    pages = await fetchEvidencePages(id);
    if (await oneRun(id, pages)) return { evidence: joinEvidence(pages), consistent: true };
  }
  return { evidence: joinEvidence(pages), consistent: false };
}

type Copy = Evidence["items"][number];

/** A copy's key: core's record (edge, boot, seq: a copy is unique per record, `alert_evidence_record`). */
function copyKey(c: Pick<Copy, "edge" | "boot" | "seq">): string {
  return `${c.edge}\t${c.boot}\t${c.seq}`;
}

/** Each copy's key (`copyKey`), made unique by its occurrence should a record come twice. */
export function copyKeys(items: Pick<Copy, "edge" | "boot" | "seq">[]): string[] {
  const seen = new Map<string, number>();
  return items.map((c) => {
    const k = copyKey(c);
    const n = seen.get(k) ?? 0;
    seen.set(k, n + 1);
    return n === 0 ? k : `${k}\t#${n}`;
  });
}

/** A file name part from an edge id (any character a file name can't hold as `_`). */
const fileSafe = (v: string) => v.replace(/[^A-Za-z0-9._-]/g, "_");

/** Alerts that keep evidence besides the security ones (core.md §8, §9): wire_mismatch examples, the validator's and resolver's answers. */
const EVIDENCE_KINDS = new Set(["wire_mismatch", "dnssec_bogus", "upstream_disagrees"]);
/** Security alerts core keeps no evidence for (none, core.md §9 Evidence). */
const NO_EVIDENCE_KINDS = new Set<string>();

/** The shortest time between two reads of an alert's evidence its own events cause (each can be alerts.evidence_per_alert copies and their wires). */
export const EVIDENCE_REFRESH_MS = 30_000;

/**
 * Reads an alert's evidence again when an `alert` event is about this alert (a raise adds copies
 * and counts: core.md §9; an evidence backfill or live capture adds copies, and core 4e4f53d lists
 * the alert for those too): when the event (coalesced: the alerts changed since the previous one)
 * lists it, not deleted, or lists only some alerts (`alerts_truncated`), unless it lists it as
 * deleted (gone with its evidence); not for events that list only other alerts. At most once per
 * EVIDENCE_REFRESH_MS: an event within that time schedules one read at its end, so the latest
 * evidence still shows. New copies come first on the first page (newest stored first); the read
 * covers the pages loaded (TanStack reads them again in order, each from the page before's fresh
 * cursor), so the view stays one run of copies from the newest, and those pushed past the last
 * loaded page show as older ones to load. A read still in flight, the first one or a Load more,
 * lands, and the evidence is read once more after it (`invalidateFresh`). A reconnect reads it
 * again with everything (api/events.ts resync).
 */
function useEvidenceRefresh(alertId: string, updatedAt: number) {
  const qc = useQueryClient();
  const last = React.useRef(0);
  const timer = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const read = React.useCallback(() => {
    timer.current = null;
    last.current = Date.now();
    invalidateFresh(qc, { queryKey: qk.alertEvidence(alertId), exact: true });
  }, [qc, alertId]);
  React.useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current);
      timer.current = null;
      last.current = 0;
    },
    [alertId],
  );
  useUiEvent((ev) => {
    if (ev.type !== "alert" || timer.current) return;
    const { alerts, truncated } = alertsOf(ev.data);
    const mine = alerts.find((a) => String(a.id) === alertId);
    if (mine ? mine.deleted === true : !truncated) return;
    const since = Date.now() - Math.max(last.current, updatedAt);
    if (since >= EVIDENCE_REFRESH_MS) read();
    else timer.current = setTimeout(read, EVIDENCE_REFRESH_MS - since);
  });
}

export function AlertDetailPage() {
  const { alertId } = useParams({ strict: false }) as { alertId: string };
  const id = Number(alertId);
  const navigate = useNavigate();
  const q = useQuery({
    queryKey: ["alerts", "item", alertId],
    queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/alerts/{id}", { params: { path: { id: String(id) } }, signal })),
    enabled: Number.isFinite(id),
  });
  const pages = useInfiniteQuery({
    queryKey: qk.alertEvidence(alertId),
    queryFn: ({ pageParam, signal }) => fetchEvidence(id, pageParam, EVIDENCE_PAGE, signal),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (p) => p.next_cursor ?? undefined,
    enabled: Number.isFinite(id),
    // Not on focus either: its own alert's events read it again (useEvidenceRefresh).
    refetchOnWindowFocus: false,
  });
  useEvidenceRefresh(alertId, pages.dataUpdatedAt);
  const joined = React.useMemo(() => (pages.data ? joinEvidence(pages.data.pages) : undefined), [pages.data]);
  // A failed "Load more" shows under the copies (PagedListError), not as the evidence's error.
  const evidence = { data: joined, error: pages.isFetchNextPageError ? null : pages.error, isPending: pages.isPending, refetch: pages.refetch };
  const [downloading, setDownloading] = React.useState(false);
  const resolve = useAlertMutation(() => unwrap(client.POST("/api/ui/v1/alerts/{id}/resolve", { params: { path: { id: String(id) } } })));
  const del = useAlertMutation(() => unwrap(client.DELETE("/api/ui/v1/alerts/{id}", { params: { path: { id: String(id) } } })));
  if (q.data === undefined) return q.error ? <ErrorState error={q.error} onRetry={() => void q.refetch()} /> : <LoadingState rows={8} />;
  const { alert: a, history } = q.data;
  const details = (a.details ?? {}) as Record<string, unknown>;
  const domain = str(details.domain) ?? str(details.name);
  const keepsEvidence = (a.type === "security" && !NO_EVIDENCE_KINDS.has(a.kind)) || EVIDENCE_KINDS.has(a.kind);
  return (
    <div className="space-y-4">
      {q.error && <RefetchError error={q.error} onRetry={() => void q.refetch()} />}
      <PageHeader
        title={<SafeText>{a.title}</SafeText>}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={a.severity} />
            <Badge variant="outline">{a.type}</Badge>
            <Mono>{a.kind}</Mono>
            <Badge variant={a.state === "open" ? "outline" : "secondary"}>{a.state}</Badge>
          </span>
        }
        actions={
          <>
            {a.kind === "category_answered" && domain && <AddToBlockFeed domain={domain} />}
            {a.kind === "lookup_self_test_failed" && str(details.provider) && <FlushVerdicts provider={str(details.provider)!} />}
            {a.state === "open" && (
              <Button
                variant="outline"
                onClick={() => resolve.mutate(undefined, { onSuccess: () => toast.success("Resolved"), onError: (e) => toast.error(errorMessage(e)) })}
              >
                <CheckIcon /> Resolve
              </Button>
            )}
            <Confirm
              title="Delete this alert?"
              description="Its history and evidence go with it."
              destructive
              confirmLabel="Delete"
              onConfirm={() =>
                del.mutate(undefined, {
                  onSuccess: () => {
                    toast.success("Deleted");
                    void navigate({ to: "/alerts" });
                  },
                  onError: (e) => toast.error(errorMessage(e)),
                })
              }
            >
              <Button variant="outline" className="text-destructive">
                <Trash2Icon /> Delete
              </Button>
            </Confirm>
          </>
        }
      />
      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="Summary">
          <KeyValue
            items={[
              ["Count", a.count],
              ["First seen", formatTime(a.first_seen)],
              ["Last seen", formatTime(a.last_seen)],
              ["Dedup key", <SafeText mono>{a.dedupe_key}</SafeText>],
              ["About", <AlertSubjects alert={a} />],
            ]}
          />
        </Section>
        <Section title="History" description="Every raise and resolve.">
          <ol className="space-y-2 text-sm">
            {history.map((h, i) => (
              <li key={i} className="flex flex-col gap-1 border-l-2 pl-3">
                <span>
                  <strong>{h.change}</strong> <span className="text-muted-foreground">{formatTime(h.at)}</span>
                </span>
                {h.detail !== null && h.detail !== undefined && <JsonBlock value={h.detail} className="max-h-40" />}
              </li>
            ))}
          </ol>
        </Section>
      </div>
      {a.kind === "category_blocked" && <BlockedBy details={details} />}
      {a.kind === "bundle_cold_share" && <ColdShare details={details} />}
      {a.kind === "bundle_warning" && details.warning === "public_suffix" && <PublicSuffixes details={details} />}
      {a.kind === "edge_tls_version_refused" && <TlsVersionRefused details={details} />}
      <Section title="Details" description="As core recorded them; shown as text.">
        <JsonBlock value={a.details} />
      </Section>
      {a.kind === "wire_mismatch" && (
        <Section title="Examples" description="Up to 20 answers whose decode disagreed with what the edge logged. Each can be saved for the differential tests' corpus.">
          <QueryView query={evidence} what="Wire-mismatch examples" rows={3} empty={<p className="text-sm text-muted-foreground">No examples kept (the evidence budget was full).</p>} isEmpty={(ev) => ev.examples.length === 0}>
            {(ev) => (
              <ul className="space-y-3">
                {ev.examples.map((ex, i) => (
                  <WireExampleView key={i} example={ex} index={i} alertId={a.id} />
                ))}
              </ul>
            )}
          </QueryView>
        </Section>
      )}
      {keepsEvidence && (
        <Section
          title="Evidence"
          description="Copies of the related log records, newest stored first, kept until the alert is deleted (at most alerts.evidence_per_alert: half the first, half the latest), with exact counts per client and name and the upstream answers they reference."
          actions={
            evidence.data && (
              <Button
                size="sm"
                variant="outline"
                disabled={downloading}
                title="Every copy, all pages"
                onClick={async () => {
                  setDownloading(true);
                  try {
                    const { evidence: all, consistent } = await fetchAllEvidence(a.id);
                    saveJson(all, `alert-${a.id}-evidence.json`);
                    if (!consistent)
                      toast.warning(
                        `The evidence changed while it downloaded (copies kept coming in): the file has ${formatNumber(all.items.length)} of ${formatNumber(all.total)} copies and may miss some or hold some core has dropped since. Download again for an exact copy.`,
                      );
                  } catch (e) {
                    toast.error(errorMessage(e));
                  } finally {
                    setDownloading(false);
                  }
                }}
              >
                <DownloadIcon /> Download evidence
              </Button>
            )
          }
        >
          <QueryView query={evidence} what="Alert evidence" rows={4}>
            {(ev) => (
              <div className="space-y-3">
                <EvidenceBody ev={ev} alertId={a.id} />
                <PagedListError query={pages} placement="bottom" what="older copies" />
                {pages.hasNextPage && (
                  // Held while any read is out: a next page sent during an event's refresh
                  // would replace it, and the new copies wouldn't come (api/events.ts).
                  <Button variant="outline" onClick={() => void pages.fetchNextPage()} disabled={pages.isFetching}>
                    Load older copies
                  </Button>
                )}
                {!pages.hasNextPage && ev.items.length < ev.total && (
                  // Every older copy is loaded, yet core counts more: they were stored after the
                  // first page was read, and come on a fresh first page (never behind a cursor).
                  <p className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground" data-testid="evidence-newer">
                    {formatNumber(ev.total - ev.items.length)} newer {ev.total - ev.items.length === 1 ? "copy was" : "copies were"} stored since the first page was read.
                    <Button size="sm" variant="outline" onClick={() => void pages.refetch()} disabled={pages.isFetching}>
                      Show the newest
                    </Button>
                  </p>
                )}
              </div>
            )}
          </QueryView>
        </Section>
      )}
    </div>
  );
}

const PUBLIC_SUFFIX_PAGE = 50;

/**
 * A grouped public-suffix warning (bundles.md §2, compiler/guard.rs `psl_summarise`; read
 * defensively): how many public suffixes the bundle blocks from the feed and through how many
 * rules, the preview and the suffixes added since it was last shown, then the full list with each
 * suffix's rules, a page at a time (`GET /bundles/{id}/public-suffixes`).
 */
function PublicSuffixes({ details: d }: { details: Record<string, unknown> }) {
  const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : null);
  const names = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
  const bundle = text(d.bundle);
  const feed = text(d.feed);
  const suffixes = num(d.suffixes);
  const rules = num(d.rules);
  const preview = names(d.preview);
  const more = num(d.more) ?? 0;
  const added = names(d.added);
  const addedCount = num(d.added_count) ?? added.length;
  const [open, setOpen] = React.useState(false);
  const pages = useInfiniteQuery({
    queryKey: ["bundlePublicSuffixes", bundle, feed],
    queryFn: ({ pageParam, signal }) =>
      unwrap(
        client.GET("/api/ui/v1/bundles/{id}/public-suffixes", {
          params: { path: { id: bundle ?? "" }, query: { feed: feed ?? undefined, cursor: pageParam, limit: PUBLIC_SUFFIX_PAGE } },
          signal,
        }),
      ),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (p) => p.next_cursor ?? undefined,
    enabled: open && bundle !== null,
  });
  const items = pages.data?.pages.flatMap((p) => p.items) ?? [];
  const total = pages.data?.pages[pages.data.pages.length - 1]?.total;
  return (
    <Section
      title="Public suffixes"
      description="Blocking a public suffix blocks every site registered under it. Each is listed once, with every rule of the feed that blocks it."
      actions={
        bundle && (
          <Link to="/bundles/$bundleId" params={{ bundleId: bundle }} className="text-sm text-primary hover:underline">
            The bundle
          </Link>
        )
      }
    >
      <div className="space-y-3 text-sm" data-testid="public-suffixes">
        {suffixes !== null && (
          <p>
            {`${formatNumber(suffixes)} public suffix${suffixes === 1 ? "" : "es"}`}
            {rules !== null && ` through ${formatNumber(rules)} rule${rules === 1 ? "" : "s"}`}
            {feed && (
              <>
                {" from feed "}
                <Link to="/feeds/$feedId" params={{ feedId: feed }} className="hover:underline">
                  <SafeText>{feed}</SafeText>
                </Link>
              </>
            )}
            .
          </p>
        )}
        {preview.length > 0 && (
          <p>
            <SafeText mono>{preview.join(", ")}</SafeText>
            {more > 0 && <span className="text-muted-foreground">{` and ${formatNumber(more)} more`}</span>}
          </p>
        )}
        {addedCount > 0 && (
          <p data-testid="public-suffixes-added">
            {`New since it was last shown (${formatNumber(addedCount)}): `}
            <SafeText mono>{added.join(", ")}</SafeText>
            {addedCount > added.length && <span className="text-muted-foreground">{` and ${formatNumber(addedCount - added.length)} more`}</span>}
          </p>
        )}
        {!open ? (
          <Button variant="outline" size="sm" onClick={() => setOpen(true)} disabled={bundle === null}>
            Show every suffix and its rules
          </Button>
        ) : pages.isPending ? (
          <LoadingState rows={3} />
        ) : pages.error && !pages.isFetchNextPageError ? (
          <ErrorState error={pages.error} onRetry={() => void pages.refetch()} />
        ) : (
          <>
            {total !== undefined && <p className="text-muted-foreground">{`${formatNumber(items.length)} of ${formatNumber(total)} shown.`}</p>}
            <Table aria-label="Public suffixes and their rules">
              <TableHeader>
                <TableRow>
                  <TableHead>Suffix</TableHead>
                  <TableHead>Rules (line)</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((i) => (
                  <TableRow key={`${i.feed}\n${i.suffix}`}>
                    <TableCell>
                      <SafeText mono>{i.suffix}</SafeText>
                    </TableCell>
                    <TableCell>
                      <SuffixRules bundle={bundle ?? ""} item={i} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <PagedListError query={pages} placement="bottom" what="more suffixes" />
            {pages.hasNextPage && (
              <Button variant="outline" size="sm" onClick={() => void pages.fetchNextPage()} disabled={pages.isFetching}>
                Load more suffixes
              </Button>
            )}
          </>
        )}
      </div>
    </Section>
  );
}

function RuleLine({ rule: r }: { rule: PublicSuffixRule }) {
  return (
    <li>
      <SafeText mono>{r.rule ?? "(no longer in the feed)"}</SafeText>
      {r.line !== null && r.line !== undefined && <span className="text-muted-foreground">{` (${r.line})`}</span>}
    </li>
  );
}

/**
 * One suffix's rules: the first few that come with the suffix page, then the rest a page at a
 * time from `GET /bundles/{id}/public-suffixes/rules` when asked for (issue 115).
 */
function SuffixRules({ bundle, item }: { bundle: string; item: PublicSuffixItem }) {
  const [open, setOpen] = React.useState(false);
  const more = useInfiniteQuery({
    // Under the suffix list's key, so the events that refresh the list refresh these too.
    queryKey: ["bundlePublicSuffixes", bundle, item.feed, "rules", item.suffix, item.rules_cursor],
    queryFn: ({ pageParam, signal }) =>
      unwrap(
        client.GET("/api/ui/v1/bundles/{id}/public-suffixes/rules", {
          params: { path: { id: bundle }, query: { feed: item.feed, suffix: item.suffix, cursor: pageParam, limit: PUBLIC_SUFFIX_PAGE } },
          signal,
        }),
      ),
    initialPageParam: item.rules_cursor ?? undefined,
    getNextPageParam: (p) => p.next_cursor ?? undefined,
    enabled: open && !!item.rules_cursor,
  });
  const rules = [...item.rules, ...(more.data?.pages.flatMap((p) => p.items) ?? [])];
  const count = typeof item.rule_count === "number" ? item.rule_count : rules.length;
  const left = Math.max(count - rules.length, 0);
  const hasMore = !!item.rules_cursor && (!open || more.hasNextPage);
  return (
    <div className="space-y-1">
      <ul>
        {rules.map((r, k) => (
          <RuleLine key={k} rule={r} />
        ))}
      </ul>
      {open && more.error && !more.isFetchNextPageError && <RefetchError error={more.error} onRetry={() => void more.refetch()} />}
      <PagedListError query={more} placement="bottom" what="more rules" />
      {hasMore && (
        <Button
          variant="link"
          size="sm"
          className="h-auto p-0"
          onClick={() => (open ? void more.fetchNextPage() : setOpen(true))}
          disabled={open && more.isFetching}
        >
          {left > 0 ? `Show ${formatNumber(left)} more rule${left === 1 ? "" : "s"}` : "Show more rules"}
        </Button>
      )}
    </div>
  );
}

/** A feed's cold blocks in a `bundle_cold_share` alert (`details.feeds[]`). */
interface ColdFeed {
  feed: string;
  cold: number;
  share: number | null;
}

/**
 * A `bundle_cold_share` alert's figures (core.md §9, logs/cold_share.rs; read defensively): the
 * bundle's logged blocks over the window, those answered from its cold part and their share
 * against the limit, each deciding feed's cold blocks and share, and the cold blocks no feed is
 * known to have decided yet.
 */
function ColdShare({ details: d }: { details: Record<string, unknown> }) {
  const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : null);
  const feeds: ColdFeed[] = (Array.isArray(d.feeds) ? d.feeds : [])
    .filter((f): f is Record<string, unknown> => !!f && typeof f === "object" && typeof (f as { feed?: unknown }).feed === "string")
    .map((f) => ({ feed: f.feed as string, cold: num(f.cold_blocks) ?? 0, share: num(f.share) }));
  const blocks = num(d.blocks);
  const cold = num(d.cold_blocks);
  const unattributed = num(d.unattributed_cold_blocks) ?? 0;
  const bundle = text(d.bundle);
  return (
    <Section
      title="Cold share"
      description="Blocks answered from keys in the bundle's cold part, counted from the logged blocks."
      actions={
        bundle && (
          <Link to="/bundles/$bundleId" params={{ bundleId: bundle }} search={{ tab: "cold" }} className="text-sm text-primary hover:underline">
            The bundle's cold part
          </Link>
        )
      }
    >
      <div className="space-y-3 text-sm" data-testid="cold-share">
        {blocks !== null && cold !== null && (
          <p>{`${formatNumber(cold)} of ${formatNumber(blocks)} blocks (${formatPercent(num(d.share))}) over the last ${num(d.window_h) ?? 24} h came from the cold part; the limit is ${formatPercent(num(d.limit))}.`}</p>
        )}
        {feeds.length > 0 && (
          <Table aria-label="Cold blocks per feed">
            <TableHeader>
              <TableRow>
                <TableHead>Feed</TableHead>
                <TableHead>Cold blocks</TableHead>
                <TableHead>Share of the bundle's blocks</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {feeds.map((f) => (
                <TableRow key={f.feed}>
                  <TableCell>
                    <Link to="/feeds/$feedId" params={{ feedId: f.feed }} className="hover:underline">
                      <SafeText>{f.feed}</SafeText>
                    </Link>
                  </TableCell>
                  <TableCell>{formatNumber(f.cold)}</TableCell>
                  <TableCell>{formatPercent(f.share)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        {unattributed > 0 && (
          <p className="text-muted-foreground">{`${formatNumber(unattributed)} cold block${unattributed === 1 ? " has" : "s have"} no deciding feed yet (attribution hasn't run or couldn't tell).`}</p>
        )}
      </div>
    </Section>
  );
}

/**
 * What a client refused for offering no TLS 1.3 offered instead (`tls_version_refused`'s
 * `offered`, api.md §5: the newest version it offered), as the "Offered" row says it and, where
 * known, as the versions it supports.
 */
const TLS_OFFERED: Record<string, { offered: string; supports?: string }> = {
  tls12: { offered: "TLS 1.2", supports: "TLS 1.2" },
  tls11_or_older: { offered: "TLS 1.1 or older", supports: "TLS 1.1 or older" },
  no_tls13: { offered: "a version list without TLS 1.3 or TLS 1.0–1.2" },
};

const TRANSPORTS: Record<string, string> = { dot: "DoT", doh: "DoH" };

/**
 * An `edge_tls_version_refused` alert (core.md §9 style, logs/ingest.rs; read defensively): the
 * device a DoT or DoH listener (or the bypass API on a DoH listener) refused because its
 * ClientHello offered no TLS 1.3, the listener, the name it asked for, what it offered, and what
 * to do about it.
 */
function TlsVersionRefused({ details: d }: { details: Record<string, unknown> }) {
  const device = text(d.device);
  const client = text(d.client);
  const mac = text(d.mac);
  const listener = text(d.listener);
  const transport = text(d.transport);
  const offered = text(d.offered);
  const known = offered && Object.hasOwn(TLS_OFFERED, offered) ? TLS_OFFERED[offered] : undefined;
  const via = transport && Object.hasOwn(TRANSPORTS, transport) ? TRANSPORTS[transport] : transport;
  const items: [React.ReactNode, React.ReactNode][] = [
    ["Device", <SafeText>{device && client && device !== client ? `${device} (${client})` : (device ?? client ?? "—")}</SafeText>],
  ];
  if (mac && mac !== device) items.push(["MAC", <SafeText mono>{mac}</SafeText>]);
  items.push(
    ["Listener", <SafeText>{listener ? (via ? `${listener} (${via})` : listener) : "—"}</SafeText>],
    ["Server name", <SafeText>{text(d.sni) ?? "none sent"}</SafeText>],
    ["Offered", <SafeText>{known?.offered ?? offered ?? "—"}</SafeText>],
  );
  return (
    <Section title="Refused TLS version" description="The latest refused handshake, as the edge logged it.">
      <div className="space-y-3" data-testid="tls-version-refused">
        <KeyValue items={items} />
        <p className="text-sm">
          {known?.supports
            ? `This client only supports ${known.supports}; Picket's listeners require TLS 1.3. Update the client, or point it at plain DNS on port 53.`
            : "This client doesn't support TLS 1.3, which Picket's listeners require. Update the client, or point it at plain DNS on port 53."}
        </p>
      </div>
    </Section>
  );
}

/** A feed that blocked a `category_blocked` alert's query (`details.feeds[]`). */
export interface BlockingFeed {
  feed: string;
  category: string | null;
}

/** A sync lookup provider that blocked it (`details.providers[]`, core c58ba80: core.md §9). */
export interface BlockingProvider {
  provider: string;
  category: string | null;
  score: number | null;
  reason: string | null;
  detail: unknown;
  cached: boolean | null;
}

const text = (v: unknown) => (typeof v === "string" ? v : null);

/**
 * What blocked a `category_blocked` alert's query, from its details (core's JSON, read
 * defensively): the feeds (`feeds[]`: feed, category) or the sync lookup providers (`providers[]`:
 * provider, category, score, reason, detail, cached), at most 64 of each.
 */
export function blockedBy(details: Record<string, unknown>): { feeds: BlockingFeed[]; providers: BlockingProvider[] } {
  const list = (v: unknown) => (Array.isArray(v) ? v.slice(0, 64).filter((x): x is Record<string, unknown> => !!x && typeof x === "object" && !Array.isArray(x)) : []);
  const feeds = list(details.feeds)
    .filter((f) => typeof f.feed === "string")
    .map((f) => ({ feed: f.feed as string, category: text(f.category) }));
  const providers = list(details.providers)
    .filter((p) => typeof p.provider === "string")
    .map((p) => ({
      provider: p.provider as string,
      category: text(p.category),
      score: typeof p.score === "number" && Number.isFinite(p.score) ? p.score : null,
      reason: text(p.reason),
      detail: p.detail ?? null,
      cached: typeof p.cached === "boolean" ? p.cached : null,
    }));
  return { feeds, providers };
}

/** A `category_blocked` alert's feeds and lookup providers (core.md §9 "Block alerts per profile"). */
function BlockedBy({ details }: { details: Record<string, unknown> }) {
  const { feeds, providers } = blockedBy(details);
  if (feeds.length === 0 && providers.length === 0) return null;
  return (
    <Section title="Blocked by" description="The feeds and sync lookup providers in the profile's alert settings that blocked the query (the latest raise's).">
      <div className="space-y-4">
        {feeds.length > 0 && (
          <Table aria-label="Blocking feeds">
            <TableHeader>
              <TableRow>
                <TableHead>Feed</TableHead>
                <TableHead>Category</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {feeds.map((f) => (
                <TableRow key={f.feed}>
                  <TableCell>
                    <Link to="/feeds/$feedId" params={{ feedId: f.feed }} className="hover:underline">
                      <SafeText mono>{f.feed}</SafeText>
                    </Link>
                  </TableCell>
                  <TableCell>
                    <SafeText>{f.category ?? "—"}</SafeText>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        {providers.length > 0 && (
          <Table aria-label="Blocking lookup providers">
            <TableHeader>
              <TableRow>
                <TableHead>Lookup provider</TableHead>
                <TableHead>Category</TableHead>
                <TableHead className="text-right">Score</TableHead>
                <TableHead>Reason</TableHead>
                <TableHead>Verdict</TableHead>
                <TableHead>Detail</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {providers.map((p) => (
                <TableRow key={p.provider}>
                  <TableCell>
                    <Link to="/lookup-providers/$providerId" params={{ providerId: p.provider }} className="hover:underline">
                      <SafeText mono>{p.provider}</SafeText>
                    </Link>
                  </TableCell>
                  <TableCell>
                    <SafeText>{p.category ?? "—"}</SafeText>
                  </TableCell>
                  <TableCell className="text-right tabular-nums">{p.score === null ? "—" : String(p.score)}</TableCell>
                  <TableCell>
                    <SafeText>{p.reason ?? "—"}</SafeText>
                  </TableCell>
                  <TableCell>{p.cached === null ? "—" : p.cached ? <Badge variant="outline">cached</Badge> : <Badge variant="outline">fresh</Badge>}</TableCell>
                  <TableCell className="max-w-xs">{p.detail === null ? "—" : <JsonBlock value={p.detail} className="max-h-32" />}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>
    </Section>
  );
}

function ruleText(rule: NonNullable<Evidence["rule"]>): string {
  const parts = [`records for ${rule.domain} and names under it`];
  if (rule.device) parts.push(`from ${rule.device}`);
  if (rule.profiles?.length) parts.push(`in profiles ${rule.profiles.join(", ")}`);
  if (rule.decisions?.length) parts.push(`decided ${rule.decisions.join(" or ")}`);
  if (rule.answers) parts.push("or whose answer names it");
  if (rule.ips?.length) parts.push(`or whose answer holds ${rule.ips.join(", ")}`);
  return escapeControl(parts.join(", "));
}

/** One breakdown (clients or names) with its "other" count. */
function CountTable({ title, counts, other }: { title: string; counts: Record<string, number> | undefined; other: number | undefined }) {
  const rows = Object.entries(counts ?? {}).sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0]));
  return (
    <Table aria-label={`Evidence counts per ${title.toLowerCase()}`}>
      <TableHeader>
        <TableRow>
          <TableHead>{title}</TableHead>
          <TableHead className="text-right">Records</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.length === 0 && !other && (
          <TableRow>
            <TableCell colSpan={2} className="text-center text-sm text-muted-foreground">
              None.
            </TableCell>
          </TableRow>
        )}
        {rows.map(([k, n]) => (
          <TableRow key={k}>
            <TableCell>
              <SafeText mono>{k}</SafeText>
            </TableCell>
            <TableCell className="text-right tabular-nums">{n}</TableCell>
          </TableRow>
        ))}
        {!!other && (
          <TableRow>
            <TableCell className="text-muted-foreground">others (past 1,000 distinct)</TableCell>
            <TableCell className="text-right tabular-nums">{other}</TableCell>
          </TableRow>
        )}
      </TableBody>
    </Table>
  );
}

function EvidenceBody({ ev, alertId }: { ev: Evidence; alertId: number }) {
  // The open copy, by its record: newer copies come first on a refresh and shift the rows.
  const [open, setOpen] = React.useState<string | null>(null);
  const items = ev.items;
  const keys = React.useMemo(() => copyKeys(items), [items]);
  const other = (k: string) => Object.values(ev.counts[k] ?? {}).reduce((x, y) => x + y, 0);
  return (
    <div className="space-y-4">
      {ev.rule ? <p className="text-sm">Copies {ruleText(ev.rule)}.</p> : <p className="text-sm text-muted-foreground">This alert copies no further records.</p>}
      {ev.incomplete && <Badge variant="warning">Breakdown incomplete: further clients or names are counted as others</Badge>}
      {Object.keys(ev.counts).length > 0 && (
        <div className="grid gap-4 md:grid-cols-2">
          <CountTable title="Client" counts={ev.counts.client} other={other("client_other")} />
          <CountTable title="Name" counts={ev.counts.name} other={other("name_other")} />
        </div>
      )}
      <div className="space-y-2">
        <h3 className="text-sm font-medium" data-testid="evidence-copies">
          Copies ({items.length < ev.total ? `${formatNumber(items.length)} of ${formatNumber(ev.total)}` : formatNumber(ev.total)})
        </h3>
        {items.length === 0 ? (
          <p className="text-sm text-muted-foreground">No copies yet.</p>
        ) : (
          <Table aria-label="Evidence copies">
            <TableHeader>
              <TableRow>
                <TableHead>Time</TableHead>
                <TableHead>Name</TableHead>
                <TableHead>Decision</TableHead>
                <TableHead>Device</TableHead>
                <TableHead>Edge</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((it, i) => (
                <React.Fragment key={keys[i]}>
                  <TableRow className="cursor-pointer" tabIndex={0} onClick={() => setOpen(open === keys[i] ? null : keys[i])} onKeyDown={(e) => e.key === "Enter" && setOpen(open === keys[i] ? null : keys[i])}>
                    <TableCell className="whitespace-nowrap text-xs">{formatTime(it.ts)}</TableCell>
                    <TableCell>
                      <SafeText mono>{it.qname}</SafeText> <span className="text-xs text-muted-foreground">{escapeControl(it.qtype ?? "")}</span>
                    </TableCell>
                    <TableCell>
                      <Badge variant={it.decision === "block" ? "destructive" : "outline"}>{escapeControl(it.decision ?? "?")}</Badge>
                      {it.incomplete === true && (
                        <Badge variant="warning" className="ml-1" title="Only the logged preview is known (truncated, or stored with answer_missing)">
                          incomplete
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-xs">
                      <SafeText>{it.device ?? it.client}</SafeText>
                    </TableCell>
                    <TableCell className="text-xs">
                      <SafeText>{it.edge}</SafeText>
                    </TableCell>
                  </TableRow>
                  {open === keys[i] && (
                    <TableRow>
                      <TableCell colSpan={5}>
                        <div className="space-y-2">
                          {it.response && (
                            <Button size="sm" variant="outline" onClick={() => saveBase64(it.response, `alert-${alertId}-reply-${fileSafe(String(it.edge))}-${it.seq}.bin`)}>
                              <DownloadIcon /> Download the reply's wire
                            </Button>
                          )}
                          <JsonBlock value={it} className="max-h-72" />
                        </div>
                      </TableCell>
                    </TableRow>
                  )}
                </React.Fragment>
              ))}
            </TableBody>
          </Table>
        )}
      </div>
      {ev.answers.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-sm font-medium">Answers ({ev.answers.length})</h3>
          <ul className="space-y-2">
            {ev.answers.map((ans) => (
              <li key={ans.answer_id} className="rounded-md border p-2 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <Mono>{escapeControl(ans.answer_id)}</Mono>
                  <Badge variant="outline" title={ANSWER_SOURCE[ans.source]}>
                    {escapeControl(ans.source)}
                  </Badge>
                  <Button size="sm" variant="outline" onClick={() => saveBase64(ans.wire, `alert-${alertId}-answer-${ans.answer_id}.bin`)}>
                    <DownloadIcon /> Download wire
                  </Button>
                </div>
                <pre className="mt-1 max-h-40 overflow-auto rounded-md bg-muted p-2 font-mono text-xs whitespace-pre-wrap break-all">{ans.records.map(escapeControl).join("\n")}</pre>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

const ANSWER_SOURCE: Record<string, string> = {
  log: "An upstream answer an edge logged",
  validator: "The DNSSEC validator's own answer (DNSKEY, DS)",
  crosscheck: "The cross-check resolver's answer",
};

function WireExampleView({ example, index, alertId }: { example: Evidence["examples"][number]; index: number; alertId: number }) {
  const rec = (example.record ?? {}) as Record<string, unknown>;
  const decoded = (example.decoded ?? {}) as { decoded?: { addrs?: string[]; hints?: string[]; chain?: string[]; targets?: string[] }; error?: unknown };
  const list = (v: unknown) => (Array.isArray(v) && v.length ? v.map((x) => escapeControl(String(x))).join(", ") : "—");
  // Core checks the logged answers against the A/AAAA addresses and the HTTPS/SVCB address hints
  // together (logs/wire.rs `compare`), so the hints show with the addresses.
  const hints = decoded.decoded?.hints ?? [];
  const decodedAnswers = [decoded.decoded?.addrs?.length ? list(decoded.decoded.addrs) : null, hints.length ? `hints ${list(hints)}` : null].filter(Boolean).join("; ") || "—";
  return (
    <li className="rounded-md border p-3">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <span className="flex flex-wrap items-center gap-2 text-sm font-medium">
          Example {index + 1} <Badge variant="outline">{escapeControl(example.kind)}</Badge> <SafeText mono>{str(rec.qname)}</SafeText>
          <span className="text-xs font-normal text-muted-foreground">{formatTime(example.at)}</span>
        </span>
        <Button size="sm" variant="outline" disabled={!example.wire} onClick={() => saveBase64(example.wire, `wire-mismatch-${alertId}-${index + 1}.bin`)}>
          <DownloadIcon /> Download as fuzz case
        </Button>
      </div>
      <Table aria-label={`Example ${index + 1}`}>
        <TableHeader>
          <TableRow>
            <TableHead />
            <TableHead>The edge logged</TableHead>
            <TableHead>domain decoded</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {decoded.error !== undefined ? (
            <TableRow>
              <TableCell>Decode</TableCell>
              <TableCell />
              <TableCell className="text-destructive">
                <SafeText>{typeof decoded.error === "string" ? decoded.error : JSON.stringify(decoded.error)}</SafeText>
              </TableCell>
            </TableRow>
          ) : null}
          <TableRow>
            <TableCell>Answers</TableCell>
            <TableCell className="font-mono text-xs">{list(rec.answers)}</TableCell>
            <TableCell className="font-mono text-xs">{decodedAnswers}</TableCell>
          </TableRow>
          <TableRow>
            <TableCell>CNAME chain</TableCell>
            <TableCell className="font-mono text-xs">{list(rec.cname)}</TableCell>
            <TableCell className="font-mono text-xs">{list(decoded.decoded?.chain)}</TableCell>
          </TableRow>
          <TableRow>
            <TableCell>Targets</TableCell>
            <TableCell className="font-mono text-xs">{list(rec.targets)}</TableCell>
            <TableCell className="font-mono text-xs">{list(decoded.decoded?.targets)}</TableCell>
          </TableRow>
        </TableBody>
      </Table>
      <details className="mt-2 text-xs">
        <summary className="cursor-pointer text-muted-foreground">The record and the decode as core stored them</summary>
        <JsonBlock value={{ record: example.record, decoded: example.decoded }} className="mt-1 max-h-60" />
      </details>
    </li>
  );
}

/** One-click "add to manual block feed" (core.md §7): appends `||domain^` to manual-block. */
function AddToBlockFeed({ domain }: { domain: string }) {
  const qc = useQueryClient();
  const [busy, setBusy] = React.useState(false);
  const safe = /^[a-z0-9._-]+$/i.test(domain);
  return (
    <Confirm
      title="Add to the manual block feed?"
      description={
        <span>
          Appends <Mono>{`||${escapeControl(domain)}^`}</Mono> to <Mono>manual-block</Mono> as one new run.
        </span>
      }
      confirmLabel="Add"
      onConfirm={async () => {
        setBusy(true);
        try {
          await unwrap(client.POST("/api/ui/v1/feeds/{id}/file/lines", { params: { path: { id: "manual-block" } }, body: { lines: [`||${domain}^`] } }));
          toast.success("Added to manual-block");
          void qc.invalidateQueries({ queryKey: ["feeds"] });
          // Its file changed: a closed editor's cached file is stale (an open one sees the run).
          void qc.invalidateQueries({ queryKey: qk.manualFile("manual-block"), type: "inactive", refetchType: "none" });
        } catch (e) {
          toast.error(errorMessage(e));
        } finally {
          setBusy(false);
        }
      }}
    >
      <Button variant="outline" disabled={busy || !safe} title={safe ? undefined : "The name has characters a rule can't hold"}>
        <ShieldPlusIcon /> Add to manual block feed
      </Button>
    </Confirm>
  );
}

function FlushVerdicts({ provider }: { provider: string }) {
  const [busy, setBusy] = React.useState(false);
  return (
    <Button
      variant="outline"
      disabled={busy}
      onClick={async () => {
        setBusy(true);
        try {
          const r = await unwrap(client.POST("/api/ui/v1/lookup-providers/{id}/flush", { params: { path: { id: provider } }, body: {} }));
          toast.success(`Cached verdicts flushed on every edge and core (cache generation ${r.cache_generation})`);
        } catch (e) {
          toast.error(errorMessage(e));
        } finally {
          setBusy(false);
        }
      }}
    >
      Flush cached verdicts
    </Button>
  );
}
