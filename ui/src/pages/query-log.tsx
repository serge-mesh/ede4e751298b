import * as React from "react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { DownloadIcon, SearchIcon, XIcon } from "lucide-react";
import { PageHeader, Section, KeyValue } from "@/components/common/page";
import { ErrorState, LoadingState, PagedListError, RefetchError } from "@/components/common/states";
import { JsonBlock, Mono, SafeText } from "@/components/common/text";
import { AppendRuleButton } from "@/components/common/append-rule";
import { EdgeSelector } from "@/components/common/window-picker";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useEntities, usePagedList } from "@/api/queries";
import { client, unwrap } from "@/api/http";
import { WINDOW_SECONDS, type AnswerView, type QueryParams, type AttributionMatch, type LogRecord, type LogReply, type LookupView, type WouldBlockView } from "@/api/types";
import type { QueryLogSearch } from "@/lib/search";
import { formatTime } from "@/lib/format";
import { escapeControl } from "@/lib/text";
import { saveBase64 } from "@/lib/bytes";

const DECISIONS = ["allow", "block", "rewrite", "refused", "servfail"];
const ANY = "__any__";

function toLocalInput(iso?: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function fromLocalInput(v: string): string | undefined {
  if (!v) return undefined;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

/** The search's query to core: an explicit range, else the dashboard window ending now. */
export function logQuery(s: QueryLogSearch, now = Date.now()) {
  const from = s.from ?? (s.window ? new Date(now - WINDOW_SECONDS[s.window] * 1000).toISOString() : undefined);
  return {
    from,
    to: s.to,
    edge: s.edge && s.edge !== "all" ? s.edge : undefined,
    client: s.client,
    device: s.device,
    qname: s.qname,
    match: s.qname ? (s.match ?? "suffix") : undefined,
    // As the URL says: a value core doesn't take is its 400, shown as the page's error.
    decision: s.decision as QueryParams<"searchLogs">["decision"],
    profile: s.profile,
    bundle: s.bundle,
  };
}

export function QueryLogPage() {
  const search = useSearch({ strict: false }) as QueryLogSearch;
  const navigate = useNavigate();
  const [open, setOpen] = React.useState<string | null>(null);
  // Fixed per search, so "Load more" pages stay consistent.
  const query = React.useMemo(() => logQuery(search), [search]);
  // The app's retry rule applies (lib/query-client.ts: a 4xx refusal isn't retried); past one
  // page, the focus reads the newest records alone (usePagedList).
  const q = usePagedList({
    queryKey: ["logs", query],
    fetchPage: (cursor, signal) => unwrap(client.GET("/api/ui/v1/logs", { params: { query: { ...query, cursor, limit: 100 } }, signal })),
    rowKey: (r) => r.id,
  });
  const apply = (s: QueryLogSearch) => void navigate({ to: "/query-log", search: s as Record<string, unknown> });
  const records = q.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <div className="space-y-4">
      <PageHeader title="Query log" description="Newest partition first. Only logged queries are here: a profile's log level limits what reaches core." />
      <SearchForm key={JSON.stringify(search)} search={search} apply={apply} />
      {q.data === undefined ? (
        q.error ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        ) : (
          <LoadingState rows={8} />
        )
      ) : (
        // Loaded records stay on an error (core.md §12): a failed refresh above, a failed page below.
        <div className="space-y-3">
          <PagedListError query={q} placement="top" what="older records" />
          <div className="rounded-md border">
            <Table aria-label="Query log">
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Decision</TableHead>
                  <TableHead>Device</TableHead>
                  <TableHead>Profile</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead>Edge</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {records.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={8} className="h-20 text-center text-sm text-muted-foreground">
                      No records match.
                    </TableCell>
                  </TableRow>
                )}
                {records.map((r) => (
                  <TableRow key={r.id} className="cursor-pointer" tabIndex={0} onClick={() => setOpen(r.id)} onKeyDown={(e) => e.key === "Enter" && setOpen(r.id)}>
                    <TableCell className="whitespace-nowrap text-xs">{formatTime(r.ts)}</TableCell>
                    <TableCell className="max-w-xs">
                      <SafeText mono>{r.qname}</SafeText>
                    </TableCell>
                    <TableCell className="text-xs">{String(r.qtype ?? "")}</TableCell>
                    <TableCell>
                      <DecisionBadge decision={r.decision} />
                    </TableCell>
                    <TableCell className="text-xs">
                      <SafeText>{r.device ?? r.client}</SafeText>
                    </TableCell>
                    <TableCell className="text-xs">
                      <SafeText mono>{r.profile}</SafeText>
                    </TableCell>
                    <TableCell className="text-xs">
                      <SafeText mono>{reasonText(r.reason)}</SafeText>
                      <RecordFlags r={r} />
                    </TableCell>
                    <TableCell className="text-xs">
                      <SafeText>{r.edge}</SafeText>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <PagedListError query={q} placement="bottom" what="older records" />
          {q.hasNextPage && (
            <Button variant="outline" onClick={() => void q.fetchNextPage()} disabled={q.isFetching}>
              Load older records
            </Button>
          )}
        </div>
      )}
      <Sheet open={!!open} onOpenChange={(o) => !o && setOpen(null)}>
        <SheetContent className="sm:max-w-2xl">
          <SheetHeader>
            <SheetTitle>Query detail</SheetTitle>
            <SheetDescription>Full attribution and each lookup's verdict.</SheetDescription>
          </SheetHeader>
          <div className="px-4 pb-4">{open && <RecordDetail id={open} />}</div>
        </SheetContent>
      </Sheet>
    </div>
  );
}

function SearchForm({ search, apply }: { search: QueryLogSearch; apply: (s: QueryLogSearch) => void }) {
  const [draft, setDraft] = React.useState<QueryLogSearch>(search);
  const profiles = useEntities("profiles");
  const bundles = useEntities("bundles");
  const set = (k: keyof QueryLogSearch, v: string | undefined) => setDraft((d) => ({ ...d, [k]: v || undefined }));
  return (
    <Section>
        <form
          className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4"
          onSubmit={(e) => {
            e.preventDefault();
            apply(draft);
          }}
          aria-label="Search the query log"
        >
          <div className="space-y-1.5 sm:col-span-2">
            <Label htmlFor="ql-qname">Name</Label>
            <div className="flex gap-2">
              <Input id="ql-qname" value={draft.qname ?? ""} onChange={(e) => set("qname", e.target.value)} placeholder="example.com" className="font-mono" />
              <Select value={draft.match ?? "suffix"} onValueChange={(v) => set("match", v)}>
                <SelectTrigger aria-label="Name match" className="w-36">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="exact">exact</SelectItem>
                  <SelectItem value="suffix">suffix</SelectItem>
                  <SelectItem value="substring">substring</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ql-from">From</Label>
            <Input id="ql-from" type="datetime-local" value={toLocalInput(draft.from)} onChange={(e) => set("from", fromLocalInput(e.target.value))} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ql-to">To</Label>
            <Input id="ql-to" type="datetime-local" value={toLocalInput(draft.to)} onChange={(e) => set("to", fromLocalInput(e.target.value))} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ql-client">Client address</Label>
            <Input id="ql-client" value={draft.client ?? ""} onChange={(e) => set("client", e.target.value)} placeholder="192.168.1.20" className="font-mono" />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ql-device">Device</Label>
            <Input id="ql-device" value={draft.device ?? ""} onChange={(e) => set("device", e.target.value)} placeholder="name or MAC" />
          </div>
          <div className="space-y-1.5">
            <Label>Edge</Label>
            <EdgeSelector value={draft.edge ?? "all"} onChange={(v) => set("edge", v === "all" ? undefined : v)} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ql-decision">Decision</Label>
            <Select value={draft.decision ?? ANY} onValueChange={(v) => set("decision", v === ANY ? undefined : v)}>
              <SelectTrigger id="ql-decision" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={ANY}>Any decision</SelectItem>
                {DECISIONS.map((d) => (
                  <SelectItem key={d} value={d}>
                    {d}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ql-profile">Profile</Label>
            <Select value={draft.profile ?? ANY} onValueChange={(v) => set("profile", v === ANY ? undefined : v)}>
              <SelectTrigger id="ql-profile" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={ANY}>Any profile</SelectItem>
                {(profiles.data ?? []).map((p) => (
                  <SelectItem key={p.id} value={p.id ?? ""}>
                    {p.id}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ql-bundle">Bundle</Label>
            <Select value={draft.bundle ?? ANY} onValueChange={(v) => set("bundle", v === ANY ? undefined : v)}>
              <SelectTrigger id="ql-bundle" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={ANY}>Any bundle</SelectItem>
                {(bundles.data ?? []).map((b) => (
                  <SelectItem key={b.id} value={b.id ?? ""}>
                    {b.id}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex items-end gap-2 sm:col-span-2 lg:col-span-4">
            <Button type="submit">
              <SearchIcon /> Search
            </Button>
            <Button variant="ghost" onClick={() => apply({ window: search.window, edge: search.edge })}>
              <XIcon /> Clear
            </Button>
            {search.window && !search.from && <span className="text-xs text-muted-foreground">Window: the last {search.window}, from the dashboard.</span>}
          </div>
        </form>
      </Section>
  );
}

export function DecisionBadge({ decision }: { decision?: string }) {
  const v = decision === "block" ? "destructive" : decision === "allow" ? "success" : decision === "rewrite" ? "secondary" : "outline";
  return <Badge variant={v}>{decision ?? "?"}</Badge>;
}

/** A record's `reason` (api.md §5): the ladder step, the deciding bundle or provider, the match kind. */
export function reasonText(reason: unknown): string {
  if (!reason || typeof reason !== "object") return "";
  const r = reason as { step?: number; bundle?: string; provider?: string; kind?: string; allow_id?: string };
  return [r.step !== undefined ? `step ${r.step}` : null, r.bundle ?? r.provider ?? r.allow_id ?? null, r.kind ?? null].filter(Boolean).join(" · ");
}

/** What core's checks found on a record: only the preview known, a wire mismatch, a missed cold block. */
function RecordFlags({ r }: { r: LogRecord }) {
  return (
    <span className="ml-1 inline-flex flex-wrap gap-1 align-middle">
      {r.incomplete && <Badge variant="outline">incomplete</Badge>}
      {r.wire_check === "mismatch" && <Badge variant="warning">wire mismatch</Badge>}
      {r.cold_check === "missed" && <Badge variant="warning">cold block missed</Badge>}
    </span>
  );
}

const ROLE_TEXT: Record<string, string> = {
  decisive: "Decided the query",
  also_matched: "Also matched; another rule decided",
  overridden: "Matched, but cancelled",
  would_block: "Would have blocked (trial)",
};

const BY_TEXT: Record<string, string> = {
  exception: "by an @@ exception",
  badfilter: "by a $badfilter rule",
  rewrite_exception: "by a $dnsrewrite exception",
};

const SOURCE_TEXT: Record<string, string> = {
  response: "the reply the edge made",
  tc: "cut to the header, question and OPT (TC set)",
  answer: "the upstream answer as the edge served it",
  preview: "only the logged preview is known",
};

function MatchList({ matches }: { matches: AttributionMatch[] }) {
  return (
    <ul className="space-y-2">
      {matches.map((m, i) => (
        <li key={i} className="rounded-md border p-2 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={m.role === "decisive" || m.role === "would_block" ? "default" : m.role === "overridden" ? "outline" : "secondary"} title={ROLE_TEXT[m.role]}>
              {escapeControl(m.role)}
            </Badge>
            {m.by && <span className="text-xs text-muted-foreground">{BY_TEXT[m.by] ?? `by ${escapeControl(m.by)}`}</span>}
            <Link to="/feeds/$feedId" params={{ feedId: m.feed }} className="hover:underline">
              <SafeText>{m.feed}</SafeText>
            </Link>
            <span className="text-xs text-muted-foreground">
              in <SafeText mono>{m.bundle}</SafeText>
            </span>
            {m.line !== null && m.line !== undefined && <span className="text-xs text-muted-foreground">line {m.line}</span>}
            {m.format && <span className="text-xs text-muted-foreground">{escapeControl(m.format)}</span>}
          </div>
          <SafeText mono className="mt-1 block">
            {m.text}
          </SafeText>
          <div className="mt-1 text-xs text-muted-foreground">
            {escapeControl(m.rule_type)} rule, matched <SafeText mono>{m.value}</SafeText> at the {escapeControl(m.stage)} stage
          </div>
        </li>
      ))}
    </ul>
  );
}

/** `GET logs/{id}` as the client returns it (openapi-fetch reads `decisive`'s pair as an array). */
const fetchDetail = (id: string, signal?: AbortSignal) => unwrap(client.GET("/api/ui/v1/logs/{id}", { params: { path: { id } }, signal }));
type LogDetail = Awaited<ReturnType<typeof fetchDetail>>;

function Attribution({ a }: { a: LogDetail["attribution"] }) {
  if (!a) return <p className="text-sm text-muted-foreground">No attribution yet: core attributes blocks and rewrites after ingest, and an allow by no rule has none.</p>;
  const decisive = a.decisive ? `step ${a.decisive[0]}, bundle ${escapeControl(String(a.decisive[1] ?? ""))}` : null;
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Badge variant={a.state === "complete" ? "success" : "warning"}>{escapeControl(a.state)}</Badge>
        <span className="text-xs text-muted-foreground">
          self-check{" "}
          <Badge variant={a.self_check === "mismatch" ? "destructive" : "outline"} title="Replay compared with the logged decision">
            {escapeControl(a.self_check)}
          </Badge>
        </span>
        {decisive && <span className="text-xs text-muted-foreground">replay: {decisive}</span>}
      </div>
      {a.state === "incomplete" && <p className="text-xs text-muted-foreground">Incomplete: only the logged preview is known, or a limit cut the replay short.</p>}
      {a.unavailable.length > 0 && (
        <ul className="space-y-1 text-xs">
          {a.unavailable.map((u, i) => (
            <li key={i}>
              Unavailable: {u.bundle ? <SafeText mono>{u.bundle}</SafeText> : "config"} <Mono>{escapeControl(u.head.slice(0, 16))}</Mono> — <SafeText>{u.reason}</SafeText>
            </li>
          ))}
        </ul>
      )}
      {a.matches.length === 0 ? <p className="text-sm text-muted-foreground">No rule matched in replay.</p> : <MatchList matches={a.matches} />}
    </div>
  );
}

function WireButton({ wire, name, label }: { wire: string | null | undefined; name: string; label: string }) {
  if (!wire) return null;
  return (
    <Button size="sm" variant="outline" onClick={() => saveBase64(wire, name)}>
      <DownloadIcon /> {label}
    </Button>
  );
}

function Records({ records }: { records: string[] }) {
  if (records.length === 0) return <p className="text-sm text-muted-foreground">No records.</p>;
  return (
    <pre className="max-h-60 overflow-auto rounded-md bg-muted p-2 font-mono text-xs whitespace-pre-wrap break-all">{records.map(escapeControl).join("\n")}</pre>
  );
}

function Reply({ reply, id }: { reply: LogReply; id: string }) {
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Badge variant="outline">{escapeControl(reply.source)}</Badge>
        <span className="text-xs text-muted-foreground">{SOURCE_TEXT[reply.source] ?? ""}</span>
        {reply.rcode && <Mono>{escapeControl(reply.rcode)}</Mono>}
        {reply.tc && <Badge variant="secondary">TC</Badge>}
        {reply.incomplete && <Badge variant="warning">incomplete</Badge>}
        <WireButton wire={reply.wire} name={`reply-${id.slice(0, 24)}.bin`} label="Download wire" />
      </div>
      <Records records={reply.records} />
    </div>
  );
}

function UpstreamAnswer({ answer }: { answer: AnswerView }) {
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Mono>{escapeControl(answer.id)}</Mono>
        {answer.received_at && <span className="text-xs text-muted-foreground">received {formatTime(answer.received_at)}</span>}
        {answer.age_s !== null && answer.age_s !== undefined && <span className="text-xs text-muted-foreground">served {answer.age_s} s old</span>}
        <WireButton wire={answer.wire} name={`answer-${answer.id}.bin`} label="Download wire" />
      </div>
      <Records records={answer.records} />
    </div>
  );
}

function Lookups({ lookups }: { lookups: LookupView[] }) {
  if (lookups.length === 0) return <p className="text-sm text-muted-foreground">No lookups for this query.</p>;
  return (
    <ul className="space-y-2 text-sm">
      {lookups.map((l, i) => (
        <li key={i} className="rounded-md border p-2">
          <div className="flex flex-wrap items-center gap-2">
            <Mono>{escapeControl(l.provider)}</Mono>
            <Badge variant={l.verdict === "block" ? "destructive" : "secondary"}>{escapeControl(l.verdict ?? "no verdict")}</Badge>
            {l.score !== null && <span className="text-xs">score {l.score}</span>}
            <span className="text-xs text-muted-foreground">{l.source === "cache" ? "from the edge's cache or verdict set" : "from the provider"}</span>
            {l.ms !== null && <span className="text-xs text-muted-foreground">{l.ms} ms</span>}
            {l.timed_out && <Badge variant="warning">timed out</Badge>}
            {l.retry && <Badge variant="outline">retry queued</Badge>}
          </div>
          {l.reason && (
            <div className="mt-1 text-xs">
              Reason: <SafeText>{l.reason}</SafeText>
            </div>
          )}
          {l.detail !== null && (
            <div className="mt-1 space-y-1 text-xs">
              <div>Detail:</div>
              <JsonBlock value={l.detail} className="max-h-32" />
            </div>
          )}
        </li>
      ))}
    </ul>
  );
}

function WouldBlocks({ items }: { items: WouldBlockView[] }) {
  return (
    <ul className="space-y-2">
      {items.map((w) => (
        <li key={w.bundle} className="space-y-1 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <SafeText mono>{w.bundle}</SafeText>
            <Mono className="text-xs text-muted-foreground">{escapeControl(w.head.slice(0, 16))}</Mono>
            {w.key && (
              <span className="text-xs">
                key <SafeText mono>{w.key}</SafeText>
              </span>
            )}
            {w.stage && <Badge variant="outline">{escapeControl(w.stage)}</Badge>}
            {w.status && w.status !== "complete" && <Badge variant="warning">{escapeControl(w.status)}</Badge>}
          </div>
          {w.matches.length > 0 && <MatchList matches={w.matches} />}
        </li>
      ))}
    </ul>
  );
}

function Checks({ r }: { r: LogDetail }) {
  const rows: [string, React.ReactNode][] = [
    ["Wire check", r.wire_check ? <Badge variant={r.wire_check === "mismatch" ? "warning" : "outline"}>{escapeControl(r.wire_check)}</Badge> : "not run yet"],
    ["Trial check", r.trial_check ? formatTime(r.trial_check) : "not run (or nothing to check)"],
    ["Cold check", r.cold_check ? <Badge variant={r.cold_check === "missed" ? "warning" : "outline"}>{escapeControl(r.cold_check)}</Badge> : "—"],
  ];
  if (r.cold_unchecked.length) rows.push(["Cold lookups the edge couldn't make", <SafeText mono>{r.cold_unchecked.join(", ")}</SafeText>]);
  return <KeyValue items={rows} />;
}

function UpstreamText({ u }: { u: { group?: string; upstream?: string | null; ms?: number; cached?: boolean; stale?: boolean; cause?: string } }) {
  const how = u.cached ? (u.stale ? `from the edge's cache, stale${u.cause ? ` (cause ${u.cause})` : ""}` : "from the edge's cache") : u.ms !== undefined ? `${u.ms} ms` : "";
  return (
    <span>
      <SafeText mono>{[u.group, u.upstream].filter(Boolean).join(" · ")}</SafeText>
      {how && <span className="text-muted-foreground"> {escapeControl(how)}</span>}
    </span>
  );
}

function RecordDetail({ id }: { id: string }) {
  const q = useQuery({
    queryKey: ["logs", "item", id],
    queryFn: ({ signal }) => fetchDetail(id, signal),
  });
  if (q.data === undefined) return q.error ? <ErrorState error={q.error} onRetry={() => void q.refetch()} /> : <LoadingState rows={6} />;
  const r = q.data;
  const name = r.qname.replace(/\.$/, "");
  // api.md §5 `upstream` (picket-api UpstreamInfo); null for an answer the edge made itself.
  const upstream = r.upstream as { group?: string; upstream?: string | null; ms?: number; cached?: boolean; stale?: boolean; cause?: string } | null | undefined;
  return (
    <div className="space-y-4">
      {q.error && <RefetchError error={q.error} onRetry={() => void q.refetch()} />}
      <div className="flex flex-wrap gap-2">
        <AppendRuleButton action="allow" name={name} label="Allow permanently" />
        <AppendRuleButton action="block" name={name} label="Block" />
      </div>
      <KeyValue
        items={[
          ["Name", <SafeText mono>{r.qname}</SafeText>],
          ["Type", escapeControl(r.qtype)],
          ["Decision", <span className="flex flex-wrap items-center gap-1"><DecisionBadge decision={r.decision} /> <Mono>{escapeControl(r.rcode)}</Mono> <RecordFlags r={r} /></span>],
          ["Reason", <SafeText mono>{reasonText(r.reason)}</SafeText>],
          ["Time", formatTime(r.ts)],
          ["Client", <SafeText mono>{r.client}</SafeText>],
          ["Device", <SafeText>{r.device}</SafeText>],
          ["Profile", <SafeText mono>{r.profile}</SafeText>],
          ["Edge", <SafeText>{r.edge}</SafeText>],
          ["Listener", <span><SafeText mono>{r.listener}</SafeText> ({escapeControl(r.proto)}){r.do ? ", DO set" : ""}</span>],
          ["Upstream", upstream ? <UpstreamText u={upstream} /> : "answered by the edge"],
        ]}
      />
      <Section title="Attribution" description="Every rule of the bundle versions used that matched, as it stood at those runs, with its role.">
        <Attribution a={r.attribution} />
      </Section>
      <Section title="Reply the client got">
        <Reply reply={r.response} id={r.id} />
      </Section>
      {r.answer && (
        <Section title="Upstream answer" description="The answer the record references, as logged (scrubbed): separate evidence, never rebuilt as the reply.">
          <UpstreamAnswer answer={r.answer} />
        </Section>
      )}
      <Section title="Lookups">
        <Lookups lookups={r.lookups} />
      </Section>
      {r.would_blocks.length > 0 && (
        <Section title="Trial would-blocks" description="Trial bundles of the profile that would have blocked this query.">
          <WouldBlocks items={r.would_blocks} />
        </Section>
      )}
      <Section title="Checks">
        <Checks r={r} />
      </Section>
      {r.versions !== undefined && r.versions !== null && (
        <Section title="Versions" description="The config version and bundle heads the query was answered with.">
          <JsonBlock value={r.versions} />
        </Section>
      )}
    </div>
  );
}
