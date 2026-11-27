// TanStack Query hooks over the UI API. Query keys are arrays whose first element names the
// resource; the UI WebSocket invalidates them by prefix (api/events.ts).
import * as React from "react";
import {
  focusManager,
  hashKey,
  isCancelledError,
  keepPreviousData,
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
  type InfiniteData,
  type QueryClient,
  type QueryFilters,
  type QueryMeta,
} from "@tanstack/react-query";
import { client, request, unwrap } from "./http";
import { ApiError, isNotAvailable } from "./errors";
import { isNotBuiltSeries, unknownSeriesOf } from "./availability";
import { ordered } from "./order";
import { deepEqual } from "@/lib/merge";
import { DEFAULT_DOWNLOAD_MIB, type DownloadCap } from "@/lib/import-file";
import {
  createEntity,
  deleteEntity,
  entityId,
  fetchAllPages,
  getEntity,
  listEntities,
  updateEntity,
  type EntityKind,
  type EntityTypes,
  type SaveFlags,
} from "./entities";
import type {
  Alert,
  Issue,
  Chart,
  EdgeView,
  FeedStatus,
  Outcome,
  Page,
  PendingEdge,
  ProviderStatus,
  QueryParams,
  SecretMeta,
  SettingsView,
  Window,
} from "./types";

// ---------------------------------------------------------------------------------------------
// Keys

export const qk = {
  config: (kind: EntityKind) => ["config", kind] as const,
  entity: (kind: EntityKind, id: string) => ["config", kind, "item", id] as const,
  identity: ["identity"] as const,
  settings: ["settings"] as const,
  issues: ["config", "issues"] as const,
  changes: ["config", "changes"] as const,
  secrets: ["config", "secrets"] as const,
  edges: ["edges"] as const,
  edgeStatus: (id: string) => ["edges", id, "status"] as const,
  edgeConfig: (id: string) => ["edges", id, "config"] as const,
  pending: ["edges", "pending"] as const,
  alerts: (filter: object) => ["alerts", filter] as const,
  alert: (id: number | string) => ["alerts", "item", String(id)] as const,
  /**
   * An alert's evidence (up to alerts.evidence_per_alert copies and their answers' wires): outside
   * the `alerts` prefix, so the alert events that refresh alert views never download it again; the
   * alert's page reads it again for its own alert's events (pages/alerts.tsx).
   */
  alertEvidence: (id: number | string) => ["alert-evidence", String(id)] as const,
  /** `GET temp-allows` per state and edge: `[…, state, edge]` (pages/temporary-allows.tsx). */
  tempAllows: ["temp-allows"] as const,
  /** `GET query-summary`, a device's or a profile's view: `[…, subject, window, edge]` (pages/clients.tsx). */
  querySummary: ["query-summary"] as const,
  /** `GET dnssec/results` per outcome, and `GET dnssec/queue` (pages/dnssec.tsx). */
  dnssecResults: ["dnssec-results"] as const,
  dnssecQueue: ["dnssec-queue"] as const,
  metrics: (series: string[], window: Window, edge: string) => ["metrics", series.join(","), window, edge] as const,
  jobs: ["jobs"] as const,
  browserLists: ["browser-lists"] as const,
  bundleStatus: ["bundles", "status"] as const,
  bundle: (id: string, part: string) => ["bundles", id, part] as const,
  downloadModules: ["modules", "download"] as const,
  lookupModules: ["modules", "lookup"] as const,
  presets: ["feed-presets"] as const,
  providerStatus: ["feed-providers", "status"] as const,
  provider: (id: string, part: string) => ["feed-providers", id, part] as const,
  review: ["feed-providers", "review"] as const,
  feedStatus: ["feeds", "status"] as const,
  /** Every feed's status with when each read was sent (`useFeedStatusesRead`): under `feedStatus`, so it refreshes with it. */
  feedStatusRead: ["feeds", "status", "read"] as const,
  feed: (id: string, part: string) => ["feeds", id, part] as const,
  /**
   * A manual feed's file (up to the download cap): outside the `feeds` prefix, so the events and
   * invalidations that refresh feed views never download it again; the editor decides.
   */
  manualFile: (id: string) => ["manual-file", id] as const,
  warninglists: ["warninglists"] as const,
};

/**
 * Query meta (`meta: READ_ON_OPEN`) for a query read once more when the event socket first opens
 * whatever events do (api/events.ts; what events keep fresh reads then too, `keptByEvents`, and a
 * reconnect reads everything): core's identity, whose version the page compares with the one it
 * loaded with (app-shell.tsx). A read still out when the socket opens lands, and one more follows.
 */
export const READ_ON_OPEN: QueryMeta = { readOnOpen: true };

/** A list read a page at a time with "Load more" (api.md §7 paging). */
type Paged = { state: { data?: unknown } };

/** How many pages a paged list's query has loaded. */
export const pagesLoaded = (q: Paged) => (q.state.data as InfiniteData<unknown> | undefined)?.pages.length ?? 0;

/**
 * TanStack's own refresh of a paged list: a refetch reads every loaded page again, one request
 * each, so its focus refetch and polling (`interval`, for changes core sends no event for) run
 * only while one page is loaded; past that, `usePagedList` reads the first page alone. Reconnects
 * and most events still refresh every loaded page (api/events.ts); events that only add rows go
 * through `refreshPagedLists`.
 */
export function pagedRefresh(interval?: number) {
  return {
    refetchOnWindowFocus: (q: Paged) => pagesLoaded(q) <= 1,
    refetchInterval: (q: Paged) => (interval !== undefined && pagesLoaded(q) <= 1 ? interval : false),
  };
}

/** A page of a list, newest first: each next page starts after the previous page's last row. */
export interface ListPage {
  items: unknown[];
  next_cursor?: string | null;
}

type ListData<P extends ListPage> = InfiniteData<P, string | undefined>;

/**
 * The loaded pages with the first page read again (`head`), older pages kept as loaded. Pages
 * hold rows in core's order and `rowKey` names a row, so `head` replaces the rows from the top
 * down to the last loaded row it also has (a row there it doesn't have has left the list); the
 * rows after that one stay, with the pages after them. A `head` with nothing after it is the
 * whole list; one sharing no row with the loaded pages can't be joined to them (more new rows
 * than a page), so the list starts again from it.
 */
export function withHead<P extends ListPage>(data: ListData<P>, head: P, rowKey: (row: P["items"][number]) => string): ListData<P> {
  const first = data.pageParams[0];
  const alone = { pages: [head], pageParams: [first] };
  if (head.next_cursor == null) return alone;
  const fresh = new Set(head.items.map(rowKey));
  for (let m = data.pages.length - 1; m >= 0; m--) {
    const rows = data.pages[m].items;
    for (let i = rows.length - 1; i >= 0; i--) {
      if (!fresh.has(rowKey(rows[i]))) continue;
      const rest = rows.slice(i + 1);
      // Rows left on page m: go on where page m did. None: from `head`'s last row, which may be
      // past page m's (a cursor from page m would read rows twice).
      const next = rest.length > 0 ? data.pages[m].next_cursor : head.next_cursor;
      return {
        pages: [{ ...head, items: [...head.items, ...rest], next_cursor: next }, ...data.pages.slice(m + 1)],
        pageParams: [first, ...data.pageParams.slice(m + 1)],
      };
    }
  }
  return alone;
}

/** The shortest time between two reads of a mounted paged list that its events cause (`refreshPagedLists`). */
export const PAGED_EVENT_GAP_MS = 2_000;

/** The mounted `usePagedList`s' event refreshes, per query client and query hash. */
const pagedRefreshers = new WeakMap<QueryClient, Map<string, Set<() => void>>>();

function registerPagedRefresher(qc: QueryClient, hash: string, fn: () => void): () => void {
  let byHash = pagedRefreshers.get(qc);
  if (!byHash) pagedRefreshers.set(qc, (byHash = new Map()));
  let fns = byHash.get(hash);
  if (!fns) byHash.set(hash, (fns = new Set()));
  fns.add(fn);
  const own = fns;
  return () => {
    own.delete(fn);
    if (own.size === 0 && byHash.get(hash) === own) byHash.delete(hash);
  };
}

/**
 * Refreshes the paged lists matching `filters` after an event that says rows were added (lists
 * whose loaded rows never change, new ones coming first): a list a mounted `usePagedList` shows
 * reads again as that hook does, at most once per PAGED_EVENT_GAP_MS (an event within it, or
 * while a read is out, reads once at its end), one loaded page by TanStack's refetch and more by
 * the first page alone joined to them (`withHead`), so no read cancels another. Lists nobody shows
 * are only marked stale.
 */
export function refreshPagedLists(qc: QueryClient, filters: QueryFilters) {
  const mounted = pagedRefreshers.get(qc);
  for (const query of qc.getQueryCache().findAll(filters)) {
    const fns = mounted?.get(query.queryHash);
    if (fns && fns.size > 0) for (const fn of [...fns]) fn();
    else void qc.invalidateQueries({ queryKey: query.queryKey, exact: true });
  }
}

/**
 * A list read a page at a time with "Load more" (api.md §7 paging, newest first) that refreshes
 * by itself: on focus while stale and, with `interval`, by polling, for changes core sends no
 * event for. While one page is loaded TanStack refetches it (`pagedRefresh`); past that, only
 * the first page is read again and joined to the loaded ones (`withHead`), so new rows show
 * without reading every page. A read is joined only to the data it was sent after: a refetch or
 * next page that lands meanwhile, or is still out, holds reads as new. A failed read shows as the
 * list's error (Retry reads every loaded page) until the list's data changes again. Events that
 * add rows read the same way, throttled (`refreshPagedLists`).
 */
export function usePagedList<P extends ListPage>({
  queryKey,
  fetchPage,
  rowKey,
  interval,
}: {
  queryKey: readonly unknown[];
  fetchPage: (cursor: string | undefined, signal: AbortSignal) => Promise<P>;
  rowKey: (row: P["items"][number]) => string;
  interval?: number;
}) {
  const qc = useQueryClient();
  const q = useInfiniteQuery({
    queryKey,
    queryFn: ({ pageParam, signal }) => fetchPage(pageParam, signal),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (p) => p.next_cursor ?? undefined,
    ...pagedRefresh(interval),
  });
  const latest = React.useRef({ fetchPage, rowKey });
  React.useEffect(() => {
    latest.current = { fetchPage, rowKey };
  });
  const hash = hashKey(queryKey);
  const [failed, setFailed] = React.useState<{ hash: string; at: number; error: Error } | null>(null);
  React.useEffect(() => {
    const ctrl = new AbortController();
    let reading = false;
    type Query = NonNullable<ReturnType<typeof find>>;
    const find = () => qc.getQueryCache().get<P, Error, ListData<P>>(hash);
    /** Reads the first page and joins it; false when the list's data changed meanwhile (the read is dropped). */
    const readHead = async (query: Query): Promise<boolean> => {
      reading = true;
      const at = query.state.dataUpdatedAt;
      try {
        const head = await latest.current.fetchPage(undefined, ctrl.signal);
        if (query.state.dataUpdatedAt !== at || query.state.fetchStatus !== "idle") return false;
        qc.setQueryData<ListData<P>>(query.queryKey, (d) => d && withHead(d, head, latest.current.rowKey));
      } catch (e) {
        if (!ctrl.signal.aborted) setFailed({ hash, at, error: e instanceof Error ? e : new Error(String(e)) });
      } finally {
        reading = false;
      }
      return true;
    };
    const refresh = async (onFocus: boolean) => {
      const query = find();
      if (reading || !query || pagesLoaded(query) <= 1 || query.state.fetchStatus !== "idle" || (onFocus && !query.isStale())) return;
      await readHead(query);
    };
    // Events that add rows (refreshPagedLists): one read at a time, PAGED_EVENT_GAP_MS apart. A
    // read that is out (this hook's, TanStack's refetch or next page) may predate the event, so
    // the event's read waits for it; one dropped because the data changed meanwhile is retried.
    let last = Number.NEGATIVE_INFINITY;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const later = (ms: number) => {
      timer = setTimeout(eventRead, ms);
    };
    const eventRead = () => {
      timer = undefined;
      const query = find();
      if (ctrl.signal.aborted || !query) return;
      if (reading || query.state.fetchStatus !== "idle") return later(PAGED_EVENT_GAP_MS);
      last = Date.now();
      if (pagesLoaded(query) <= 1) {
        void qc.invalidateQueries({ queryKey: query.queryKey, exact: true });
        return;
      }
      void readHead(query).then((joined) => {
        if (!joined && !ctrl.signal.aborted && timer === undefined) later(PAGED_EVENT_GAP_MS);
      });
    };
    const unregister = registerPagedRefresher(qc, hash, () => {
      // A read already due covers this event too.
      if (timer !== undefined) return;
      const wait = last + PAGED_EVENT_GAP_MS - Date.now();
      if (wait > 0) later(wait);
      else eventRead();
    });
    // As TanStack's own: polling only while the page is in view, the focus only for stale data.
    const poll =
      interval === undefined
        ? undefined
        : setInterval(() => {
            if (focusManager.isFocused()) void refresh(false);
          }, interval);
    const unsubscribe = focusManager.subscribe((focused) => {
      if (focused) void refresh(true);
    });
    return () => {
      ctrl.abort();
      clearInterval(poll);
      clearTimeout(timer);
      unregister();
      unsubscribe();
    };
  }, [qc, hash, interval]);
  const refreshError = failed && failed.hash === hash && failed.at === q.dataUpdatedAt ? failed.error : null;
  return refreshError && !q.error ? { ...q, error: refreshError } : q;
}

// ---------------------------------------------------------------------------------------------
// Config entities

export function useEntities<K extends EntityKind>(kind: K, opts: { enabled?: boolean } = {}) {
  return useQuery({
    queryKey: qk.config(kind),
    queryFn: ({ signal }) => listEntities(kind, signal),
    enabled: opts.enabled ?? true,
  });
}

export function useEntity<K extends EntityKind>(kind: K, id: string | undefined) {
  return useQuery({
    queryKey: qk.entity(kind, id ?? ""),
    queryFn: ({ signal }) => getEntity(kind, id ?? "", signal),
    enabled: !!id,
  });
}

// Entities have no server-side version check (api.md §7), so every write to one goes through
// one queue per entity (`serialised`): the read-modify-write actions (Add to bundle…, Enforce,
// Disable, …), form saves, creates and deletes alike. Each action reads the entity fresh inside
// its turn, applies its change and writes it back; a form save first checks that the entity is
// still the one the form was edited from (`StaleEntity` otherwise). So no write starts from a
// value read before an earlier write of this page landed.
const writeQueues = new Map<string, Promise<unknown>>();

/** Runs `fn` after every earlier write queued under `key`. */
export function serialised<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const prev = writeQueues.get(key) ?? Promise.resolve();
  const next = prev.catch(() => undefined).then(fn);
  writeQueues.set(key, next);
  void next.finally(() => {
    if (writeQueues.get(key) === next) writeQueues.delete(key);
  }).catch(() => undefined);
  return next;
}

const entityKey = (kind: EntityKind, id: string) => `${kind}/${id}`;

/** Runs another write to one entity (an action endpoint that changes it) in its queue. */
export function entityWrite<T>(kind: EntityKind, id: string, fn: () => Promise<T>): Promise<T> {
  return serialised(entityKey(kind, id), fn);
}

/**
 * A form save refused before sending: the entity changed since the form's base (another tab,
 * another admin, or an action on this page that wrote first). `current` is what it is now.
 */
export class StaleEntity<T = unknown> extends Error {
  constructor(readonly current: T) {
    super("It changed since you started editing: reload it or keep your changes, then save again.");
  }
}

/**
 * Creates (no `id`) or replaces an entity, in its write queue; invalidates its kind and what
 * depends on it. A replace with `base` (the saved value the form was edited from) sends `body`
 * only while the entity still equals it; otherwise it throws `StaleEntity` and writes nothing.
 */
export function useSaveEntity<K extends EntityKind>(kind: K) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body, base, flags }: { id?: string; body: EntityTypes[K]; base?: EntityTypes[K]; flags?: SaveFlags }) =>
      id
        ? serialised(entityKey(kind, id), async () => {
            if (base !== undefined) {
              const current = await getEntity(kind, id);
              if (!deepEqual(current, base)) throw new StaleEntity(current);
            }
            return updateEntity(kind, id, body, flags);
          })
        : serialised(entityKey(kind, entityId(kind, body)), () => createEntity(kind, body)),
    onSettled: () => invalidateConfig(qc, kind),
  });
}

/** The result of a read-modify-write: the outcome, or null when the change was already there. */
export async function modifyEntity<K extends EntityKind>(
  kind: K,
  id: string,
  change: (current: EntityTypes[K]) => EntityTypes[K] | null,
  flags?: SaveFlags,
): Promise<Outcome | null> {
  return serialised(entityKey(kind, id), async () => {
    const current = await getEntity(kind, id);
    const next = change(current);
    if (next === null) return null;
    return updateEntity(kind, id, next, flags);
  });
}

/** `modifyEntity` as a mutation that invalidates the kind afterwards. */
export function useModifyEntity<K extends EntityKind>(kind: K) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, change, flags }: { id: string; change: (current: EntityTypes[K]) => EntityTypes[K] | null; flags?: SaveFlags }) =>
      modifyEntity(kind, id, change, flags),
    onSettled: () => invalidateConfig(qc, kind),
  });
}

export function useDeleteEntity(kind: EntityKind) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => serialised(entityKey(kind, id), () => deleteEntity(kind, id)),
    onSuccess: () => invalidateConfig(qc, kind),
  });
}

/**
 * Every feed provider's views read again, except backtests: one replays history only when Run asks
 * (core computes each in full, and a read sent over one in flight would have core compute two), so
 * it is only marked stale, and read when next shown.
 */
export function invalidateProviders(qc: ReturnType<typeof useQueryClient>) {
  const backtest = (q: { queryKey: readonly unknown[] }) => q.queryKey[2] === "backtest";
  void qc.invalidateQueries({ queryKey: ["feed-providers"], predicate: (q) => !backtest(q) });
  void qc.invalidateQueries({ queryKey: ["feed-providers"], predicate: backtest, refetchType: "none" });
}

export function invalidateConfig(qc: ReturnType<typeof useQueryClient>, kind?: EntityKind) {
  void qc.invalidateQueries({ queryKey: kind ? qk.config(kind) : ["config"] });
  void qc.invalidateQueries({ queryKey: qk.issues });
  // Statuses derive from definitions.
  if (!kind || kind === "feeds" || kind === "feed-providers") {
    void qc.invalidateQueries({ queryKey: ["feeds"] });
    invalidateProviders(qc);
  }
  if (!kind || kind === "bundles" || kind === "feeds" || kind === "profiles") {
    void qc.invalidateQueries({ queryKey: ["bundles"] });
    void qc.invalidateQueries({ queryKey: qk.browserLists });
    void qc.invalidateQueries({ queryKey: qk.warninglists });
  }
  if (!kind || kind === "listeners") void qc.invalidateQueries({ queryKey: qk.edges });
}

export { entityId };

// ---------------------------------------------------------------------------------------------
// Core, settings, secrets

/** Core's identity; read again whenever the event socket opens, for its version (READ_ON_OPEN, app-shell.tsx). */
export function useIdentity() {
  return useQuery({
    queryKey: qk.identity,
    queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/identity", { signal })),
    staleTime: 5 * 60_000,
    meta: READ_ON_OPEN,
  });
}

/**
 * The settings view. `refetchInterval` polls it while this view's observer is mounted, from the
 * view read last (e.g. the LAN CA tab while core's clock isn't synchronised: no event says when
 * it is).
 */
export function useSettings(opts: { refetchInterval?: (view: SettingsView | undefined) => number | false } = {}) {
  const poll = opts.refetchInterval;
  return useQuery({
    queryKey: qk.settings,
    queryFn: ({ signal }) => fetchSettings(signal),
    refetchInterval: poll ? (q) => poll(q.state.data) : undefined,
  });
}

type SettingsValue = Awaited<ReturnType<typeof fetchSettings>>["settings"];

export function fetchSettings(signal?: AbortSignal) {
  return unwrap(client.GET("/api/ui/v1/settings", { signal }));
}

/**
 * The download size cap an import is bounded by (api.md §7), read from the settings
 * (`feeds.max_download_mib`) as an import starts; core's default (core.md §5) when they can't be
 * read, which the refusal then says.
 */
export async function downloadCap(qc: QueryClient): Promise<DownloadCap> {
  // A restore or reconnect cancels reads in flight (api/events.ts invalidateAll): asked again.
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const s = await qc.fetchQuery({ queryKey: qk.settings, queryFn: ({ signal }) => fetchSettings(signal), staleTime: 0, retry: false });
      // Left out, core's default applies (settings.rs serde defaults).
      return { bytes: (s.settings.feeds?.max_download_mib ?? DEFAULT_DOWNLOAD_MIB) * MIB, fromSettings: true };
    } catch (e) {
      // Unreadable settings: core's default below.
      if (!isCancelledError(e)) break;
    }
  }
  return { bytes: DEFAULT_DOWNLOAD_MIB * MIB, fromSettings: false };
}

const MIB = 1024 * 1024;

/**
 * A settings form's save refused before sending: a section it covers changed since the form's
 * base (another tab, another admin). `current` is what the settings are now.
 */
export class StaleSettings extends Error {
  constructor(readonly current: SettingsValue) {
    super("These settings changed since you started editing: reload them or keep your changes, then save again.");
  }
}

/**
 * Saves a partial nested settings object, in one write queue for the settings. Settings have no
 * version check and core writes every leaf a patch names (settings.rs `apply_patch`), and a form
 * sends its changed sections whole: so a form's save (`check`) re-reads the settings in its turn
 * and sends nothing, throwing `StaleSettings`, when a section it covers is no longer its base,
 * as an entity form does (api.md §7).
 */
export function useSaveSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ patch, check }: { patch: Record<string, unknown>; check?: { base: SettingsValue; keys: string[] } }) =>
      serialised("settings", async () => {
        if (check) {
          const current = (await fetchSettings()).settings;
          const part = (x: SettingsValue) => check.keys.map((k) => (x as Record<string, unknown>)[k]);
          if (!deepEqual(part(current), part(check.base))) throw new StaleSettings(current);
        }
        return request<unknown>("PUT", "/settings", { body: patch });
      }),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: qk.settings });
      void qc.invalidateQueries({ queryKey: qk.issues });
      void qc.invalidateQueries({ queryKey: qk.identity });
    },
  });
}

/**
 * Core's `409` code for a rotation whose `lanca.rotate_from` is no longer the current root
 * (lanca::rotation `ROOT_CHANGED`, core 07acc1c): another change replaced it. Its other `409`,
 * `conflict`, means a previous root is still in use.
 */
export const LANCA_ROOT_CHANGED = "lanca_root_changed";

/**
 * A LAN CA rotation refused because the root it named in `lanca.rotate_from` is no longer the
 * current one (core's `409 lanca_root_changed`: another change replaced it). `current` is the
 * settings view read right after (null when it couldn't be read).
 */
export class StaleRoot extends Error {
  constructor(
    readonly refusal: ApiError,
    readonly current: SettingsView | null,
  ) {
    super(refusal.message);
  }
}

/** Core's own `503 unavailable` (web/error.rs `CoreError::Unavailable`; on PUT settings, its clock isn't synchronised). */
export function isCoreUnavailable(e: unknown): boolean {
  return e instanceof ApiError && e.status === 503 && e.code === "unavailable";
}

/**
 * Whether a write's answer was lost, so it may have taken effect: no answer at all (status 0: the
 * connection dropped) or a 5xx other than core's own `503 unavailable` (a proxy's 502, 503 or
 * timeout, or core failing after its commit). Core's refusals (4xx, its 503) change nothing.
 */
export function answerLost(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 0 || (e.status >= 500 && !isCoreUnavailable(e)));
}

/**
 * A LAN CA rotation whose answer was lost (`answerLost`, or a 2xx without the settings view):
 * core may have rotated. `now` is the settings view read right after (null when it couldn't be
 * read either), to judge by the root core has.
 */
export class RotationAnswerLost extends Error {
  constructor(
    readonly lost: ApiError,
    readonly now: SettingsView | null,
  ) {
    super(lost.message);
  }
}

/**
 * Rotates the LAN CA (core.md §11; PUT settings, core c58ba80): `{lanca: {zones, rotate_from}}`
 * alone, `rotate_from` the root the admin decided on, in the settings' write queue. Core's `409`
 * says by its code why: `lanca_root_changed` when that root is no longer the current one
 * (`StaleRoot`, with the settings read again), `conflict` while a previous root is still in use
 * (core 07acc1c). An answer lost after core may have committed is `RotationAnswerLost` with the
 * settings read again. Resolves to core's answer, the settings view (a root that is still `from`
 * means core kept it: the zones were the ones it has).
 */
export function useRotateLanca() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ zones, from }: { zones: string[]; from: string }) =>
      serialised("settings", async () => {
        let lost: ApiError;
        try {
          const view = await request<SettingsView | undefined>("PUT", "/settings", { body: { lanca: { zones, rotate_from: from } } });
          if (typeof view?.lanca?.fingerprint === "string") return view;
          lost = new ApiError(200, "no_view", "Core's answer didn't carry the settings.");
        } catch (e) {
          if (e instanceof ApiError && e.status === 409 && e.code === LANCA_ROOT_CHANGED) throw new StaleRoot(e, await fetchSettings().catch(() => null));
          if (!answerLost(e)) throw e;
          lost = e as ApiError;
        }
        throw new RotationAnswerLost(lost, await fetchSettings().catch(() => null));
      }),
    // Core answers with the settings view on the new root: the page has it at once. Core sends
    // its `lanca rotated` event before this answer, so the settings read that event causes can show
    // the new root while the request is out (the LAN CA form says nothing of a moved root then).
    // The same for the settings read after a lost answer.
    onSuccess: (view) => qc.setQueryData(qk.settings, view),
    onError: (e) => {
      if (e instanceof RotationAnswerLost && e.now) qc.setQueryData(qk.settings, e.now);
      // The root core has now, at once: the form names it with the refusal.
      if (e instanceof StaleRoot && e.current) qc.setQueryData(qk.settings, e.current);
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: qk.settings });
      void qc.invalidateQueries({ queryKey: qk.issues });
      void qc.invalidateQueries({ queryKey: qk.identity });
    },
  });
}

export function useConfigIssues() {
  return useQuery({
    queryKey: qk.issues,
    queryFn: ({ signal }) =>
      // Core answers every issue in one page (no `limit`; next_cursor stays null).
      fetchAllPages<Issue>((cursor) => request<Page<Issue>>("GET", "/config/issues", { query: { cursor }, signal })),
  });
}

export function useSecrets() {
  return useQuery({
    queryKey: qk.secrets,
    queryFn: ({ signal }) =>
      fetchAllPages<SecretMeta>((cursor) =>
        unwrap(client.GET("/api/ui/v1/secrets", { params: { query: { cursor, limit: 500 } }, signal })),
      ),
  });
}

// ---------------------------------------------------------------------------------------------
// Edges

export function useEdges(refetchInterval?: number) {
  return useQuery({
    refetchInterval,
    queryKey: qk.edges,
    queryFn: ({ signal }) =>
      fetchAllPages<EdgeView>((cursor) => unwrap(client.GET("/api/ui/v1/edges", { params: { query: { cursor, limit: 500 } }, signal }))),
  });
}

export function useEdgeStatus(id: string | undefined, refetchInterval?: number) {
  return useQuery({
    queryKey: qk.edgeStatus(id ?? ""),
    queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/edges/{id}/status", { params: { path: { id: id ?? "" } }, signal })),
    enabled: !!id,
    refetchInterval,
  });
}

export function usePendingEdges() {
  return useQuery({
    queryKey: qk.pending,
    queryFn: ({ signal }) =>
      fetchAllPages<PendingEdge>((cursor) =>
        unwrap(client.GET("/api/ui/v1/edges/pending", { params: { query: { cursor, limit: 500 } }, signal })),
      ),
  });
}

/** Any mutation that changes edges; invalidates the edge views. */
export function useEdgeMutation<V>(fn: (v: V) => Promise<unknown>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.edges });
      void qc.invalidateQueries({ queryKey: qk.issues });
    },
  });
}

// ---------------------------------------------------------------------------------------------
// Alerts

/** `GET alerts` filters, typed by core's OpenAPI document. */
export type AlertFilter = Omit<QueryParams<"listAlerts">, "cursor" | "limit">;

export function useAlerts(filter: AlertFilter) {
  return useInfiniteQuery({
    queryKey: qk.alerts(filter),
    queryFn: ({ pageParam, signal }) =>
      unwrap(
        client.GET("/api/ui/v1/alerts", {
          params: { query: { ...filter, cursor: pageParam, limit: 100 } },
          signal,
        }),
      ) as Promise<Page<Alert>>,
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    placeholderData: keepPreviousData,
  });
}

/** Open alerts (all pages, bounded), for counts and dashboard lists. */
export function useOpenAlerts(refetchInterval?: number) {
  return useQuery({
    refetchInterval,
    queryKey: qk.alerts({ state: "open", all: true }),
    queryFn: ({ signal }) =>
      fetchAllPages<Alert>((cursor) =>
        unwrap(client.GET("/api/ui/v1/alerts", { params: { query: { state: "open", cursor, limit: 500 } }, signal })),
      ),
  });
}

export function useAlertMutation<V>(fn: (v: V) => Promise<unknown>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["alerts"] });
      void qc.invalidateQueries({ queryKey: qk.review });
    },
  });
}

// ---------------------------------------------------------------------------------------------
// Metrics

/** A chart, and the series asked for that this core doesn't record yet. */
export type ChartData = Chart & { unavailable: string[] };

/**
 * Asks for a chart's series (api.md §7 `GET metrics`) in one call. When core answers
 * `422 unknown series` for a series core.md §10 names but this core doesn't record yet
 * (api/availability.ts), that series is left out and the rest asked for again, so one such series
 * doesn't blank the chart; only when none is left is the chart "not available yet". Any other
 * unknown series is an error.
 */
export async function fetchChart(series: string[], window: Window, edge: string, signal?: AbortSignal): Promise<ChartData> {
  let ask = [...series];
  const unavailable: string[] = [];
  for (;;) {
    try {
      const chart = (await unwrap(
        client.GET("/api/ui/v1/metrics", { params: { query: { series: ask.join(","), window, edge } }, signal }),
      )) as Chart;
      return { ...chart, unavailable };
    } catch (e) {
      const name = e instanceof ApiError && e.status === 422 ? unknownSeriesOf(e.message) : null;
      if (name === null || !isNotBuiltSeries(name) || !ask.includes(name)) throw e;
      unavailable.push(name);
      ask = ask.filter((s) => s !== name);
      if (ask.length === 0) throw e;
    }
  }
}

/** One chart's series over a window; each chart asks separately. */
export function useMetrics(
  series: string[],
  window: Window,
  edge: string,
  opts: { enabled?: boolean; refetchInterval?: number } = {},
) {
  return useQuery({
    queryKey: qk.metrics(series, window, edge),
    queryFn: ({ signal }) => fetchChart(series, window, edge, signal),
    enabled: (opts.enabled ?? true) && series.length > 0,
    refetchInterval: opts.refetchInterval,
    placeholderData: keepPreviousData,
    retry: (count, e) => !isNotAvailable(e) && count < 2,
  });
}

// ---------------------------------------------------------------------------------------------
// Feeds and providers

export function useFeedStatuses(refetchInterval?: number) {
  return useQuery({
    refetchInterval,
    queryKey: qk.feedStatus,
    queryFn: ({ signal }) =>
      fetchAllPages<FeedStatus>((cursor) =>
        unwrap(client.GET("/api/ui/v1/feed-status", { params: { query: { cursor, limit: 500 } }, signal })),
      ),
  });
}

/**
 * Every feed's status, as `useFeedStatuses` gives it, with when each read was sent (api/order.ts):
 * for a view that ends a held run report by it (a feed isn't `busy` once its run ended). Its own
 * query, since its answers are never replaced by an equal earlier one (`structuralSharing: false`).
 */
export function useFeedStatusesRead() {
  return useQuery({
    queryKey: qk.feedStatusRead,
    queryFn: ordered((signal) =>
      fetchAllPages<FeedStatus>((cursor) => unwrap(client.GET("/api/ui/v1/feed-status", { params: { query: { cursor, limit: 500 } }, signal }))),
    ),
    structuralSharing: false,
  });
}

export function useProviderStatuses() {
  return useQuery({
    queryKey: qk.providerStatus,
    queryFn: ({ signal }) =>
      fetchAllPages<ProviderStatus>((cursor) =>
        unwrap(client.GET("/api/ui/v1/feed-provider-status", { params: { query: { cursor, limit: 500 } }, signal })),
      ),
  });
}

export function useReviewQueue() {
  return useQuery({
    queryKey: qk.review,
    queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/feed-providers-review", { signal })),
  });
}

export function useDownloadModules() {
  return useQuery({
    queryKey: qk.downloadModules,
    queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/download-modules", { signal })),
    staleTime: Infinity,
  });
}

// ---------------------------------------------------------------------------------------------
// Bundles, lists, warninglists, jobs

export function useBundleStatuses() {
  return useQuery({
    queryKey: qk.bundleStatus,
    queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/bundle-status", { signal })),
  });
}

export function useBrowserLists() {
  return useQuery({
    queryKey: qk.browserLists,
    queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/browser-lists", { signal })),
  });
}

export function useWarninglists() {
  return useQuery({
    queryKey: qk.warninglists,
    queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/warninglists", { signal })),
  });
}

export function useJobs(refetchInterval?: number) {
  return useQuery({
    queryKey: qk.jobs,
    queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/jobs", { signal })),
    refetchInterval,
  });
}
