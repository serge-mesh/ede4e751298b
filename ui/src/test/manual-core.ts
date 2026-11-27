// A stateful mock of core's manual feed (feeds.md §1, api.md §7) for the editor's tests.
import fixtures from "./fixtures/core.json";
import { reply, type Call, type Route } from "./mock-api";
import { feedRunFrame, runItem } from "./events";
import type { FeedRunItem } from "@/api/types";

export const RUN = {
  feed_id: "manual-block",
  kind: "download",
  status: "applied",
  added: { dns: 1, ip: 0, browser: 0 },
  removed: { dns: 0, ip: 0, browser: 0 },
  total: { dns: 3, ip: 0, browser: 0 },
  policy_dropped: {},
  error: null,
  gate: null,
  source_run: null,
  updated_at: "2026-11-23T10:00:00.000000Z",
  downloaded_at: "2026-11-23T10:00:00.000000Z",
  confirmed_at: null,
  blob: null as string | null,
  parse: null,
};

/** FNV-1a (32 bits) with a seed, as 8 hex characters. */
function fnv32(s: string, seed: number): string {
  let h = (0x811c9dc5 ^ Math.imul(seed, 0x9e3779b1)) >>> 0;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 0x01000193) >>> 0;
  return h.toString(16).padStart(8, "0");
}

/** The blob a text is stored as (core: its BLAKE3; any content hash keeps the property tested). */
export const blobOf = (content: string) => [0, 1, 2, 3, 4, 5, 6, 7].map((seed) => fnv32(content, seed)).join("");
/** A file's version: the blob's short id (feeds/manual.rs), so the same text gives the same version. */
export const versionOf = (content: string) => blobOf(content).slice(0, 16);

interface Save {
  version: string;
  blob: string;
  at: string;
}

const conflict = (version: string) => reply(409, { error: { code: "conflict", message: `the file changed since it was read (version ${version}); reload it and save again` } });

/**
 * core's manual feed: `PUT file` needs the current version as base_version (else 409); a changed
 * text is stored with a new save time and the version of its content (a text that comes back
 * brings its version back), and the write returns both (`saved_at`, the string its run carries as
 * `updated_at`); a run row appears only when its run ends (`finishRun`), with the version and
 * `updated_at` of the save it read, and its `feed_run` event (`event`, listing it) names both;
 * `status.busy` holds while a save of an enabled feed waits for its run, and the status gives the
 * file's `version`, `saved_at` and `manual_retry_at` (`st.retryAt`).
 */
export function manualCore(feed = "manual-block", opts: { enabled?: boolean; content?: string } = {}) {
  let clock = Date.parse("2026-11-23T10:00:00Z");
  /** core's clock: RFC 3339 with microseconds, one second per save. */
  const tick = () => {
    clock += 1000;
    return new Date(clock).toISOString().replace("Z", "000Z");
  };
  const content = opts.content ?? "||original.example^\n";
  const first: Save = { version: versionOf(content), blob: blobOf(content), at: tick() };
  const st = {
    content,
    version: first.version,
    savedAt: first.at,
    saves: [first] as Save[],
    runs: [{ ...RUN, feed_id: feed, id: 7, version: first.version, updated_at: first.at, blob: first.blob }] as Record<string, unknown>[],
    fileReads: 0,
    statusReads: 0,
    /** The last run id given (ids aren't reused after a restore deletes the runs). */
    lastRun: 7,
    busy: false,
    retryAt: null as string | null,
    enabled: opts.enabled ?? true,
  };
  const write = (text: string) => {
    const blob = blobOf(text);
    st.content = text;
    st.version = blob.slice(0, 16);
    st.savedAt = tick();
    st.saves.push({ version: st.version, blob, at: st.savedAt });
    if (st.enabled) {
      st.busy = true;
      st.retryAt = null;
    }
    return st.version;
  };
  /** A manual-feed write's answer (SaveResult, and Imported's file fields). */
  const saved = (text: string) => (text === st.content ? { version: st.version, saved_at: st.savedAt, changed: false } : { version: write(text), saved_at: st.savedAt, changed: true });
  const item = (run: number): FeedRunItem => {
    const r = st.runs.find((x) => x.id === run);
    const opt = <T,>(v: unknown) => (v ?? null) as T | null;
    return runItem({ feed, run, kind: String(r?.kind ?? "download"), status: String(r?.status ?? "applied"), gate: opt<string>(r?.gate), version: opt<string>(r?.version), saved_at: opt<string>(r?.updated_at), source_run: opt<number>(r?.source_run) });
  };
  const statusFixture = (fixtures as Record<string, unknown>)[`/feeds/${feed}/status`] ?? (fixtures as Record<string, unknown>)["/feeds/manual-block/status"];
  return {
    st,
    /** Another writer's save of `text`. */
    save: write,
    /** Another writer's one-click append (`POST file/lines`). */
    append: (line: string) => write(`${st.content}${line}\n`),
    /**
     * A restore (config/export.rs): the file becomes the export's, with the export's own save time
     * (`at`: it can be older than saves since), and every run is deleted.
     */
    restore: (text: string, at: string) => {
      const blob = blobOf(text);
      st.content = text;
      st.version = blob.slice(0, 16);
      st.savedAt = at;
      st.saves.push({ version: st.version, blob, at });
      st.runs = [];
      st.busy = false;
      return st.version;
    },
    /** The run of the newest save of `version` (default: the file now) ends: its row appears. */
    finishRun: (version: string = st.version, extra: Record<string, unknown> = {}) => {
      const save = [...st.saves].reverse().find((x) => x.version === version);
      const id = (st.lastRun = Math.max(st.lastRun, ...st.runs.map((r) => r.id as number)) + 1);
      st.runs.unshift({ ...RUN, feed_id: feed, id, version, updated_at: save?.at ?? null, downloaded_at: save?.at ?? null, blob: save?.blob ?? null, ...extra });
      if (version === st.version) st.busy = false;
      return id;
    },
    /** A stored run as core's `feed_run` event lists it (FeedRunItem): its version and, for a manual feed, its save time. */
    item,
    /** The `feed_run` event core sends for these stored runs (coalesced: FeedRunEvent, core a3eb6d5), in this order. */
    event: (...runs: number[]) => feedRunFrame(runs.map(item)).data,
    /** `POST feeds/{id}/import` into this feed (feeds/transfer.rs): base_version checked, the file replaced or merged into, like a save. */
    importRoute: (lines: string): Route => ({
      method: "POST",
      path: `/feeds/${feed}/import`,
      body: (c: Call) => {
        if ((c.query.get("base_version") ?? null) !== st.version) return conflict(st.version);
        const text = c.query.get("mode") === "replace" ? lines : `${st.content}${lines}`;
        return { feed, created: false, ...saved(text), run_queued: false, entries: null };
      },
    }),
    routes: [
      {
        method: "GET",
        path: `/feeds/${feed}/file`,
        body: () => {
          st.fileReads++;
          return { version: st.version, content: st.content, saved_at: st.savedAt, size: st.content.length };
        },
      },
      {
        method: "PUT",
        path: `/feeds/${feed}/file`,
        body: (c: Call) => {
          const b = c.body as { content: string; base_version: string | null };
          if (b.base_version !== st.version) return conflict(st.version);
          return saved(b.content);
        },
      },
      { method: "GET", path: `/feeds/${feed}/runs`, body: (c: Call) => ({ items: st.runs.slice(0, Number(c.query.get("limit") ?? 50)), next_cursor: null }) },
      {
        method: "GET",
        path: `/feeds/${feed}/status`,
        body: () => {
          st.statusReads++;
          return { ...(statusFixture as object), feed, busy: st.busy, enabled: st.enabled, version: st.version, saved_at: st.savedAt, manual_retry_at: st.busy ? null : st.retryAt };
        },
      },
    ] as Route[],
  };
}
