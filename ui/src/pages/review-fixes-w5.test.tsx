// Review round 1 of the wave-5 wiring (dev/briefs/fix-ui-w5.md): what a restore leaves cached
// (Z1), temporary allows and DNSSEC results following core (Z2), alert evidence read only for its
// own alert (Z3), the restore's head scan (Z4), errors in paged lists (Z5), the trial graph per
// edge (Z6), the export's progress and Cancel (Z7), and the small ones (Z9). Z8 is in
// wave5-ops.test.tsx.
import { describe, expect, it, vi } from "vitest";
import { act, renderHook, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { focusManager, type QueryClient, type QueryKey } from "@tanstack/react-query";
import { mockApi, mutations, reply, type Call } from "@/test/mock-api";
import { renderApp } from "@/test/render";
import { W5 } from "@/test/core-w5";
import { alertFrame, type AlertLike } from "@/test/events";
import { captureDownloads } from "@/test/downloads";
import { contractViolations } from "@/test/contract";
import { isRestore, useUiEvent } from "@/api/events";
import { qk } from "@/api/queries";
import { TRIAL_LIMITS } from "./trial-bundle";
import { scanExportRoot } from "./settings";

const T = { timeout: 8000 };
type Rec = Record<string, unknown>;
const gets = (calls: Call[], path: string) => calls.filter((c) => c.method === "GET" && c.path === path);
const coreError = (status: number, code: string, message: string) => reply(status, { error: { code, message } });
const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));
const file = (content: string, name = "picket-config-2026-11-24.json") => new File([content], name, { type: "application/json" });

interface FakeSocket {
  open(): void;
  emit(data: unknown): void;
}
const socket = () => (globalThis.WebSocket as unknown as { instances: FakeSocket[] }).instances.at(-1)!;

/** The refresh options a mounted query's observer resolves to now (functions evaluated against the query). */
function refreshOf(qc: QueryClient, queryKey: QueryKey) {
  const q = qc.getQueryCache().find({ queryKey, exact: true });
  const o = q?.observers[0]?.options as { refetchInterval?: unknown; refetchOnWindowFocus?: unknown } | undefined;
  const val = (v: unknown) => (typeof v === "function" ? (v as (x: unknown) => unknown)(q) : v);
  return { interval: val(o?.refetchInterval), focus: val(o?.refetchOnWindowFocus) };
}

/** The window losing and regaining focus (TanStack's focus refetch). */
function refocus() {
  act(() => {
    focusManager.setFocused(false);
    focusManager.setFocused(true);
  });
  focusManager.setFocused(undefined);
}

describe("Z1: a restore refreshes what the page holds (the restoring tab, whether or not core's restore event arrives)", () => {
  it("shows the restored secrets, marks every cached read stale, and drops a cached manual file (its editor's next open reads it)", async () => {
    const user = userEvent.setup();
    let restored = false;
    const before = { items: [{ name: "old_secret", has_value: true }], next_cursor: null };
    const after = { items: [{ name: "aws_secret", has_value: false }], next_cursor: null };
    const { calls } = mockApi([
      { method: "GET", path: "/secrets", body: () => (restored ? after : before) },
      {
        method: "PUT",
        path: "/config/export",
        body: () => {
          restored = true;
          return { restored: true, generation: 1, missing_secrets: ["aws_secret"], warnings: [] };
        },
      },
    ]);
    const { queryClient } = renderApp("/settings?tab=secrets");
    // What an open manual-feed editor listens for to check its file (api/events.ts resync).
    const heard: string[] = [];
    renderHook(() => useUiEvent((ev) => heard.push(ev.type)));
    expect(await screen.findByText("old_secret", undefined, T)).toBeInTheDocument();
    queryClient.setQueryData(qk.manualFile("manual-block"), { content: "||a.example^\n", saved_at: "2026-11-24T00:00:00.000000Z" });
    await user.click(screen.getByRole("tab", { name: "Export and restore" }));
    await user.upload(await screen.findByLabelText("File", undefined, T), file(JSON.stringify(W5["GET /config/export"])));
    await user.click(await screen.findByRole("button", { name: /^Restore$/ }, T));
    const at = Date.now();
    await user.click(await screen.findByRole("button", { name: "Restore" }));
    const result = await screen.findByTestId("restore-result", undefined, T);
    expect(heard).toEqual(["resync"]);
    // Every read cached before the restore is stale or read again after it, except a manual file's.
    for (const q of queryClient.getQueryCache().getAll()) {
      if (q.queryKey[0] === "manual-file") continue;
      expect(q.state.isInvalidated || q.state.dataUpdatedAt >= at, JSON.stringify(q.queryKey)).toBe(true);
    }
    // A closed editor's cached file is dropped, never downloaded here: a restore can take its save
    // time back, so the next open reads it rather than start from it (fix-6b2 U3).
    expect(queryClient.getQueryState(qk.manualFile("manual-block"))).toBeUndefined();
    await user.click(within(result).getByRole("link", { name: "set them under Secrets" }));
    const table = await screen.findByRole("table", { name: "Secrets" }, T);
    expect(await within(table).findByText("aws_secret", undefined, T)).toBeInTheDocument();
    expect(within(table).queryByText("old_secret")).toBeNull();
    expect(within(table).getByText("missing")).toBeInTheDocument();
    expect(gets(calls, "/feeds/manual-block/file")).toHaveLength(0);
  });
});

describe("Z1: a restore that may have run", () => {
  it("reads everything again after an error that isn't one of core's refusals (a lost connection, a 5xx), not after a refusal", async () => {
    const user = userEvent.setup();
    const answers = [coreError(409, "busy", "a restore is running; try again when it ends"), coreError(502, "bad_gateway", "the connection was lost")];
    let n = 0;
    mockApi([{ method: "PUT", path: "/config/export", refuses: true, body: () => answers[n++] }]);
    renderApp("/settings?tab=export");
    const heard: string[] = [];
    renderHook(() => useUiEvent((ev) => heard.push(isRestore(ev) ? "resync (restore)" : ev.type)));
    await user.upload(await screen.findByLabelText("File", undefined, T), file(JSON.stringify(W5["GET /config/export"])));
    const restore = async () => {
      await user.click(await screen.findByRole("button", { name: /^Restore$/ }, T));
      await user.click(await screen.findByRole("button", { name: "Restore" }));
    };
    await restore();
    expect(await screen.findByTestId("restore-error", undefined, T)).toHaveTextContent("Another restore is running");
    expect(heard).toEqual([]);
    await restore();
    await waitFor(() => expect(screen.getByTestId("restore-error")).toHaveTextContent("the connection was lost"), T);
    // As after a restore (fix-6b2 U3): manual feed pages forget what they knew of their files' saves.
    expect(heard).toEqual(["resync (restore)"]);
  });
});

describe("Z2: temporary allows and DNSSEC results follow core", () => {
  // Core 720be97 sends `temp_allow` and `dnssec` events: the re-reads on edge_status and DNSSEC
  // alerts, and the revoked badge in the active list, are replaced (ui-cf2.test.tsx, P3 and P5).
  it("polls while the event socket isn't open (core's events say what changed once it is), while one page is loaded", async () => {
    mockApi();
    const { queryClient } = renderApp("/temporary-allows");
    await screen.findByRole("table", { name: "Active temporary allows" }, T);
    await waitFor(() => expect(refreshOf(queryClient, ["temp-allows", "active", "all"]).interval).toBe(60_000), T);
    expect(refreshOf(queryClient, ["temp-allows", "recent", "all"]).interval).toBe(60_000);
    act(() => socket().open());
    await waitFor(() => expect(refreshOf(queryClient, ["temp-allows", "active", "all"]).interval).toBe(false), T);
    expect(refreshOf(queryClient, ["temp-allows", "recent", "all"]).interval).toBe(false);
  });
});

describe("Z3: alert evidence is read again only for its own alert, at most every 30 s", () => {
  it("ignores other alerts' events and reads its own alert's evidence once now and once at the end of the interval", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const a = W5["/alerts/{category_blocked}"] as { alert: AlertLike };
      const id = a.alert.id;
      const { calls } = mockApi([
        { method: "GET", path: `/alerts/${id}`, body: a },
        { method: "GET", path: `/alerts/${id}/evidence`, body: W5["/alerts/{category_blocked}/evidence"] },
      ]);
      const { queryClient } = renderApp(`/alerts/${id}`);
      await screen.findByText(/Copies \(/, undefined, T);
      // Events come through the page's event socket (applyEvent, then the page's own listeners).
      act(() => socket().open());
      const emit = (alert: AlertLike) => act(() => socket().emit(alertFrame([alert])));
      const ev = () => gets(calls, `/alerts/${id}/evidence`).length;
      expect(ev()).toBe(1);
      for (let i = 0; i < 5; i++) emit({ id: 999, kind: "edge_offline", state: "open" });
      await act(() => vi.advanceTimersByTimeAsync(31_000));
      expect(ev()).toBe(1);
      // Its own alert raised again three times: one read now, one at the end of the interval.
      for (let i = 0; i < 3; i++) emit({ ...a.alert, count: 2 + i });
      await waitFor(() => expect(ev()).toBe(2), T);
      await act(() => vi.advanceTimersByTimeAsync(10_000));
      expect(ev()).toBe(2);
      await act(() => vi.advanceTimersByTimeAsync(21_000));
      await waitFor(() => expect(ev()).toBe(3), T);
      await act(() => vi.advanceTimersByTimeAsync(60_000));
      expect(ev()).toBe(3);
      // Its deletion reads nothing more.
      emit({ id, kind: a.alert.kind, deleted: true });
      await act(() => vi.advanceTimersByTimeAsync(31_000));
      expect(ev()).toBe(3);
      expect(queryClient.getQueryCache().find({ queryKey: ["alerts"], exact: false, predicate: (q) => q.queryKey.includes("evidence") })).toBeUndefined();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("Z4: the restore reads format_version wherever the document's top level has it", () => {
  const doc = W5["GET /config/export"] as Rec;

  it("offers Restore for an export with sorted keys (format_version past the first 4 KiB), as core accepts it", async () => {
    const user = userEvent.setup();
    const sorted = Object.fromEntries(Object.keys(doc).sort().map((k) => [k, doc[k]]));
    const text = JSON.stringify(sorted);
    expect(text.indexOf('"format_version"')).toBeGreaterThan(4096);
    const { calls } = mockApi([{ method: "PUT", path: "/config/export", body: { restored: true, generation: 1, missing_secrets: [], warnings: [] } }]);
    renderApp("/settings?tab=export");
    await user.upload(await screen.findByLabelText("File", undefined, T), file(text));
    expect(await screen.findByTestId("export-head", undefined, T)).toHaveTextContent("A config export from picket-core 0.1.0");
    expect(screen.getByTestId("export-head")).toHaveTextContent("(format 1)");
    await user.click(screen.getByRole("button", { name: /^Restore$/ }));
    await user.click(await screen.findByRole("button", { name: "Restore" }));
    await screen.findByTestId("restore-result", undefined, T);
    expect(mutations(calls).find((c) => c.path === "/config/export")!.body).toEqual(sorted);
  });

  it("refuses a document whose top level has no format_version, and only warns when it can't tell", async () => {
    const user = userEvent.setup();
    mockApi();
    renderApp("/settings?tab=export");
    const input = await screen.findByLabelText("File", undefined, T);
    // format_version nested deeper doesn't count: core reads the top level's.
    await user.upload(input, file(JSON.stringify({ configuration: { format_version: 1 }, alerts: [] })));
    expect(await screen.findByText(/no format_version at its top level/, undefined, T)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Restore$/ })).toBeDisabled();
    await user.upload(input, file("[1, 2]"));
    expect(await screen.findByText(/not a JSON object/, undefined, T)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Restore$/ })).toBeDisabled();
    // Cut short before format_version: the page can't tell, core can.
    await user.upload(input, file(`{"alerts": [${'{"a": "x"},'.repeat(1000)}`));
    expect(await screen.findByTestId("export-head-unknown", undefined, T)).toHaveTextContent(/core checks it when you restore/);
    expect(screen.getByRole("button", { name: /^Restore$/ })).toBeEnabled();
  });

  it("scans the top level's keys in chunks, past strings and nesting, within a budget (unit)", async () => {
    const blob = (s: string) => new Blob([s]);
    const late = `{"alerts": [{"format_version": 9, "t": "\\"}{,"}], "x\\"y": "]", "exported_at": "2026-11-24T02:00:00Z", "format_version": 1}`;
    expect(await scanExportRoot(blob(late), { chunk: 7 })).toEqual({ kind: "export", format: 1, exportedAt: "2026-11-24T02:00:00Z" });
    expect(await scanExportRoot(blob(`\uFEFF {"format_version" : 2 , "core_version": "0.2.0"}`))).toMatchObject({ kind: "export", format: 2 });
    expect(await scanExportRoot(blob(`{"format\\u005fversion": 1}`))).toMatchObject({ kind: "export", format: 1 });
    expect(await scanExportRoot(blob('{"picket_feed_export": 1, "format_version": 1}'))).toEqual({ kind: "feed-export" });
    // A feed export names itself first (as Feeds → Import reads it); later, it's another key.
    expect(await scanExportRoot(blob('{"format_version": 1, "picket_feed_export": 1}'))).toEqual({ kind: "export", format: 1 });
    expect(await scanExportRoot(blob('{"a": {"format_version": 1}}'))).toEqual({ kind: "no-format" });
    expect(await scanExportRoot(blob("  ||ads.example^"))).toEqual({ kind: "not-object" });
    expect(await scanExportRoot(blob(""))).toEqual({ kind: "not-object" });
    expect(await scanExportRoot(blob(`{"alerts": "${"x".repeat(5000)}", "format_version": 1}`), { budget: 4096, chunk: 1024 })).toEqual({ kind: "unknown" });
    expect(await scanExportRoot(blob(`{"alerts": [1, 2`))).toEqual({ kind: "unknown" });
    expect(await scanExportRoot(blob(`{"format_version": "1"}`))).toEqual({ kind: "unknown" });
    // A key or value longer than any the restore reads is skipped whole, however long.
    expect(await scanExportRoot(blob(`{"${"k".repeat(70_000)}": "${"v".repeat(70_000)}", "format_version": 1}`), { chunk: 4096 })).toMatchObject({ kind: "export", format: 1 });
    expect(await scanExportRoot(blob(`{"format_version": ${"1".repeat(300)}}`))).toEqual({ kind: "unknown" });
  });
});

describe("Z5: paged lists keep their rows on an error", () => {
  const first = W5["/logs?limit=3"] as { items: Rec[]; next_cursor: string };
  const older = { items: [(W5["/logs"] as { items: Rec[] }).items.at(-1)], next_cursor: null };

  it("shows the loaded records with an inline error when Load older fails, and retries that page", async () => {
    const user = userEvent.setup();
    let fail = true;
    const { calls } = mockApi([{ method: "GET", path: "/logs", body: (c: Call) => (c.query.get("cursor") ? (fail ? coreError(503, "unavailable", "core is busy") : older) : first) }]);
    renderApp("/query-log");
    await screen.findByText("lookup.example", undefined, T);
    await user.click(screen.getByRole("button", { name: "Load older records" }));
    const error = await screen.findByTestId("next-page-error", undefined, T);
    expect(error).toHaveTextContent("Couldn't load older records: core is busy");
    expect(screen.getByText("lookup.example")).toBeInTheDocument();
    fail = false;
    const n = gets(calls, "/logs").length;
    await user.click(within(error).getByRole("button", { name: /Retry/ }));
    expect(await screen.findByText("ads.example", undefined, T)).toBeInTheDocument();
    expect(screen.queryByTestId("next-page-error")).toBeNull();
    // Only the failed page was asked for again.
    expect(gets(calls, "/logs").slice(n).map((c) => c.query.get("cursor"))).toEqual([first.next_cursor]);
  });

  it("keeps the records when a background refetch fails", async () => {
    let fail = false;
    mockApi([{ method: "GET", path: "/logs", body: () => (fail ? coreError(503, "unavailable", "core is busy") : first) }]);
    const { queryClient } = renderApp("/query-log");
    await screen.findByText("lookup.example", undefined, T);
    fail = true;
    act(() => void queryClient.invalidateQueries({ queryKey: ["logs"] }));
    expect(await screen.findByTestId("refetch-error", undefined, T)).toHaveTextContent("core is busy");
    expect(screen.getByText("lookup.example")).toBeInTheDocument();
  });

  it("keeps a record's detail when reading it again fails", async () => {
    const user = userEvent.setup();
    let fail = false;
    const id = (first.items[0] as { id: string }).id;
    mockApi([
      { method: "GET", path: "/logs", body: first },
      { method: "GET", path: `/logs/${id}`, body: () => (fail ? coreError(503, "unavailable", "core is busy") : W5["/logs/{seq 9}"]) },
    ]);
    const { queryClient } = renderApp("/query-log");
    await user.click(await screen.findByText("lookup.example", undefined, T));
    const sheet = await screen.findByRole("dialog", undefined, T);
    await within(sheet).findByText("Attribution", undefined, T);
    fail = true;
    act(() => void queryClient.invalidateQueries({ queryKey: ["logs", "item", id] }));
    expect(await within(sheet).findByTestId("refetch-error", undefined, T)).toHaveTextContent("core is busy");
    expect(within(sheet).getByText("Attribution")).toBeInTheDocument();
  });

  it("doesn't retry core's refusal of a search (4xx), with the app's own retry rule", async () => {
    const { calls } = mockApi([{ method: "GET", path: "/logs", body: () => coreError(400, "bad_request", "from: an RFC 3339 time") }]);
    renderApp("/query-log", { retry: true });
    expect(await screen.findByText(/from: an RFC 3339 time/, undefined, T)).toBeInTheDocument();
    await pause(1500);
    expect(gets(calls, "/logs")).toHaveLength(1);
  });

  it("refetches on focus while one page is loaded; once older pages are, reads the newest page alone (G1), not each page", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([{ method: "GET", path: "/logs", body: (c: Call) => (c.query.get("cursor") ? older : first) }]);
    const { queryClient } = renderApp("/query-log");
    await screen.findByText("lookup.example", undefined, T);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    // Stale without a refetch of its own, so only the focus can read it again.
    act(() => void queryClient.invalidateQueries({ queryKey: ["logs"], refetchType: "none" }));
    let n = gets(calls, "/logs").length;
    refocus();
    await waitFor(() => expect(gets(calls, "/logs").length).toBe(n + 1), T);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    await user.click(screen.getByRole("button", { name: "Load older records" }));
    expect(await screen.findByText("ads.example", undefined, T)).toBeInTheDocument();
    act(() => void queryClient.invalidateQueries({ queryKey: ["logs"], refetchType: "none" }));
    n = gets(calls, "/logs").length;
    refocus();
    await pause(300);
    expect(gets(calls, "/logs").slice(n).map((c) => c.query.get("cursor"))).toEqual([null]);
    expect(screen.getByText("ads.example")).toBeInTheDocument();
  });

  it("does the same for temporary allows and DNSSEC results: TanStack's refetch of every page is off past one page (G1 reads the first)", async () => {
    const user = userEvent.setup();
    const allow = { ...(W5["/temp-allows?state=active"] as { items: Rec[] }).items[0] };
    const cursor = (W5["/temp-allows?limit=1"] as { next_cursor: string }).next_cursor;
    mockApi([
      {
        method: "GET",
        path: "/temp-allows",
        body: (c: Call) =>
          c.query.get("state") === "recent" ? { items: [], next_cursor: null } : c.query.get("cursor") ? { items: [{ ...allow, allow_id: "a-9", target: "second.example" }], next_cursor: null } : { items: [allow], next_cursor: cursor },
      },
    ]);
    const { queryClient } = renderApp("/temporary-allows");
    await screen.findByText("ads.example", undefined, T);
    const key = ["temp-allows", "active", "all"];
    expect(refreshOf(queryClient, key)).toEqual({ interval: 60_000, focus: true });
    await user.click(screen.getByRole("button", { name: "Load more" }));
    expect(await screen.findByText("second.example", undefined, T)).toBeInTheDocument();
    expect(refreshOf(queryClient, key)).toEqual({ interval: false, focus: false });
  });
});

// Z6 (the trial graph charted every edge's would-blocks with a note) is replaced: core 720be97
// counts them per edge, so the graph follows the edge selector (ui-cf2.test.tsx, P6).

describe("Z7: the export's progress and Cancel", () => {
  it("shows how much has arrived of core's Content-Length, and Cancel ends the download (core's export slot is released) without saving", async () => {
    const user = userEvent.setup();
    const saved = captureDownloads();
    mockApi();
    let cancelled = false;
    const real = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if (!String(input instanceof Request ? input.url : input).endsWith("/config/export")) return real(input, init);
      const body = new ReadableStream<Uint8Array>({
        start(c) {
          c.enqueue(new Uint8Array(1024 * 1024));
        },
        cancel() {
          cancelled = true;
        },
      });
      return new Response(body, {
        status: 200,
        headers: { "content-type": "application/json", "content-length": String(3 * 1024 * 1024), "content-disposition": 'attachment; filename="picket-config-2026-11-24.json"' },
      });
    }) as typeof fetch;
    try {
      renderApp("/settings?tab=export");
      expect(await screen.findByText(/best downloaded on a desktop browser/, undefined, T)).toBeInTheDocument();
      await user.click(await screen.findByRole("button", { name: /Download export/ }, T));
      expect(await screen.findByText("1.0 MiB of 3.0 MiB (33 %)", { exact: false }, T)).toBeInTheDocument();
      // A tab switch keeps the download and its Cancel.
      await user.click(screen.getByRole("tab", { name: "Secrets" }));
      await user.click(screen.getByRole("tab", { name: "Export and restore" }));
      await user.click(await screen.findByRole("button", { name: "Cancel the export" }, T));
      await waitFor(() => expect(cancelled).toBe(true), T);
      expect(await screen.findByRole("button", { name: /Download export/ }, T)).toBeEnabled();
      expect(saved).toHaveLength(0);
      expect(screen.queryByTestId("export-error")).toBeNull();
    } finally {
      globalThis.fetch = real;
    }
  });

  it("saves the whole document once it has arrived", async () => {
    const user = userEvent.setup();
    const saved = captureDownloads();
    const doc = JSON.stringify(W5["GET /config/export"]);
    mockApi([{ method: "GET", path: "/config/export", body: doc, headers: { "content-type": "application/json", "content-length": String(doc.length), "content-disposition": 'attachment; filename="picket-config-2026-11-24.json"' } }]);
    renderApp("/settings?tab=export");
    await user.click(await screen.findByRole("button", { name: /Download export/ }, T));
    await waitFor(() => expect(saved).toHaveLength(1), T);
    expect(saved[0].name).toBe("picket-config-2026-11-24.json");
    expect(await saved[0].blob.text()).toBe(doc);
    expect(saved[0].blob.type).toBe("application/json");
    expect(await screen.findByRole("button", { name: /Download export/ }, T)).toBeEnabled();
  });
});

describe("Z9: the small ones", () => {
  it("keeps the trial check's limits on the page while trial-results loads or fails", async () => {
    mockApi([{ method: "GET", path: "/trial-results", body: () => coreError(503, "unavailable", "core is busy") }]);
    renderApp("/profiles/p1/trial/trial-b");
    const limits = await screen.findByRole("list", { name: "What the trial check can't see" }, T);
    for (const l of TRIAL_LIMITS) expect(within(limits).getByText(l)).toBeInTheDocument();
    // The UI's own list is core's (logs/query.rs trial_results `limits`).
    expect(TRIAL_LIMITS).toEqual((W5["/trial-results"] as { limits: string[] }).limits);
  });

  it("shows a wire-mismatch example's SVCB hints with domain's answers (core counts them as answers)", async () => {
    const a = W5["/alerts/{wire_mismatch}"] as { alert: { id: number } };
    const ev = structuredClone(W5["/alerts/{wire_mismatch}/evidence"]) as { examples: { decoded: { decoded: Rec } }[] };
    ev.examples[0].decoded.decoded.hints = ["192.0.2.7", "2001:db8::7"];
    mockApi([
      { method: "GET", path: `/alerts/${a.alert.id}`, body: a },
      { method: "GET", path: `/alerts/${a.alert.id}/evidence`, body: ev },
    ]);
    renderApp(`/alerts/${a.alert.id}`);
    const table = await screen.findByRole("table", { name: "Example 1" }, T);
    const answers = within(table).getByText("Answers").closest("tr")!;
    expect(answers).toHaveTextContent("192.0.2.1");
    expect(answers).toHaveTextContent("hints 192.0.2.7, 2001:db8::7");
  });

  it("models core refusing format_version 0 and a temp-allows cursor it didn't give", () => {
    const identity = (p: string) => (p === "/identity" ? { lanca_zones: ["home.arpa"] } : undefined);
    const doc = W5["GET /config/export"] as Rec;
    const q = (s = "") => new URLSearchParams(s);
    expect(contractViolations("PUT", "/config/export", q(), { ...doc, format_version: 0 }, identity)).toEqual([expect.stringMatching(/422 an export of format 0/)]);
    expect(contractViolations("PUT", "/config/export", q(), { ...doc, format_version: -1 }, identity)).toEqual([expect.stringMatching(/422 format_version: a whole number/)]);
    expect(contractViolations("PUT", "/config/export", q(), { ...doc, format_version: 1 }, identity)).toEqual([]);
    const cursor = (W5["/temp-allows?limit=1"] as { next_cursor: string }).next_cursor;
    expect(contractViolations("GET", "/temp-allows", q(`state=active&cursor=${cursor}`), undefined)).toEqual([]);
    // "YQ" is "a"; "YR" decodes to "a" too where trailing bits are allowed (Node), not in core.
    expect(contractViolations("GET", "/temp-allows", q("cursor=YQ"), undefined)).toEqual([]);
    for (const bad of ["x", "next-1", "a+b/", "YQ==", "_w", "YR", "YWJ"]) expect(contractViolations("GET", "/temp-allows", q(`cursor=${encodeURIComponent(bad)}`), undefined), bad).toEqual([expect.stringMatching(/400 bad cursor/)]);
  });
});
