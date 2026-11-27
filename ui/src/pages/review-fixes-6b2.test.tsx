// Review fixes for the UI at 6b2588a and its adaptation to core 4e4f53d (dev/briefs/fix-6b2-ui.md):
// U1 views that poll only while the event socket is down read once more when it first opens; U2 a
// feed's check-derived views read again on every feed_run; U3 the manual editor's newest save is
// reset by a restore; U5 a banner when core's version differs from the page's; U6 core 4e4f53d's
// required fields and evidence changes in `alert` events. U4's frames are test/events.ts's and the
// contract's (test/contract.ts `eventViolations`).
import { describe, expect, it, vi } from "vitest";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { toast } from "sonner";
import { QueryClient } from "@tanstack/react-query";
import { EditorView } from "@codemirror/view";
import { mockApi, mutations, type Call } from "@/test/mock-api";
import { manualCore } from "@/test/manual-core";
import { renderApp } from "@/test/render";
import { MAX_LISTED, alertFrame, alertItem, feedRunFrame, jobFrame, runItem, truncatedAlertFrame, truncatedRunFrame, type AlertLike } from "@/test/events";
import { checkSchema, eventViolations } from "@/test/contract";
import { W5, capturedTruncated, recordDetail } from "@/test/core-w5";
import { applyEvent, beforeRestoreEvent, feedRunsChanged, restoreSent, resyncForRestore } from "@/api/events";
import { qk } from "@/api/queries";
import { page } from "@/lib/page";
import { EVIDENCE_REFRESH_MS } from "./alerts";

const T = { timeout: 8000 };
type Rec = Record<string, unknown>;
const gets = (calls: Call[], path: string) => calls.filter((c) => c.method === "GET" && c.path === path);
const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

interface FakeSocket {
  open(): void;
  emit(data: unknown): void;
  onclose: (() => void) | null;
}
const sockets = () => (globalThis.WebSocket as unknown as { instances: FakeSocket[] }).instances;
const socket = () => sockets().at(-1)!;
/** Core restarts: the socket closes, and the page opens a new one (after the 1 s backoff). */
async function reconnect() {
  const n = sockets().length;
  act(() => socket().onclose?.());
  await waitFor(() => expect(sockets().length).toBe(n + 1), T);
  act(() => socket().open());
}
/** The keys of `keys` a query client marks stale. */
const staleOf = (qc: QueryClient, keys: (readonly unknown[])[]) => keys.filter((k) => qc.getQueryCache().find({ queryKey: k, exact: true })?.state.isInvalidated).map((k) => k.join("/"));

describe("U2: a feed's check-derived views read again on every feed_run (Codex UD2, Opus UE1)", () => {
  it("marks every feed's status, checks and learned schedule stale; its runs, a run, its entries and its export size only for its listed runs (unit)", () => {
    const keys = [
      qk.feed("a", "runs"),
      qk.feed("a", "run:4"),
      qk.feed("a", "entries:dns:true"),
      qk.feed("a", "status"),
      qk.feed("b", "runs"),
      qk.feed("b", "run:9"),
      qk.feed("b", "entries:dns:true"),
      qk.feed("b", "status"),
      qk.feed("b", "checks"),
      qk.feed("b", "schedule"),
      qk.feed("b", "export-size"),
      qk.feedStatus,
      qk.feedStatusRead,
    ];
    const stale = (frame: unknown) => {
      const qc = new QueryClient();
      for (const k of keys) qc.setQueryData(k, {});
      applyEvent(qc, frame as never);
      return staleOf(qc, keys);
    };
    const always = ["feeds/a/status", "feeds/b/status", "feeds/b/checks", "feeds/b/schedule", "feeds/status", "feeds/status/read"];
    expect(stale(feedRunFrame([{ feed: "a", run: 4 }]))).toEqual(["feeds/a/runs", "feeds/a/run:4", "feeds/a/entries:dns:true", ...always]);
    expect(stale(feedRunFrame([{ feed: "b", run: 9 }]))).toEqual(["feeds/a/status", "feeds/b/runs", "feeds/b/run:9", "feeds/b/entries:dns:true", "feeds/b/status", "feeds/b/checks", "feeds/b/schedule", "feeds/b/export-size", "feeds/status", "feeds/status/read"]);
    expect(stale(feedRunFrame([{ feed: "c", run: 5 }]))).toEqual(always);
    expect(stale(truncatedRunFrame([{ feed: "c", run: 5 }]))).toEqual(keys.map((k) => k.join("/")));
    expect(stale({ type: "feed_run", data: null })).toEqual(keys.map((k) => k.join("/")));
    expect(feedRunsChanged(["feeds"], [], false)).toBe(true);
  });

  /** A provider's feed (`hagezi-pro`) with its status, learned schedule and check history as core gives them. */
  function providerFeed() {
    const { calls, fixtures } = mockApi([
      { method: "GET", path: "/feeds/hagezi-pro", body: () => ({ ...(fixtures["/feeds/manual-block"] as Rec), id: "hagezi-pro", name: "HaGeZi PRO", provider: "hagezi", file: "adblock/pro.txt", system: false }) },
      { method: "GET", path: "/feeds/hagezi-pro/status", body: () => ({ ...(fixtures["/feeds/manual-block/status"] as Rec), feed: "hagezi-pro", provider: "hagezi", manual: false }) },
      { method: "GET", path: "/feeds/hagezi-pro/schedule", body: () => fixtures["/feeds/manual-block/schedule"] },
      { method: "GET", path: "/feeds/hagezi-pro/checks", body: () => fixtures["/feeds/manual-block/checks"] },
    ]);
    return calls;
  }

  it("an open feed's status and learned schedule read again on an event listing only another feed's run (its check found it unchanged)", async () => {
    const calls = providerFeed();
    const { queryClient } = renderApp("/feeds/hagezi-pro?tab=overview");
    await waitFor(() => expect(gets(calls, "/feeds/hagezi-pro/schedule").length).toBeGreaterThan(0), T);
    act(() => socket().open());
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    const reads = () => [gets(calls, "/feeds/hagezi-pro/status").length, gets(calls, "/feeds/hagezi-pro/schedule").length];
    const [s, h] = reads();
    act(() => socket().emit(feedRunFrame([{ feed: "hagezi-tif", run: 60 }])));
    await waitFor(() => expect(reads()).toEqual([s + 1, h + 1]), T);
  });

  it("an open feed's check history reads again on an event listing only another feed's run", async () => {
    const calls = providerFeed();
    const { queryClient } = renderApp("/feeds/hagezi-pro?tab=checks");
    await screen.findByRole("table", { name: "Feed checks" }, T);
    act(() => socket().open());
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    const n = gets(calls, "/feeds/hagezi-pro/checks").length;
    act(() => socket().emit(feedRunFrame([{ feed: "hagezi-tif", run: 60 }])));
    await waitFor(() => expect(gets(calls, "/feeds/hagezi-pro/checks").length).toBe(n + 1), T);
    await pause(200);
    expect(gets(calls, "/feeds/hagezi-pro/checks").length).toBe(n + 1);
  });
});

describe("U1: a view that polls only while the event socket is down reads once more when it first opens (Codex UD1)", () => {
  /** Opens the socket once the page's reads have landed, and counts each path's reads from then. */
  async function openAfterReads(calls: Call[], queryClient: QueryClient, paths: string[]) {
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    const before = paths.map((p) => gets(calls, p).length);
    act(() => socket().open());
    await pause(300);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    return paths.map((p, i) => gets(calls, p).length - before[i]);
  }

  it("the DNSSEC queue and results: one more read each, then none (events keep them fresh)", async () => {
    const { calls } = mockApi();
    const { queryClient } = renderApp("/dnssec");
    await screen.findByRole("table", { name: "DNSSEC queue" }, T);
    await waitFor(() => expect(gets(calls, "/dnssec/results").length).toBeGreaterThan(0), T);
    expect(await openAfterReads(calls, queryClient, ["/dnssec/queue", "/dnssec/results"])).toEqual([1, 1]);
    const reads = [gets(calls, "/dnssec/queue").length, gets(calls, "/dnssec/results").length];
    await pause(300);
    expect([gets(calls, "/dnssec/queue").length, gets(calls, "/dnssec/results").length]).toEqual(reads);
  });

  it("the queue's first read still out when the socket opens: it lands, then one more read follows", async () => {
    let release: () => void = () => {};
    const held = new Promise<void>((r) => (release = r));
    const { calls } = mockApi([
      {
        method: "GET",
        path: "/dnssec/queue",
        body: async () => {
          if (gets(calls, "/dnssec/queue").length === 1) await held;
          return { depth: 0, items: [], crosscheck_depth: 0, crosscheck: [] };
        },
      },
    ]);
    const { queryClient } = renderApp("/dnssec");
    await waitFor(() => expect(gets(calls, "/dnssec/queue").length).toBe(1), T);
    act(() => socket().open());
    await pause(200);
    expect(gets(calls, "/dnssec/queue").length).toBe(1);
    release();
    await waitFor(() => expect(gets(calls, "/dnssec/queue").length).toBe(2), T);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    await pause(200);
    expect(gets(calls, "/dnssec/queue").length).toBe(2);
  });

  it("the temporary allows: one more read", async () => {
    const { calls } = mockApi();
    const { queryClient } = renderApp("/temporary-allows");
    await waitFor(() => expect(gets(calls, "/temp-allows").length).toBeGreaterThan(0), T);
    const lists = new Set(gets(calls, "/temp-allows").map((c) => c.query.toString())).size;
    expect(await openAfterReads(calls, queryClient, ["/temp-allows"])).toEqual([lists]);
  });

  it("a bundle's build status (polled while a build asked for runs and the socket is down): one more read", async () => {
    const { calls } = mockApi();
    const { queryClient } = renderApp("/bundles/block-common");
    await waitFor(() => expect(gets(calls, "/bundles/block-common/status").length).toBeGreaterThan(0), T);
    expect(await openAfterReads(calls, queryClient, ["/bundles/block-common/status"])).toEqual([1]);
  });

  it("views that never poll read once more too (polish U1, Opus FO5-5); a reconnect still reads everything", async () => {
    const { calls } = mockApi();
    const { queryClient } = renderApp("/alerts");
    await screen.findByRole("heading", { name: "Alerts" }, T);
    await waitFor(() => expect(gets(calls, "/alerts").length).toBeGreaterThan(0), T);
    // The alert list and the open-alerts badge, one read each; core's identity, for its version (U5).
    expect(await openAfterReads(calls, queryClient, ["/alerts", "/identity"])).toEqual([2, 1]);
    const before = gets(calls, "/alerts").length;
    await reconnect();
    await waitFor(() => expect(gets(calls, "/alerts").length).toBeGreaterThan(before), T);
  });
});

describe("U5: a banner when core's version isn't the one the page loaded with (Opus P2 on core)", () => {
  const BANNER = /^Picket was updated \(0\.1\.0 → 0\.2\.0\)\. Reload to use the new version\.$/;
  /** The app with core's identity answering `version()`. */
  function withVersion(version: () => string) {
    const { calls, fixtures } = mockApi([{ method: "GET", path: "/identity", body: () => ({ ...(fixtures["/identity"] as Rec), version: version() }) }]);
    return calls;
  }

  it("shows it on a reconnect to an upgraded core, with Reload; never reloads by itself, and stays", async () => {
    const reload = vi.spyOn(page, "reload").mockImplementation(() => {});
    try {
      const user = userEvent.setup();
      let version = "0.1.0";
      const calls = withVersion(() => version);
      const { queryClient } = renderApp("/");
      await screen.findByText("core 0.1.0", undefined, T);
      act(() => socket().open());
      await waitFor(() => expect(gets(calls, "/identity").length).toBe(2), T);
      await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
      expect(screen.queryByText(BANNER)).toBeNull();
      // Core restarts upgraded: the socket closes and reconnects; the page reads the identity again.
      version = "0.2.0";
      await reconnect();
      const banner = (await screen.findByText(BANNER, undefined, T)).closest("[role=alert]") as HTMLElement;
      expect(banner).not.toBeNull();
      expect(reload).not.toHaveBeenCalled();
      // It stays: more events, another reconnect.
      act(() => socket().emit(feedRunFrame([{ feed: "manual-block", run: 70 }])));
      await reconnect();
      await pause(300);
      expect(screen.getByText(BANNER)).toBeInTheDocument();
      expect(reload).not.toHaveBeenCalled();
      await user.click(screen.getByRole("button", { name: "Reload" }));
      expect(reload).toHaveBeenCalledTimes(1);
    } finally {
      reload.mockRestore();
    }
  });

  it("shows it on the first open when core changed after the page loaded", async () => {
    let version = "0.1.0";
    withVersion(() => version);
    renderApp("/");
    await screen.findByText("core 0.1.0", undefined, T);
    version = "0.2.0";
    act(() => socket().open());
    expect(await screen.findByText(BANNER, undefined, T)).toBeInTheDocument();
  });

  it("no banner after a reconnect to the same version", async () => {
    const calls = withVersion(() => "0.1.0");
    const { queryClient } = renderApp("/");
    await screen.findByText("core 0.1.0", undefined, T);
    act(() => socket().open());
    const n = gets(calls, "/identity").length;
    await reconnect();
    await waitFor(() => expect(gets(calls, "/identity").length).toBeGreaterThan(n), T);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    expect(screen.queryByText(/Picket was updated/)).toBeNull();
    expect(screen.queryByRole("button", { name: "Reload" })).toBeNull();
  });
});

describe("U3: a restore resets what the manual editor knows of its file's saves (Opus UE2)", () => {
  /** An export's save time: older than every save the page saw (core keeps a restored file's own). */
  const EXPORTED_AT = "2026-11-20T08:00:00.000000Z";
  const RESTORED = "||restored.example^\n";
  const editorView = () => EditorView.findFromDOM(screen.getByTestId("code-editor").querySelector(".cm-editor") as HTMLElement)!;
  const editorText = () => editorView().state.doc.toString();
  const typeAtEnd = (text: string) => act(() => editorView().dispatch({ changes: { from: editorView().state.doc.length, insert: text } }));
  /** Core's `restore` event (RestoreEvent). */
  const restoreEvent = (generation: number) => ({ type: "restore", data: { at: "2026-11-23T12:00:00.000000Z", generation } });
  const RESTORE_TOAST = "A restore replaced the file: reloaded.";

  /**
   * The feed's page with its editor open on the socket, after another writer's save the editor took
   * from its run's event (so the page knows a save later than the export's). `late()`: another
   * writer's save whose run is stored just before the restore, its event not sent yet.
   */
  async function editorAfterSaves() {
    const core = manualCore();
    const { calls } = mockApi(core.routes);
    const rendered = renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    act(() => socket().open());
    await pause(300);
    const run = core.finishRun(core.append("||elsewhere.example^"));
    act(() => socket().emit(feedRunFrame([core.item(run)])));
    await waitFor(() => expect(editorText()).toContain("||elsewhere.example^"), T);
    await waitFor(() => expect(core.st.fileReads).toBe(2), T);
    const late = () => core.item(core.finishRun(core.append("||late.example^")));
    return { core, calls, late, ...rendered };
  }
  /** After the restore: the editor's next save is based on the restored file (no 409), and later runs reads download nothing. */
  async function savesOnRestored(core: ReturnType<typeof manualCore>, calls: Call[], reads: number) {
    const user = userEvent.setup();
    typeAtEnd("||mine.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(mutations(calls).filter((c) => c.method === "PUT")).toHaveLength(1), T);
    expect(mutations(calls)[0].body).toEqual({ content: `${RESTORED}||mine.example^\n`, base_version: expect.any(String) });
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    expect(screen.queryByText("The file changed since you opened it")).toBeNull();
    act(() => socket().emit(truncatedRunFrame()));
    await pause(500);
    expect(core.st.fileReads).toBe(reads);
  }

  it("another tab's restore of an older export: the open clean editor reads the file once and takes it", async () => {
    const { core, calls } = await editorAfterSaves();
    core.restore(RESTORED, EXPORTED_AT);
    const info = vi.spyOn(toast, "info");
    act(() => socket().emit(restoreEvent(1)));
    await waitFor(() => expect(editorText()).toBe(RESTORED), T);
    expect(info.mock.calls.filter(([m]) => m === RESTORE_TOAST)).toHaveLength(1);
    info.mockRestore();
    await pause(300);
    expect(core.st.fileReads).toBe(3);
    await savesOnRestored(core, calls, 3);
  });

  it("a save stored just before the restore, its event sent ahead of the restore's (core 4e4f53d): one read each, then none", async () => {
    const { core, calls, late } = await editorAfterSaves();
    const item = late();
    core.restore(RESTORED, EXPORTED_AT);
    // The save is another writer's, so the editor reads the file; the restore's own event then
    // sends that read again (fix-5d5 R3: a read out at a restore is the replaced file's), and the
    // reload takes the file it gets as the restore's.
    const info = vi.spyOn(toast, "info");
    act(() => socket().emit(feedRunFrame([item])));
    act(() => socket().emit(restoreEvent(1)));
    await waitFor(() => expect(editorText()).toBe(RESTORED), T);
    await pause(300);
    expect(core.st.fileReads).toBe(4);
    expect(info.mock.calls.map(([m]) => m)).toEqual(["A restore replaced the file: reloaded."]);
    info.mockRestore();
    await savesOnRestored(core, calls, 4);
  });

  it("the restoring tab, its answer before the events sent ahead of the restore's own: takes no save from them, one download", async () => {
    const { core, calls, queryClient, late } = await editorAfterSaves();
    const item = late();
    core.restore(RESTORED, EXPORTED_AT);
    // The restore's answer (settings.tsx; sent on this open socket), then the socket's events from
    // before it, then its own.
    act(() => resyncForRestore(queryClient, 1, restoreSent()));
    await waitFor(() => expect(editorText()).toBe(RESTORED), T);
    act(() => socket().emit(feedRunFrame([item])));
    await pause(300);
    act(() => socket().emit(restoreEvent(1)));
    await pause(300);
    expect(editorText()).toBe(RESTORED);
    expect(core.st.fileReads).toBe(3);
    await savesOnRestored(core, calls, 3);
    // Events after the restore's own are placed again: its save's run ends the wait on its event,
    // before the poll's next read (2 s after the save).
    const mine = core.finishRun();
    act(() => socket().emit(feedRunFrame([core.item(mine)])));
    expect(await screen.findByText(`Run ${mine}`, undefined, { timeout: 800 })).toBeInTheDocument();
  });

  it("a restore while a reload is out (it read the file before the restore): the file is read again after it", async () => {
    const core = manualCore();
    let hold: Promise<void> | null = null;
    const file = core.routes.find((r) => r.method === "GET" && r.path === "/feeds/manual-block/file")!;
    // The answer is the file as the read finds it; it arrives when `hold` lets it.
    const { calls } = mockApi([
      {
        method: "GET",
        path: "/feeds/manual-block/file",
        body: async (c: Call) => {
          const answer = (file.body as (c: Call) => unknown)(c);
          if (hold) await hold;
          return answer;
        },
      },
      ...core.routes,
    ]);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    act(() => socket().open());
    await pause(300);
    let release: () => void = () => {};
    hold = new Promise<void>((r) => (release = r));
    const run = core.finishRun(core.append("||elsewhere.example^"));
    act(() => socket().emit(feedRunFrame([core.item(run)])));
    await waitFor(() => expect(core.st.fileReads).toBe(2), T);
    core.restore(RESTORED, EXPORTED_AT);
    act(() => socket().emit(restoreEvent(1)));
    await pause(200);
    hold = null;
    release();
    await waitFor(() => expect(editorText()).toBe(RESTORED), T);
    await pause(300);
    expect(core.st.fileReads).toBe(3);
    await savesOnRestored(core, calls, 3);
  });

  it("a dirty editor keeps its text and says the file changed; Reload takes the restored file", async () => {
    const user = userEvent.setup();
    const { core } = await editorAfterSaves();
    typeAtEnd("||draft.example^\n");
    core.restore(RESTORED, EXPORTED_AT);
    act(() => socket().emit(restoreEvent(1)));
    expect(await screen.findByText("The file changed elsewhere", undefined, T)).toBeInTheDocument();
    expect(editorText()).toContain("||draft.example^");
    await user.click(screen.getByRole("button", { name: /Reload the file/ }));
    await waitFor(() => expect(editorText()).toBe(RESTORED), T);
  });

  it("an editor closed during the restore (another tab of the page) opens on the restored file, read once", async () => {
    const user = userEvent.setup();
    const { core, calls } = await editorAfterSaves();
    await user.click(screen.getByRole("tab", { name: "Runs" }));
    await waitFor(() => expect(screen.queryByTestId("code-editor")).toBeNull(), T);
    core.restore(RESTORED, EXPORTED_AT);
    act(() => socket().emit(restoreEvent(1)));
    await pause(300);
    await user.click(screen.getByRole("tab", { name: "File" }));
    await screen.findByTestId("code-editor", undefined, T);
    await waitFor(() => expect(editorText()).toBe(RESTORED), T);
    await pause(300);
    expect(editorText()).toBe(RESTORED);
    expect(core.st.fileReads).toBe(3);
    await savesOnRestored(core, calls, 3);
  });
});

describe("U6: core 4e4f53d's document and events", () => {
  it("captured records match its LogDetail, each lookup with every field and a detail that is an object or null", () => {
    const records = Object.keys(W5).filter((k) => k.startsWith("/logs/{seq "));
    expect(records.length).toBeGreaterThan(3);
    for (const k of records) expect(checkSchema({ $ref: "#/components/schemas/LogDetail" }, W5[k], k)).toEqual([]);
    const lookup = (recordDetail(18).lookups as Rec[])[0];
    expect(checkSchema({ $ref: "#/components/schemas/LookupView" }, { ...lookup, detail: "text" })).toEqual([expect.stringMatching(/detail: is string/)]);
    const { ms: _ms, ...noMs } = lookup;
    expect(checkSchema({ $ref: "#/components/schemas/LookupView" }, noMs)).toEqual([expect.stringMatching(/\.ms: required/)]);
  });

  it("shows a lookup's score and time of 0, and no detail for null", async () => {
    const rec = recordDetail(9);
    const lookups = rec.lookups as Rec[];
    mockApi([{ method: "GET", path: /^\/logs\/[^/]+$/, body: { ...rec, lookups: [{ ...lookups[0], provider: "q0", score: 0, ms: 0, detail: null }] } }]);
    renderApp("/query-log");
    const table = await screen.findByRole("table", { name: "Query log" }, T);
    act(() => (within(table).getAllByText("lookup.example")[0] as HTMLElement).click());
    const sheet = await screen.findByRole("dialog", undefined, T);
    expect(await within(sheet).findByText("q0", undefined, T)).toBeInTheDocument();
    expect(within(sheet).getByText("score 0")).toBeInTheDocument();
    expect(within(sheet).getByText("0 ms")).toBeInTheDocument();
    expect(within(sheet).queryByText("Detail:")).toBeNull();
  });

  it("reads an open alert's evidence again when an alert event lists it for new evidence alone (same state and count)", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const a = W5["/alerts/{paged}"] as { alert: AlertLike };
      const id = a.alert.id;
      const { calls } = mockApi([
        { method: "GET", path: `/alerts/${id}`, body: a },
        { method: "GET", path: `/alerts/${id}/evidence`, body: W5["/alerts/{paged}/evidence"] },
      ]);
      renderApp(`/alerts/${id}`);
      await screen.findByTestId("evidence-copies", undefined, T);
      act(() => socket().open());
      await act(() => vi.advanceTimersByTimeAsync(EVIDENCE_REFRESH_MS + 1000));
      const n = gets(calls, `/alerts/${id}/evidence`).length;
      // An evidence backfill (core 4e4f53d K2): the alert listed as it is.
      act(() => socket().emit(alertFrame([{ ...a.alert }])));
      await waitFor(() => expect(gets(calls, `/alerts/${id}/evidence`).length).toBe(n + 1), T);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("U4: the frames tests emit are ones core sends (Opus UE3)", () => {
  const alerts = (n: number, from = 1) => Array.from({ length: n }, (_, i) => alertItem({ id: from + i }));
  const runs = (n: number) => Array.from({ length: n }, (_, i) => runItem({ feed: `f${i}`, run: i + 1 }));

  it("a truncated list lists 64, with more counted; a whole one lists every change, at least one", () => {
    for (const f of [truncatedAlertFrame([{ id: 1 }]), truncatedRunFrame([{ feed: "f", run: 1 }]), capturedTruncated("raised"), alertFrame([{ id: 1 }]), feedRunFrame([{ feed: "f", run: 1 }])]) expect(eventViolations(f)).toEqual([]);
    expect(truncatedRunFrame().data.runs).toHaveLength(MAX_LISTED);
    const bad: [string, unknown][] = [
      ["two alerts in a truncated list", { type: "alert", data: { alerts: alerts(2), alerts_truncated: true, changes: 3 } }],
      ["no runs in a truncated list", { type: "feed_run", data: { runs: [], runs_truncated: true, stored: 1 } }],
      ["64 runs truncated, counting 64", { type: "feed_run", data: { runs: runs(64), runs_truncated: true, stored: 64 } }],
      ["65 alerts listed", { type: "alert", data: { alerts: alerts(65), alerts_truncated: false, changes: 65 } }],
      ["an empty whole list", { type: "alert", data: { alerts: [], alerts_truncated: false, changes: 0 } }],
      ["a run listed but not counted", { type: "feed_run", data: { runs: runs(2), runs_truncated: false, stored: 1 } }],
      ["fewer changes than alerts", { type: "alert", data: { alerts: alerts(2), alerts_truncated: false, changes: 1 } }],
      ["one alert twice", { type: "alert", data: { alerts: [...alerts(1), ...alerts(1)], alerts_truncated: false, changes: 2 } }],
    ];
    for (const [what, f] of bad) expect(eventViolations(f), what).not.toEqual([]);
    // An alert changed twice is listed once, both changes counted.
    expect(eventViolations({ type: "alert", data: { alerts: alerts(1), alerts_truncated: false, changes: 2 } })).toEqual([]);
    expect(() => alertFrame([{ id: 1 }], true)).toThrow(/exactly 64/);
    expect(() => feedRunFrame([], true)).toThrow(/exactly 64/);
  });

  it("a job event carries its run and dropped; a start and its end the same run", () => {
    const start = jobFrame("feed_ingest", "f1", "start");
    const end = jobFrame("feed_ingest", "f1", "end", { dropped: 2 });
    for (const f of [start, end]) expect(eventViolations(f)).toEqual([]);
    expect(end.data.run).toBe(start.data.run);
    expect([start.data.coalesced, end.data.coalesced, end.data.dropped]).toEqual([0, 0, 2]);
    // An end whose start wasn't reported stands for it.
    const alone = jobFrame("feed_ingest", "f2", "end");
    expect([alone.data.coalesced, alone.data.run === start.data.run]).toEqual([1, false]);
    const { run: _r, dropped: _d, ...old } = start.data;
    expect(eventViolations({ type: "job", data: old })).toEqual([expect.stringMatching(/matches no variant/)]);
  });
});

describe("U3: the tab that restored waits for the restore's own event before placing runs again", () => {
  /** Settings → Export and restore, a restore of the captured export answered with `generation`. */
  async function restoreFromSettings(open: boolean, generation = 1) {
    const user = userEvent.setup();
    mockApi([{ method: "PUT", path: "/config/export", body: () => ({ restored: true, generation, missing_secrets: [], warnings: [] }) }]);
    const n = sockets().length;
    const { queryClient } = renderApp("/settings?tab=export");
    const input = await screen.findByLabelText("File", undefined, T);
    await waitFor(() => expect(sockets().length).toBe(n + 1), T);
    if (open) act(() => socket().open());
    const doc = new File([JSON.stringify(W5["GET /config/export"])], "picket-config.json", { type: "application/json" });
    await user.upload(input, doc);
    await user.click(await screen.findByRole("button", { name: /^Restore$/ }, T));
    await user.click(await screen.findByRole("button", { name: "Restore" }));
    await screen.findByTestId("restore-result", undefined, T);
    return queryClient;
  }

  it("on an open socket: until the restore event of its generation comes (an earlier restore's doesn't end it)", async () => {
    const qc = await restoreFromSettings(true, 2);
    expect(beforeRestoreEvent(qc)).toBe(true);
    act(() => socket().emit({ type: "restore", data: { at: "2026-11-23T12:00:00.000000Z", generation: 1 } }));
    expect(beforeRestoreEvent(qc)).toBe(true);
    act(() => socket().emit({ type: "restore", data: { at: "2026-11-23T12:00:00.000000Z", generation: 2 } }));
    expect(beforeRestoreEvent(qc)).toBe(false);
  });

  it("not while the socket is down (no events to wait for)", async () => {
    expect(beforeRestoreEvent(await restoreFromSettings(false))).toBe(false);
  });

  it("not once the socket closes (its reconnect reads everything)", async () => {
    const qc = await restoreFromSettings(true);
    expect(beforeRestoreEvent(qc)).toBe(true);
    act(() => socket().onclose?.());
    expect(beforeRestoreEvent(qc)).toBe(false);
  });
});
