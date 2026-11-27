// The UI on core a3eb6d5's API (dev/briefs/ui-cf4.md), against answers captured from a real core at
// a3eb6d5 (test/core-w5.ts, scripts/capture-w5.mjs): C2 the coalesced `alert` event (the alert
// views read once per event; an alert's evidence when the event lists it, not deleted, or lists
// only some); C3 the coalesced `feed_run` event (each run placed for its feed: a closed editor's
// cached file, the open editor's save result; every feed when it lists only some; the provider's
// Check now progress from job events, its end from the status a feed_run reads again); C4 the DNSSEC queue polled only while the socket is down (ui-cf2.test.tsx P3);
// C5 a lookup's `detail` as a JSON object, shown as text.
import { describe, expect, it, vi } from "vitest";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryObserver } from "@tanstack/react-query";
import { EditorView } from "@codemirror/view";
import { mockApi, type Call } from "@/test/mock-api";
import { renderApp } from "@/test/render";
import { manualCore } from "@/test/manual-core";
import { W5, capturedEvent, capturedTruncated, recordDetail } from "@/test/core-w5";
import { alertFrame, feedRunFrame, jobFrame, truncatedAlertFrame, truncatedRunFrame, type AlertLike } from "@/test/events";
import { alertsOf, applyEvent, feedRunsOf } from "@/api/events";
import { qk } from "@/api/queries";
import { EVIDENCE_REFRESH_MS } from "./alerts";

const T = { timeout: 8000 };
type Rec = Record<string, unknown>;
const gets = (calls: Call[], path: string) => calls.filter((c) => c.method === "GET" && c.path === path);
const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

interface FakeSocket {
  open(): void;
  emit(data: unknown): void;
}
const socket = () => (globalThis.WebSocket as unknown as { instances: FakeSocket[] }).instances.at(-1)!;
/** The keys of `keys` a query client marks stale. */
const staleOf = (qc: QueryClient, keys: (readonly unknown[])[]) => keys.filter((k) => qc.getQueryCache().find({ queryKey: k, exact: true })?.state.isInvalidated).map((k) => k.join("/"));

const RAISED = capturedTruncated("raised");
const DELETED = capturedTruncated("deleted");

describe("C2: the coalesced alert event (core a3eb6d5)", () => {
  it("captured: a burst of 100 alerts raised, then bulk-deleted, lists 64 in each event and says the rest went unlisted", () => {
    expect(W5["DELETE /alerts (burst)"]).toEqual({ deleted: 100 });
    for (const f of [RAISED, DELETED]) {
      expect(f.data.alerts).toHaveLength(64);
      expect(f.data.changes).toBe(100);
      expect(new Set(f.data.alerts.map((a) => a.id)).size).toBe(64);
    }
    expect(RAISED.data.alerts.every((a) => !a.deleted && a.state === "open" && a.kind === "category_blocked")).toBe(true);
    expect(DELETED.data.alerts.every((a) => a.deleted && a.state === null)).toBe(true);
    // Another of the captured events: some alerts, all listed.
    const first = capturedEvent("alert");
    expect(first.data.alerts_truncated).toBe(false);
    expect(first.data.alerts.length).toBe(first.data.changes);
  });

  it("reads each alert list shown once per event, however many alerts it lists", async () => {
    const { calls } = mockApi();
    const { queryClient } = renderApp("/alerts");
    await screen.findByRole("heading", { name: "Alerts" }, T);
    act(() => socket().open());
    await waitFor(() => expect(gets(calls, "/alerts").length).toBeGreaterThan(0), T);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    // The lists the page shows (each its own read of GET alerts).
    const lists = new Set(gets(calls, "/alerts").map((c) => c.query.toString())).size;
    const reads = async (frame: unknown) => {
      const n = gets(calls, "/alerts").length;
      act(() => socket().emit(frame));
      await waitFor(() => expect(gets(calls, "/alerts").length).toBeGreaterThan(n), T);
      await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
      await pause(200);
      return gets(calls, "/alerts").length - n;
    };
    expect(await reads(RAISED)).toBe(lists);
    expect(await reads(alertFrame([{ id: 1 }]))).toBe(lists);
  });

  it("marks the alert views and the lists alerts change stale, never the DNSSEC queue (its changes send dnssec_queued)", () => {
    const keys = [["alerts", "list"], qk.review, qk.providerStatus, qk.feedStatus, qk.config("feeds"), qk.config("feed-providers"), qk.dnssecQueue];
    for (const frame of [alertFrame([{ id: 1, kind: "dnssec_bogus" }, { id: 2, kind: "upstream_disagrees" }]), RAISED, DELETED, { type: "alert", data: null }]) {
      const qc = new QueryClient();
      for (const k of keys) qc.setQueryData(k, {});
      applyEvent(qc, frame);
      expect(staleOf(qc, keys)).toEqual(keys.slice(0, -1).map((k) => k.join("/")));
    }
  });

  it("reads its alerts defensively: an event whose list can't be read counts as truncated (unit)", () => {
    expect(alertsOf(RAISED.data)).toEqual({ alerts: RAISED.data.alerts, truncated: true });
    expect(alertsOf(alertFrame([{ id: 3 }]).data)).toEqual({ alerts: [expect.objectContaining({ id: 3 })], truncated: false });
    expect(alertsOf({ alerts: [{ id: "3" }, null, { id: 4.5 }, { id: 5, kind: "x" }], alerts_truncated: false })).toEqual({ alerts: [{ id: 5, kind: "x" }], truncated: false });
    expect(alertsOf({ alerts: "no", alerts_truncated: false }).truncated).toBe(true);
    expect(alertsOf({ alerts: [] }).truncated).toBe(true);
    expect(alertsOf(null)).toEqual({ alerts: [], truncated: true });
  });

  it("reads an alert's evidence when the event lists it, not deleted, or lists only some; not for other alerts nor once it is deleted", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const a = W5["/alerts/{paged}"] as { alert: AlertLike };
      const id = a.alert.id;
      expect(RAISED.data.alerts.some((x) => x.id === id)).toBe(false);
      const { calls } = mockApi([
        { method: "GET", path: `/alerts/${id}`, body: a },
        { method: "GET", path: `/alerts/${id}/evidence`, body: W5["/alerts/{paged}/evidence"] },
      ]);
      renderApp(`/alerts/${id}`);
      await screen.findByTestId("evidence-copies", undefined, T);
      act(() => socket().open());
      const ev = () => gets(calls, `/alerts/${id}/evidence`).length;
      const past = () => act(() => vi.advanceTimersByTimeAsync(EVIDENCE_REFRESH_MS + 1000));
      await past();
      expect(ev()).toBe(1);
      // Other alerts, all listed: nothing.
      act(() => socket().emit(alertFrame([{ id: id + 1000 }, { id: id + 1001, deleted: true }])));
      await past();
      expect(ev()).toBe(1);
      // Listed among others: read.
      act(() => socket().emit(alertFrame([{ id: id + 1000 }, { ...a.alert, count: 9 }, { id: id + 1002 }])));
      await waitFor(() => expect(ev()).toBe(2), T);
      await past();
      // Not listed, but the event lists only some (the captured burst): read.
      act(() => socket().emit(RAISED));
      await waitFor(() => expect(ev()).toBe(3), T);
      await past();
      // Listed as deleted, even in an event that lists only some: gone with its evidence.
      act(() => socket().emit(truncatedAlertFrame([{ id: id + 1000 }, { id, kind: a.alert.kind, count: 9, deleted: true }])));
      await past();
      expect(ev()).toBe(3);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("C3: the coalesced feed_run event (core a3eb6d5)", () => {
  const T5 = "2026-11-23T10:00:05.000000Z";
  const T1 = "2026-11-23T10:00:01.000000Z";
  const T6 = "2026-11-23T10:00:06.000000Z";
  const file = (saved_at: string) => ({ version: "v", saved_at, content: "x", size: 1 });
  const cached = (qc: QueryClient, feeds: string[]) => {
    for (const f of feeds) qc.setQueryData(qk.manualFile(f), file(T5));
  };
  const staleFiles = (qc: QueryClient, feeds: string[]) => feeds.filter((f) => qc.getQueryState(qk.manualFile(f))?.isInvalidated);

  it("captured: each event lists every run stored since the previous one, several feeds' in one", () => {
    for (const f of W5.events.feed_run as ReturnType<typeof capturedEvent<"feed_run">>[]) {
      expect(f.data.runs_truncated).toBe(false);
      expect(f.data.runs).toHaveLength(f.data.stored);
    }
    expect(new Set(capturedEvent("feed_run").data.runs.map((r) => r.feed)).size).toBeGreaterThan(1);
  });

  it("checks each run against its feed's closed editor: a later save makes that file stale, its own or an earlier one doesn't", () => {
    const qc = new QueryClient();
    const feeds = ["a", "b", "c", "d"];
    cached(qc, feeds);
    applyEvent(
      qc,
      feedRunFrame([
        { feed: "a", run: 1, version: "w", saved_at: T6 },
        { feed: "b", run: 2, version: "v", saved_at: T5 },
        { feed: "c", run: 3, kind: "reingest", version: "u", saved_at: T1 },
        // Two runs of one feed: the later save counts, whichever comes first.
        { feed: "d", run: 4, version: "w", saved_at: T6 },
        { feed: "d", run: 5, version: "u", saved_at: T1 },
        // A run without a save time (another kind of feed, or not said): stale, as before.
        { feed: "e", run: 6 },
      ]),
    );
    expect(staleFiles(qc, feeds)).toEqual(["a", "d"]);
    const qc2 = new QueryClient();
    cached(qc2, ["a"]);
    applyEvent(qc2, feedRunFrame([{ feed: "a", run: 1 }]));
    expect(staleFiles(qc2, ["a"])).toEqual(["a"]);
  });

  it("marks every closed editor's file stale when the event lists only some runs (or can't be read), and an open editor's never", () => {
    for (const data of [truncatedRunFrame([{ feed: "b", run: 2, version: "v", saved_at: T5 }]).data, { runs: "no", runs_truncated: false }, { runs: [] }, null]) {
      const qc = new QueryClient();
      cached(qc, ["a", "b", "open"]);
      const stop = new QueryObserver(qc, { queryKey: qk.manualFile("open"), queryFn: () => new Promise<never>(() => {}), staleTime: Infinity }).subscribe(() => {});
      applyEvent(qc, { type: "feed_run", data });
      expect(staleFiles(qc, ["a", "b", "open"]), JSON.stringify(data)).toEqual(["a", "b"]);
      stop();
    }
  });

  it("reads an open feed's runs again for its own runs, not for other feeds'", async () => {
    const { calls, fixtures } = mockApi();
    const { queryClient } = renderApp("/feeds/manual-block?tab=runs");
    await waitFor(() => expect(gets(calls, "/feeds/manual-block/runs").length).toBeGreaterThan(0), T);
    act(() => socket().open());
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    const reads = () => gets(calls, "/feeds/manual-block/runs").length;
    const n = reads();
    const other = (fixtures["/feeds"] as { items: { id: string }[] }).items.find((f) => f.id !== "manual-block")!.id;
    act(() => socket().emit(feedRunFrame([{ feed: other, run: 90 }])));
    await pause(300);
    expect(reads()).toBe(n);
    act(() => socket().emit(feedRunFrame([{ feed: other, run: 91 }, { feed: "manual-block", run: 92 }])));
    await waitFor(() => expect(reads()).toBe(n + 1), T);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    act(() => socket().emit(truncatedRunFrame([{ feed: other, run: 93 }])));
    await waitFor(() => expect(reads()).toBe(n + 2), T);
  });

  it("reads its runs defensively (unit)", () => {
    expect(feedRunsOf({ runs: [{ feed: "a", run: 1 }, { run: 2 }, null, "x"], runs_truncated: false })).toEqual({ runs: [{ feed: "a", run: 1 }], truncated: false });
    expect(feedRunsOf({ runs: [{ feed: "a", run: 1 }] }).truncated).toBe(true);
    expect(feedRunsOf(undefined)).toEqual({ runs: [], truncated: true });
  });
});

describe("C3: the open editor takes each of its feed's runs from a coalesced event", () => {
  const runsReads = (calls: Call[]) => gets(calls, "/feeds/manual-block/runs").length;
  const editorText = () => EditorView.findFromDOM(screen.getByTestId("code-editor").querySelector(".cm-editor") as HTMLElement)!.state.doc.toString();
  async function typeAtEnd(text: string) {
    await screen.findByTestId("code-editor", undefined, T);
    const view = EditorView.findFromDOM(screen.getByTestId("code-editor").querySelector(".cm-editor") as HTMLElement)!;
    act(() => view.dispatch({ changes: { from: view.state.doc.length, insert: text } }));
  }

  it("shows its save's run from an event listing other feeds' runs too, on that event", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    const { calls } = mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await typeAtEnd("||mine.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    act(() => socket().open());
    await pause(300);
    const before = runsReads(calls);
    const mine = core.finishRun();
    act(() => socket().emit(feedRunFrame([{ feed: "manual-allow", run: 40, saved_at: core.st.savedAt, version: "x" }, core.item(mine), { feed: "hagezi-tif", run: 41 }])));
    // On its event, before the poll's next read (2 s after the save).
    expect(await screen.findByText(`Run ${mine}`, undefined, { timeout: 800 })).toBeInTheDocument();
    expect(runsReads(calls)).toBe(before + 1);
  });

  it("takes another writer's save from its run in a coalesced event without reading the runs; another feed's run of a later save changes nothing", async () => {
    const core = manualCore();
    const { calls } = mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    act(() => socket().open());
    await pause(300);
    const before = runsReads(calls);
    const v = core.append("||elsewhere.example^");
    const run = core.finishRun(v);
    const later = "2026-11-23T11:00:00.000000Z";
    act(() => socket().emit(feedRunFrame([{ feed: "manual-allow", run: 40, version: "zz", saved_at: later }])));
    await pause(300);
    expect(editorText()).not.toContain("||elsewhere.example^");
    act(() => socket().emit(feedRunFrame([{ feed: "manual-allow", run: 40, version: "zz", saved_at: later }, core.item(run)])));
    await waitFor(() => expect(editorText()).toContain("||elsewhere.example^"), T);
    expect(runsReads(calls)).toBe(before);
    expect(core.st.fileReads).toBe(2);
  });

  it("reads its runs when an event lists only some, so a save it left out is placed", async () => {
    const core = manualCore();
    const { calls } = mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    act(() => socket().open());
    await pause(300);
    const before = runsReads(calls);
    core.finishRun(core.append("||elsewhere.example^"));
    act(() => socket().emit(truncatedRunFrame([{ feed: "manual-allow", run: 40 }])));
    await waitFor(() => expect(runsReads(calls)).toBe(before + 1), T);
    await waitFor(() => expect(editorText()).toContain("||elsewhere.example^"), T);
  });

  it("finds its save's run on an event that lists only some, before the poll's next read", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await typeAtEnd("||mine.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    act(() => socket().open());
    await pause(300);
    const mine = core.finishRun();
    act(() => socket().emit(truncatedRunFrame()));
    expect(await screen.findByText(`Run ${mine}`, undefined, { timeout: 800 })).toBeInTheDocument();
  });
});

describe("C3: Check now's progress still shows each of the provider's feeds' runs, and the check's end on their feed_run event", () => {
  /**
   * The provider page after Check now, its status polls frozen (only events read it again), with
   * core's check running until `end()`. TanStack polls on setInterval, which is faked; user-event,
   * React, TanStack's other timers and the waits here run on setTimeout (`settled`; RTL's waitFor
   * would check only as the DOM changes).
   */
  async function checkStarted() {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    const user = userEvent.setup();
    let checking = true;
    const { calls, fixtures } = mockApi([
      { method: "POST", path: "/feed-providers/hagezi/check", status: 202, body: { result: "started" } },
      { method: "GET", path: "/feed-providers/hagezi/status", body: () => ({ ...(fixtures["/feed-providers/hagezi/status"] as Rec), enabled: true, checking }) },
      {
        method: "GET",
        path: "/feeds",
        body: () => ({
          items: [
            ...(fixtures["/feeds"] as { items: Rec[] }).items,
            ...["tif", "pro"].map((f) => ({ ...(fixtures["/feeds/manual-block"] as Rec), id: `hagezi-${f}`, name: `HaGeZi ${f.toUpperCase()}`, provider: "hagezi", file: `adblock/${f}.txt`, system: false })),
          ],
          next_cursor: null,
        }),
      },
    ]);
    const { queryClient } = renderApp("/feed-providers/hagezi");
    const checkNow = await screen.findByRole("button", { name: /Check now/ }, T);
    act(() => socket().open());
    await user.click(checkNow);
    const progress = await screen.findByLabelText("Check progress", undefined, T);
    /** Every read out has landed. */
    const settled = async () => {
      for (let i = 0; i < 400 && queryClient.isFetching() > 0; i++) await pause(20);
      expect(queryClient.isFetching()).toBe(0);
    };
    await settled();
    expect(within(progress).getByText("checking")).toBeInTheDocument();
    const statusReads = () => gets(calls, "/feed-providers/hagezi/status").length;
    return { progress, statusReads, end: () => void (checking = false), settled };
  }
  /** The badge of a feed's run in the progress line. */
  const runOf = (progress: HTMLElement, name: string) => within(within(progress).getByText(name).parentElement!);

  it("each feed's run from its job events (start, then end), and the check's end on the feed_run event listing their runs", async () => {
    try {
      const { progress, statusReads, end, settled } = await checkStarted();
      act(() => socket().emit(jobFrame("feed_ingest", "hagezi-tif", "start")));
      expect(runOf(progress, "HaGeZi TIF").getByText("running")).toBeInTheDocument();
      act(() => socket().emit(jobFrame("feed_ingest", "hagezi-tif", "end", { ms: 700 })));
      act(() => socket().emit(jobFrame("feed_ingest", "hagezi-pro", "start")));
      expect(runOf(progress, "HaGeZi TIF").getByText("done in 700 ms")).toBeInTheDocument();
      expect(runOf(progress, "HaGeZi PRO").getByText("running")).toBeInTheDocument();
      act(() => socket().emit(jobFrame("feed_ingest", "hagezi-pro", "end", { ms: 900 })));
      expect(runOf(progress, "HaGeZi PRO").getByText("done in 900 ms")).toBeInTheDocument();
      // Nothing reads the provider's status meanwhile (its polls are frozen; job events read only bundles').
      await settled();
      const n = statusReads();
      expect(within(progress).getByText("checking")).toBeInTheDocument();
      // The check ended (core says so only in the provider's status, sending no event of its own):
      // the runs' feed_run event, both feeds' runs in one, reads it again.
      end();
      act(() => socket().emit(feedRunFrame([{ feed: "hagezi-tif", run: 50 }, { feed: "hagezi-pro", run: 51 }])));
      expect(await within(progress).findByText("check done", undefined, T)).toBeInTheDocument();
      expect(statusReads()).toBe(n + 1);
      expect(within(progress).getAllByText(/^done in/)).toHaveLength(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it("the check's end on a feed_run event that lists only some runs, none of them the provider's", async () => {
    try {
      const { progress, statusReads, end, settled } = await checkStarted();
      act(() => socket().emit(feedRunFrame([{ feed: "manual-allow", run: 49 }])));
      await settled();
      // Still checking: the status read again says so.
      expect(within(progress).getByText("checking")).toBeInTheDocument();
      const n = statusReads();
      end();
      act(() => socket().emit(truncatedRunFrame()));
      expect(await within(progress).findByText("check done", undefined, T)).toBeInTheDocument();
      expect(statusReads()).toBe(n + 1);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("C5: a lookup's detail is a JSON object in the record view too (core a3eb6d5)", () => {
  it("captured: the record's lookup detail is the object an alert's providers[] holds", () => {
    const lookup = (recordDetail(18).lookups as Rec[])[0];
    expect(lookup.detail).toEqual({ list: "malware", server: "9.9.9.9" });
    const alert = W5["/alerts/{lookup block}"] as { alert: { details: { providers: Rec[] } } };
    expect(alert.alert.details.providers[0].detail).toEqual(lookup.detail);
  });

  it("shows it as JSON text, never as markup", async () => {
    const user = userEvent.setup();
    const rec = recordDetail(9);
    const lookups = rec.lookups as Rec[];
    const detail = { server: "9.9.9.9", note: "<img src=x onerror=alert(1)>", nested: { list: ["a\u0007b"] } };
    mockApi([{ method: "GET", path: /^\/logs\/[^/]+$/, body: { ...rec, lookups: [{ ...lookups[0], detail }, { ...lookups[0], provider: "q8", detail: null }] } }]);
    renderApp("/query-log");
    const table = await screen.findByRole("table", { name: "Query log" }, T);
    await user.click((await within(table).findAllByText("lookup.example", undefined, T))[0]);
    const sheet = await screen.findByRole("dialog", undefined, T);
    expect(await within(sheet).findByText("q8", undefined, T)).toBeInTheDocument();
    const pre = within(sheet).getByText((_, el) => el?.tagName === "PRE" && (el.textContent ?? "").includes("onerror"));
    expect(pre.textContent).toContain('"note": "<img src=x onerror=alert(1)>"');
    expect(pre.textContent).not.toContain("\u0007");
    expect(sheet.querySelector("img")).toBeNull();
    // One detail block: the lookup without a detail shows none.
    expect(within(sheet).getAllByText("Detail:")).toHaveLength(1);
  });
});
