// Review round 4 of the web UI (J1–J5): each test reproduces a final-check reviewer's finding and
// asserts the fixed behaviour, against stateful mocks of core (test/manual-core.ts, the bundle
// build below) and core's request contract (test/contract.ts).
import { describe, expect, it, vi } from "vitest";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient } from "@tanstack/react-query";
import { EditorView } from "@codemirror/view";
import { mockApi, mutations, type Route } from "@/test/mock-api";
import { manualCore } from "@/test/manual-core";
import { contractViolations } from "@/test/contract";
import { renderApp } from "@/test/render";
import { jobFrame } from "@/test/events";
import { applyEvent } from "@/api/events";
import { BlobParts, DEFAULT_DOWNLOAD_MIB, TopLevelKeys, fileJsonBody, importBody, importSizeProblem, inspectImport } from "@/lib/import-file";
import { downloadCap, qk } from "@/api/queries";
import { createLine, pageWrite, recordSave } from "./manual-line";
// The pages these tests open (routes load them lazily), loaded with the file: vitest transforms a
// page's module on its first use, which took most of a first test's 8 s step (T, J1's "Build now")
// on a loaded machine. T then bounds the page's own rendering and reads, not that.
import "./bundle-detail";
import "./feed-detail";
import "./feed-providers";
import "./feeds";

const T = { timeout: 8000 };

interface FakeSocket {
  open: () => void;
  emit: (d: unknown) => void;
  onclose: (() => void) | null;
}
const sockets = () => (globalThis.WebSocket as unknown as { instances: FakeSocket[] }).instances;
const socket = () => sockets().at(-1)!;
const openSocket = () => act(() => socket().open());
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
/** The socket drops and the app reconnects (after its 1 s backoff); `meanwhile` runs while it is down. */
async function reconnect(meanwhile: () => void) {
  const before = sockets().length;
  act(() => socket().onclose?.());
  meanwhile();
  await waitFor(() => expect(sockets().length).toBe(before + 1), { timeout: 3000 });
  openSocket();
}

/** A job event as core sends it (test/events.ts `jobFrame`: JobEvent with its `run` and `dropped`). */
const job = jobFrame;

/**
 * core's bundle build (compiler/mod.rs): `building` from the request until the build ends (a
 * running or waiting build, `busy`), then the status and time of the build that ended.
 */
function buildCore(fixtures: Record<string, unknown>, opts: { endsAtOnce?: boolean } = {}) {
  const st = { building: false, built_at: "2026-11-23T10:40:34.925464Z", status: "ok" };
  const finish = () => {
    st.building = false;
    st.built_at = "2026-11-24T09:00:00.000000Z";
  };
  const routes: Route[] = [
    {
      method: "POST",
      path: "/bundles/block-common/build",
      status: 202,
      body: () => {
        st.building = true;
        // A build that ends before the answer reaches the page.
        if (opts.endsAtOnce) finish();
        return { queued: true };
      },
    },
    { method: "GET", path: "/bundles/block-common/status", body: () => ({ ...(fixtures["/bundles/block-common/status"] as object), ...st }) },
  ];
  return { st, finish, routes };
}

const progress = () => screen.getByLabelText("Build progress");

describe("J1: a missed job end never leaves progress running (api.md §7 JobEvent)", () => {
  it("Build now: an end lost to a reconnect ends once a status read after it says no build runs", async () => {
    const user = userEvent.setup();
    const { fixtures } = mockApi();
    const b = buildCore(fixtures);
    mockApi(b.routes);
    renderApp("/bundles/block-common");
    const buildNow = await screen.findByRole("button", { name: /Build now/ }, T);
    openSocket();
    await user.click(buildNow);
    act(() => socket().emit(job("bundle_build", "block-common", "start")));
    expect(await within(await screen.findByLabelText("Build progress", undefined, T)).findByText("running", undefined, T)).toBeInTheDocument();
    // The build ends while the socket is down; its end event is never sent to this page.
    await reconnect(() => b.finish());
    expect(await within(progress()).findByText("done", undefined, T)).toBeInTheDocument();
  }, 20000);

  it("Build now: an end dropped past core's bound (the next event's `dropped`) ends the same way", async () => {
    const user = userEvent.setup();
    const { fixtures } = mockApi();
    const b = buildCore(fixtures);
    mockApi(b.routes);
    renderApp("/bundles/block-common");
    const buildNow = await screen.findByRole("button", { name: /Build now/ }, T);
    openSocket();
    await user.click(buildNow);
    act(() => socket().emit(job("bundle_build", "block-common", "start")));
    expect(await within(await screen.findByLabelText("Build progress", undefined, T)).findByText("running", undefined, T)).toBeInTheDocument();
    b.finish();
    act(() => socket().emit(job("feed_ingest", "other", "end", { dropped: 1 })));
    expect(await within(progress()).findByText("done", undefined, T)).toBeInTheDocument();
  }, 20000);

  it("Build now: a result seen while polling stays after the socket opens", async () => {
    const user = userEvent.setup();
    const { fixtures } = mockApi();
    const b = buildCore(fixtures);
    mockApi(b.routes);
    renderApp("/bundles/block-common");
    // The event socket isn't open: the page polls the status.
    await user.click(await screen.findByRole("button", { name: /Build now/ }, T));
    expect(await within(await screen.findByLabelText("Build progress", undefined, T)).findByText("queued", undefined, T)).toBeInTheDocument();
    b.finish();
    expect(await within(progress()).findByText("done", undefined, { timeout: 6000 })).toBeInTheDocument();
    openSocket();
    await sleep(300);
    expect(within(progress()).getByText("done")).toBeInTheDocument();
  }, 20000);

  it("a running report isn't ended by a status read sent before it arrived", async () => {
    const user = userEvent.setup();
    const { fixtures } = mockApi();
    const b = buildCore(fixtures);
    // Core as the routes model it (fix-95e: not the fixtures alone, which never show a build).
    const { fetchMock } = mockApi(b.routes);
    renderApp("/bundles/block-common");
    const buildNow = await screen.findByRole("button", { name: /Build now/ }, T);
    openSocket();
    await user.click(buildNow);
    await screen.findByLabelText("Build progress", undefined, T);
    await sleep(200);
    // A status read is sent, then the build starts and its report arrives, then the read's answer
    // (taken before the build ran: no build) lands. The read after it (the report's event came
    // while the first was out) is held, so the first one's answer is what shows.
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let answer: Promise<Response> | null = null;
    let next: (() => void) | null = null;
    vi.stubGlobal("fetch", async (req: Request) => {
      if (req.method === "GET" && new URL(req.url).pathname.endsWith("/bundles/block-common/status")) {
        if (!answer) {
          b.st.building = false;
          answer = fetchMock(req);
          await gate;
          return answer;
        }
        const later = fetchMock(req);
        await new Promise<void>((r) => (next = r));
        return later;
      }
      return fetchMock(req);
    });
    act(() => socket().emit(job("feed_ingest", "other", "end", { dropped: 1 })));
    await waitFor(() => expect(answer).not.toBeNull(), T);
    b.st.building = true;
    act(() => socket().emit(job("bundle_build", "block-common", "start")));
    await act(async () => release());
    await waitFor(() => expect(next).not.toBeNull(), T);
    await sleep(100);
    expect(within(progress()).getByText("running")).toBeInTheDocument();
    vi.stubGlobal("fetch", fetchMock);
    await act(async () => next!());
    await sleep(100);
    expect(within(progress()).getByText("running")).toBeInTheDocument();
  }, 20000);

  it("a `job` event with dropped > 0 re-reads the bundle, feed and provider statuses and runs", () => {
    const qc = new QueryClient();
    const keys = [qk.bundle("other", "status"), qk.bundleStatus, qk.feedStatus, qk.feed("f", "status"), qk.feed("f", "runs"), qk.providerStatus, qk.provider("p", "status")];
    for (const k of keys) qc.setQueryData(k, { x: 1 });
    // Not what no job changes: a bundle's versions, an edge's status.
    const others = [qk.bundle("other", "versions"), qk.edgeStatus("e1")];
    for (const k of others) qc.setQueryData(k, { x: 1 });
    applyEvent(qc, job("feed_ingest", "x", "end"));
    expect(keys.some((k) => qc.getQueryState(k)?.isInvalidated)).toBe(false);
    applyEvent(qc, job("feed_ingest", "x", "end", { dropped: 1 }));
    for (const k of keys) expect(qc.getQueryState(k)?.isInvalidated, JSON.stringify(k)).toBe(true);
    for (const k of others) expect(qc.getQueryState(k)?.isInvalidated, JSON.stringify(k)).toBe(false);
  });

  it("Check now: a feed's run whose end was missed ends once the feed's status says it isn't busy", async () => {
    const user = userEvent.setup();
    let tifBusy = false;
    const { fixtures } = mockApi();
    const statuses = fixtures["/feed-status"] as { items: object[] };
    mockApi([
      { method: "POST", path: "/feed-providers/hagezi/check", status: 202, body: { result: "started" } },
      { method: "GET", path: "/feed-providers/hagezi/status", body: () => ({ ...(fixtures["/feed-providers/hagezi/status"] as object), checking: false }) },
      {
        method: "GET",
        path: "/feeds",
        body: () => ({
          items: [
            ...(fixtures["/feeds"] as { items: object[] }).items,
            { ...(fixtures["/feeds/manual-block"] as object), id: "hagezi-tif", name: "HaGeZi TIF", provider: "hagezi", file: "adblock/tif.txt", system: false },
            { ...(fixtures["/feeds/manual-block"] as object), id: "hagezi-new", name: "HaGeZi new", provider: "hagezi", file: "adblock/new.txt", system: false },
          ],
          next_cursor: null,
        }),
      },
      {
        method: "GET",
        path: "/feed-status",
        body: () => ({ items: [...statuses.items, { ...(statuses.items[3] as object), feed: "hagezi-tif", name: "HaGeZi TIF", provider: "hagezi", manual: false, busy: tifBusy }], next_cursor: null }),
      },
    ]);
    renderApp("/feed-providers/hagezi");
    const checkNow = await screen.findByRole("button", { name: /Check now/ }, T);
    openSocket();
    await user.click(checkNow);
    const check = await screen.findByLabelText("Check progress", undefined, T);
    tifBusy = true;
    act(() => socket().emit(job("feed_ingest", "hagezi-tif", "start")));
    // A feed the status list doesn't hold yet (just discovered): nothing says its run ended.
    act(() => socket().emit(job("feed_ingest", "hagezi-new", "start")));
    const run = (name: string) => within(within(screen.getByLabelText("Check progress")).getByText(name).parentElement!);
    expect(await within(check).findByText("HaGeZi new", undefined, T)).toBeInTheDocument();
    expect(run("HaGeZi TIF").getByText("running")).toBeInTheDocument();
    await reconnect(() => (tifBusy = false));
    await waitFor(() => expect(run("HaGeZi TIF").queryByText("running")).toBeNull(), T);
    expect(run("HaGeZi TIF").getByText("ended")).toBeInTheDocument();
    expect(run("HaGeZi new").getByText("running")).toBeInTheDocument();
    // An end that came stays as reported (its outcome and time), whatever a later read says.
    act(() => socket().emit(job("feed_ingest", "hagezi-tif", "end", { ms: 800 })));
    expect(await run("HaGeZi TIF").findByText("done in 800 ms", undefined, T)).toBeInTheDocument();
    act(() => socket().emit(job("feed_ingest", "other", "end", { dropped: 1 })));
    await sleep(500);
    expect(run("HaGeZi TIF").getByText("done in 800 ms")).toBeInTheDocument();
  }, 20000);

  it("the editor's 'running now' note ends once a status read after the run's start says the feed isn't busy", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    const view = EditorView.findFromDOM(screen.getByTestId("code-editor").querySelector(".cm-editor") as HTMLElement)!;
    act(() => view.dispatch({ changes: { from: view.state.doc.length, insert: "||one.example^\n" } }));
    openSocket();
    const reads = core.st.statusReads;
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    // Past the backoff's second poll: the next is 4 s away, so only what's tested reads the status.
    await waitFor(() => expect(core.st.statusReads).toBe(reads + 2), { timeout: 4000 });
    // A re-ingest of the feed runs (the save's run waits behind it).
    act(() => socket().emit(job("feed_reingest", "manual-block", "start")));
    expect(await screen.findByText(/A run of this feed is running now/, undefined, T)).toBeInTheDocument();
    // A reconnect while it still runs: the status read after it says busy, so it shows on.
    await reconnect(() => undefined);
    await waitFor(() => expect(core.st.statusReads).toBe(reads + 3), T);
    await sleep(100);
    expect(screen.getByText(/A run of this feed is running now/)).toBeInTheDocument();
    // It ends while the socket is down (its end is never sent); core frees the feed just before
    // the save's run starts.
    await reconnect(() => (core.st.busy = false));
    await waitFor(() => expect(screen.queryByText(/A run of this feed is running now/)).toBeNull(), { timeout: 1500 });
    // The same after an end dropped past core's bound.
    core.st.busy = true;
    act(() => socket().emit(job("feed_reingest", "manual-block", "start")));
    expect(await screen.findByText(/A run of this feed is running now/, undefined, T)).toBeInTheDocument();
    core.st.busy = false;
    act(() => socket().emit(job("bundle_build", "block-common", "end", { dropped: 1 })));
    await waitFor(() => expect(screen.queryByText(/A run of this feed is running now/)).toBeNull(), { timeout: 1500 });
  }, 20000);

  it("the editor's note isn't ended by a status read sent before the run's start arrived", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    const { fetchMock } = mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    const view = EditorView.findFromDOM(screen.getByTestId("code-editor").querySelector(".cm-editor") as HTMLElement)!;
    act(() => view.dispatch({ changes: { from: view.state.doc.length, insert: "||one.example^\n" } }));
    openSocket();
    // The save's first poll reads the status as core answers it then (the feed freed for a moment),
    // but the answer lands after a run's start arrived.
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let held = false;
    vi.stubGlobal("fetch", async (req: Request) => {
      if (!held && req.method === "GET" && new URL(req.url).pathname.endsWith("/feeds/manual-block/status")) {
        held = true;
        core.st.busy = false;
        const answer = await fetchMock(req);
        core.st.busy = true;
        await gate;
        return answer;
      }
      return fetchMock(req);
    });
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(held).toBe(true), T);
    act(() => socket().emit(job("feed_ingest", "manual-block", "start")));
    expect(await screen.findByText(/A run of this feed is running now/, undefined, T)).toBeInTheDocument();
    await act(async () => release());
    await sleep(300);
    expect(screen.getByText(/A run of this feed is running now/)).toBeInTheDocument();
    vi.stubGlobal("fetch", fetchMock);
  }, 20000);
});

describe("J2: Build now follows a build whose events come before its request's answer", () => {
  it("takes a start and end that arrive while the answer is delayed", async () => {
    const user = userEvent.setup();
    const { fixtures } = mockApi();
    const b = buildCore(fixtures);
    const { fetchMock } = mockApi(b.routes);
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    vi.stubGlobal("fetch", async (req: Request) => {
      const answer = await fetchMock(req);
      if (req.method === "POST") await gate;
      return answer;
    });
    renderApp("/bundles/block-common");
    const buildNow = await screen.findByRole("button", { name: /Build now/ }, T);
    openSocket();
    await user.click(buildNow);
    act(() => socket().emit(job("bundle_build", "block-common", "start")));
    b.finish();
    act(() => socket().emit(job("bundle_build", "block-common", "end", { ms: 1500 })));
    await act(async () => release());
    expect(await within(await screen.findByLabelText("Build progress", undefined, T)).findByText("done in 2 s", undefined, T)).toBeInTheDocument();
    vi.stubGlobal("fetch", fetchMock);
  }, 20000);

  it("takes a status read after the answer that shows the build done as its end (no events)", async () => {
    const user = userEvent.setup();
    const { fixtures } = mockApi();
    const b = buildCore(fixtures, { endsAtOnce: true });
    mockApi(b.routes);
    renderApp("/bundles/block-common");
    const buildNow = await screen.findByRole("button", { name: /Build now/ }, T);
    openSocket();
    await user.click(buildNow);
    expect(await within(await screen.findByLabelText("Build progress", undefined, T)).findByText("done", undefined, T)).toBeInTheDocument();
  }, 20000);

  it("takes a build that failed again as before (a status equal to the one read before the click) as failed", async () => {
    const user = userEvent.setup();
    const { fixtures } = mockApi();
    const failed = { building: false, status: "failed", error: "out of memory" };
    let building = false;
    mockApi([
      {
        method: "POST",
        path: "/bundles/block-common/build",
        status: 202,
        body: () => {
          // It fails at once, as the last build did: the status reads as before.
          building = false;
          return { queued: true };
        },
      },
      { method: "GET", path: "/bundles/block-common/status", body: () => ({ ...(fixtures["/bundles/block-common/status"] as object), ...failed, building }) },
    ]);
    renderApp("/bundles/block-common");
    const buildNow = await screen.findByRole("button", { name: /Build now/ }, T);
    await screen.findAllByText("failed", undefined, T);
    openSocket();
    await user.click(buildNow);
    const progress = await screen.findByLabelText("Build progress", undefined, T);
    expect(await within(progress).findByText("failed", undefined, T)).toBeInTheDocument();
    expect(progress).toHaveTextContent(/The Overview tab shows the error/);
  }, 20000);

  it("stops polling once the build's end was reported", async () => {
    const user = userEvent.setup();
    const { fixtures } = mockApi();
    const b = buildCore(fixtures);
    const { calls } = mockApi(b.routes);
    renderApp("/bundles/block-common");
    const buildNow = await screen.findByRole("button", { name: /Build now/ }, T);
    openSocket();
    await user.click(buildNow);
    act(() => socket().emit(job("bundle_build", "block-common", "start")));
    act(() => socket().emit(job("bundle_build", "block-common", "end", { ms: 1500 })));
    expect(await within(await screen.findByLabelText("Build progress", undefined, T)).findByText("done in 2 s", undefined, T)).toBeInTheDocument();
    // The socket drops before a status read showed the end (the build still holds the bundle busy).
    act(() => socket().onclose?.());
    const reads = () => calls.filter((c) => c.method === "GET" && c.path === "/bundles/block-common/status").length;
    await sleep(500);
    const before = reads();
    await sleep(3500);
    expect(reads()).toBe(before);
  }, 20000);

  it("doesn't poll while the event socket is open", async () => {
    const user = userEvent.setup();
    const { fixtures } = mockApi();
    const b = buildCore(fixtures);
    const { calls } = mockApi(b.routes);
    renderApp("/bundles/block-common");
    const buildNow = await screen.findByRole("button", { name: /Build now/ }, T);
    openSocket();
    await user.click(buildNow);
    act(() => socket().emit(job("bundle_build", "block-common", "start")));
    expect(await within(await screen.findByLabelText("Build progress", undefined, T)).findByText("running", undefined, T)).toBeInTheDocument();
    const reads = () => calls.filter((c) => c.method === "GET" && c.path === "/bundles/block-common/status").length;
    await sleep(500);
    const before = reads();
    await sleep(3500);
    expect(reads()).toBe(before);
  }, 20000);

  it("doesn't take a status read made while the request is unanswered as the build's end", async () => {
    const user = userEvent.setup();
    const { fixtures } = mockApi();
    const b = buildCore(fixtures);
    const { fetchMock } = mockApi(b.routes);
    // The request is held before core takes it: a read meanwhile shows no build (none was asked for yet).
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let held = false;
    vi.stubGlobal("fetch", async (req: Request) => {
      if (req.method === "POST" && !held) {
        held = true;
        await gate;
      }
      return fetchMock(req);
    });
    renderApp("/bundles/block-common");
    const buildNow = await screen.findByRole("button", { name: /Build now/ }, T);
    openSocket();
    await user.click(buildNow);
    await waitFor(() => expect(held).toBe(true), T);
    const progress = await screen.findByLabelText("Build progress", undefined, T);
    act(() => socket().emit(job("feed_ingest", "other", "end", { dropped: 1 })));
    await sleep(300);
    expect(within(progress).getByText("queued")).toBeInTheDocument();
    await act(async () => release());
    await sleep(300);
    expect(within(screen.getByLabelText("Build progress")).getByText("queued")).toBeInTheDocument();
    vi.stubGlobal("fetch", fetchMock);
  }, 20000);

  it("shows no progress for a request core refused", async () => {
    const user = userEvent.setup();
    mockApi([{ method: "POST", path: "/bundles/block-common/build", status: 503, body: { error: { code: "busy", message: "the heavy lane is full" } } }]);
    renderApp("/bundles/block-common");
    const buildNow = await screen.findByRole("button", { name: /Build now/ }, T);
    openSocket();
    await user.click(buildNow);
    expect(await screen.findByText(/the heavy lane is full/, undefined, T)).toBeInTheDocument();
    act(() => socket().emit(job("bundle_build", "block-common", "start")));
    await sleep(200);
    expect(screen.queryByLabelText("Build progress")).toBeNull();
  }, 20000);
});

describe("J3: import preparation is bounded (api.md §7)", () => {
  it("the streaming classifier keeps only what tells the kind", () => {
    const parser = new TopLevelKeys();
    parser.push('{"padding":"');
    parser.push("x".repeat(256 * 1024));
    parser.push('"');
    for (let i = 0; i < 100_000; i++) parser.push(`,"outside${i}":0`);
    parser.push(',"li\\u0073t":[]}');
    expect(parser.keys.length).toBeLessThanOrEqual(3);
    expect(JSON.stringify(parser).length).toBeLessThan(2000);
    expect(parser.kind()).toBe("misp-list");
    const misp = new TopLevelKeys();
    misp.push('{"list":["a"],"x":1,"picket_feed":{},"list":[]}');
    expect(misp.kind()).toBe("misp-export");
    const exp = new TopLevelKeys();
    exp.push('{"picket_feed_export":1,"list":[]}');
    expect(exp.kind()).toBe("json-export");
    const late = new TopLevelKeys();
    late.push('{"a":{"picket_feed_export":1,"list":2},"picket_feed_export":1}');
    expect(late.kind()).toBe("json");
  });

  it("builds the body from bounded parts, never every escaped chunk at once", async () => {
    const parts = new BlobParts(1024);
    let most = 0;
    let expected = "";
    for (let i = 0; i < 500; i++) {
      const chunk = `"chunk ${i}"\n`.repeat(10);
      expected += chunk;
      parts.push(chunk);
      most = Math.max(most, parts.pending);
    }
    expect(most).toBeLessThan(1024 + 200);
    const blob = parts.blob("application/json");
    expect(blob.type).toBe("application/json");
    expect(await blob.text()).toBe(expected);
    // A file's body is the same JSON as one built from its whole text.
    const content = `||a.example^\n"quoted" \\ ${"é".repeat(5000)}\u0001\n`.repeat(40);
    const body = await fileJsonBody(new File([content], "l.txt"));
    expect(JSON.parse(await body.text())).toEqual({ file: content });
  });

  it("refuses a file larger than core takes before reading it, by the download size cap in the settings", async () => {
    const MiB = 1024 * 1024;
    const cap = { bytes: 1 * MiB, fromSettings: true };
    const list = { kind: "list" as const, declared: null };
    const exp = { kind: "json-export" as const, declared: {} };
    const file = (size: number, head = "") => ({ size, slice: () => new Blob([head]) }) as unknown as File;
    // A file sent as {"file": …} must fit the cap itself; a JSON export may be 32 times it.
    expect(await importSizeProblem({ file: file(MiB), text: "", info: list }, cap)).toBeNull();
    expect(await importSizeProblem({ file: file(MiB + 1), text: "", info: list }, cap)).toMatch(/core takes at most 1\.0 MiB \(1,048,576 bytes\): the file an import makes must fit the download size cap \(feeds\.max_download_mib\)/);
    expect(await importSizeProblem({ file: file(MiB + 3, "﻿"), text: "", info: list }, cap)).toBeNull();
    expect(await importSizeProblem({ file: file(32 * MiB), text: "", info: exp }, cap)).toBeNull();
    expect(await importSizeProblem({ file: file(32 * MiB + 1), text: "", info: exp }, cap)).toMatch(/core takes at most 32\.0 MiB \(33,554,432 bytes\): 32 times the download size cap of 1\.0 MiB \(feeds\.max_download_mib\)/);
    expect(await importSizeProblem({ file: null, text: "é".repeat(MiB / 2 + 1), info: inspectImport("é") }, cap)).toMatch(/download size cap/);
    // Without the settings, core's documented default, and the message says so.
    expect(await importSizeProblem({ file: file(DEFAULT_DOWNLOAD_MIB * MiB + 1), text: "", info: list }, { bytes: DEFAULT_DOWNLOAD_MIB * MiB, fromSettings: false })).toMatch(/core's default/);
  });

  it("reads the cap from the settings, else takes core's default", async () => {
    const { fixtures } = mockApi([{ method: "GET", path: "/settings", body: () => ({ ...(fixtures["/settings"] as object), settings: { ...(fixtures["/settings"] as { settings: object }).settings, feeds: { max_download_mib: 3 } } }) }]);
    expect(await downloadCap(new QueryClient())).toEqual({ bytes: 3 * 1024 * 1024, fromSettings: true });
    mockApi([{ method: "GET", path: "/settings", status: 403, body: { error: { code: "forbidden", message: "no" } } }]);
    expect(await downloadCap(new QueryClient())).toEqual({ bytes: DEFAULT_DOWNLOAD_MIB * 1024 * 1024, fromSettings: false });
  });

  it("Import… refuses a plain list over the cap without reading it or sending anything", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    const { fixtures } = mockApi();
    const { calls } = mockApi([
      ...core.routes,
      core.importRoute("x\n"),
      { method: "GET", path: "/settings", body: () => ({ ...(fixtures["/settings"] as object), settings: { ...(fixtures["/settings"] as { settings: object }).settings, feeds: { max_download_mib: 1 } } }) },
    ]);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    await user.click(screen.getByRole("button", { name: /Import…/ }));
    const dialog = await screen.findByRole("dialog");
    const big = new File(["a.example\n".repeat(110_000)], "big.txt");
    let streamed = 0;
    const stream = big.stream.bind(big);
    big.stream = () => {
      streamed++;
      return stream();
    };
    await user.upload(within(dialog).getByLabelText("File"), big);
    await within(dialog).findByText(/a plain list file/, undefined, T);
    await user.click(within(dialog).getByRole("button", { name: "Import" }));
    expect(await screen.findByText(/core takes at most 1\.0 MiB/, undefined, T)).toBeInTheDocument();
    expect(streamed).toBe(0);
    expect(mutations(calls)).toHaveLength(0);
  }, 20000);
});

describe("J3: the other import paths", () => {
  it("Import into a new feed refuses a file over the cap without reading it or sending anything", async () => {
    const user = userEvent.setup();
    const { fixtures } = mockApi();
    const { calls } = mockApi([
      { method: "POST", path: "/feeds/import", status: 201, body: { feed: "x", created: true, version: "v", changed: true, run_queued: false, entries: null } },
      { method: "GET", path: "/settings", body: () => ({ ...(fixtures["/settings"] as object), settings: { ...(fixtures["/settings"] as { settings: object }).settings, feeds: { max_download_mib: 1 } } }) },
    ]);
    renderApp("/feeds");
    await user.click(await screen.findByRole("button", { name: /Import…/ }, T));
    const dialog = await screen.findByRole("dialog");
    const big = new File(["a.example\n".repeat(110_000)], "big.txt");
    let streamed = 0;
    const stream = big.stream.bind(big);
    big.stream = () => {
      streamed++;
      return stream();
    };
    await user.upload(within(dialog).getByLabelText("File"), big);
    await within(dialog).findByText(/a plain list file/, undefined, T);
    await user.click(within(dialog).getByRole("button", { name: "Import" }));
    expect(await screen.findByText(/core takes at most 1\.0 MiB/, undefined, T)).toBeInTheDocument();
    expect(streamed).toBe(0);
    expect(mutations(calls)).toHaveLength(0);
  }, 20000);

  it("escapes pasted text in slices that never split a surrogate pair", async () => {
    const text = `${"a".repeat(64 * 1024 - 1)}\u{1F600}b\n`;
    const { body } = await importBody({ file: null, text, info: inspectImport(text.slice(0, 1000), false) });
    const raw = await body.text();
    expect(raw).not.toMatch(/\\ud83d/i);
    expect(JSON.parse(raw)).toEqual({ file: text });
  });
});

describe("J4: the contract compares import settings as core does (feeds/transfer.rs)", () => {
  const def = (d: object) => (p: string) => (p === "/feeds/f" ? d : undefined);
  const exp = (feed: object) => ({ picket_feed_export: 1, feed, entries: [] });

  it("refuses an export whose format_options aren't the feed's (same_format)", () => {
    const plain = { format: "plain", format_options: { domains_as: "exact" }, provider: null };
    expect(contractViolations("POST", "/feeds/f/import", new URLSearchParams("mode=replace"), exp({ format: "plain", format_options: { domains_as: "subdomains" } }), def(plain))).not.toEqual([]);
    expect(contractViolations("POST", "/feeds/f/import", new URLSearchParams("mode=replace"), exp({ format: "plain", format_options: { domains_as: "exact" } }), def(plain))).toEqual([]);
    // Left out is another value than `exact` (core compares the options as they are).
    expect(contractViolations("POST", "/feeds/f/import", new URLSearchParams("mode=replace"), exp({ format: "plain" }), def(plain))).not.toEqual([]);
    expect(contractViolations("POST", "/feeds/f/import", new URLSearchParams("mode=replace"), exp({ format: "adblock", format_options: {} }), def({ format: "adblock", format_options: {}, provider: null }))).toEqual([]);
    // A file export's header too.
    const file = { file: '! picket-feed-export: 1\n! format: plain\n! format_options: {"domains_as":"subdomains"}\na.example\n' };
    expect(contractViolations("POST", "/feeds/f/import", new URLSearchParams("mode=replace"), file, def(plain))).not.toEqual([]);
  });

  it("compares a new feed's warn_on with the export's as a set", () => {
    const body = exp({ format: "adblock", category: "mixed", warn_on: ["warn-a", "warn-b"] });
    const bundles = (p: string) => (p === "/bundles" ? { items: [{ id: "warn-a", action: "warn" }, { id: "warn-b", action: "warn" }] } : undefined);
    expect(contractViolations("POST", "/feeds/import", new URLSearchParams("id=n&warn_on=warn-b,warn-a"), body, bundles)).toEqual([]);
    expect(contractViolations("POST", "/feeds/import", new URLSearchParams("id=n&warn_on=warn-a,warn-a,warn-b"), body, bundles)).toEqual([]);
    expect(contractViolations("POST", "/feeds/import", new URLSearchParams("id=n&warn_on=warn-a"), body, bundles)).not.toEqual([]);
    // Into a feed too: repeats don't make another set.
    const feed = def({ format: "adblock", format_options: {}, provider: null, category: "mixed", warn_on: ["warn-a"] });
    expect(contractViolations("POST", "/feeds/f/import", new URLSearchParams("mode=merge&warn_on=warn-a,warn-a"), { file: "a.example\n" }, feed)).toEqual([]);
    const two = def({ format: "adblock", format_options: {}, provider: null, category: "mixed", warn_on: ["warn-a", "warn-b"] });
    expect(contractViolations("POST", "/feeds/f/import", new URLSearchParams("mode=merge&warn_on=warn-a,warn-a"), { file: "a.example\n" }, two)).not.toEqual([]);
  });

  it("compares a feed's rule policy as it applies (an unset switch: keep on a manual feed, drop on a provider feed)", () => {
    const manual = def({ format: "adblock", format_options: {}, provider: null, rule_policy: { redirects: null, client_rules: null, browser_changes: null } });
    const q = (s: string) => new URLSearchParams(`mode=merge&${s}`);
    const file = { file: "a.example\n" };
    expect(contractViolations("POST", "/feeds/f/import", q("redirects=keep&client_rules=keep&browser_changes=keep"), file, manual)).toEqual([]);
    expect(contractViolations("POST", "/feeds/f/import", q("redirects=drop"), file, manual)).not.toEqual([]);
    const provider = def({ format: "adblock", format_options: {}, provider: "hagezi", rule_policy: { redirects: null, client_rules: "keep", browser_changes: null } });
    expect(contractViolations("POST", "/feeds/f/import", q("redirects=drop&client_rules=keep&browser_changes=keep"), file, provider)).toEqual([]);
    expect(contractViolations("POST", "/feeds/f/import", q("redirects=keep"), file, provider)).not.toEqual([]);
    expect(contractViolations("POST", "/feeds/f/import", q("browser_changes=drop"), file, provider)).not.toEqual([]);
  });
});

describe("J5: an editor re-reads the runs after a page write that starts no wait", () => {
  const editorText = () => EditorView.findFromDOM(screen.getByTestId("code-editor").querySelector(".cm-editor") as HTMLElement)!.state.doc.toString();

  async function importHeld(core: ReturnType<typeof manualCore>, lines: string, during: () => void, afterCore: boolean) {
    const user = userEvent.setup();
    const { fetchMock, calls } = mockApi([...core.routes, core.importRoute(lines)]);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    openSocket();
    await sleep(100);
    await user.click(screen.getByRole("button", { name: /Import…/ }));
    const dialog = await screen.findByRole("dialog");
    await user.upload(within(dialog).getByLabelText("File"), new File([lines], "l.txt"));
    await within(dialog).findByText(/a plain list file/, undefined, T);
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let held = false;
    vi.stubGlobal("fetch", async (req: Request) => {
      if (req.method === "POST" && new URL(req.url).pathname.endsWith("/import") && !held) {
        held = true;
        // Held before core takes it (it then sees the other writer's save), or after (its answer is delayed).
        if (afterCore) {
          const answer = await fetchMock(req);
          await gate;
          return answer;
        }
        await gate;
      }
      return fetchMock(req);
    });
    await user.click(within(dialog).getByRole("button", { name: "Import" }));
    await waitFor(() => expect(held).toBe(true), T);
    await sleep(50);
    during();
    await sleep(100);
    await act(async () => release());
    return { calls, fetchMock };
  }

  it("a failed import: another writer's append whose run arrived meanwhile shows", async () => {
    const core = manualCore();
    const { fetchMock } = await importHeld(
      core,
      "||imported.example^\n",
      () => {
        const run = core.finishRun(core.append("||other.example^"));
        act(() => socket().emit({ type: "feed_run", data: core.event(run) }));
      },
      false,
    );
    expect(await screen.findByText(/The file changed since this page read it/, undefined, T)).toBeInTheDocument();
    await waitFor(() => expect(editorText()).toContain("||other.example^"), T);
    vi.stubGlobal("fetch", fetchMock);
  }, 20000);

  it("an unchanged import: the same", async () => {
    const core = manualCore();
    const { fetchMock } = await importHeld(
      core,
      core.st.content,
      () => {
        const run = core.finishRun(core.append("||other.example^"));
        act(() => socket().emit({ type: "feed_run", data: core.event(run) }));
      },
      true,
    );
    expect(await screen.findByText(/Nothing changed/, undefined, T)).toBeInTheDocument();
    await waitFor(() => expect(editorText()).toContain("||other.example^"), T);
    vi.stubGlobal("fetch", fetchMock);
  }, 20000);

  it("pageWrite tells the editors when a write ends without a save to wait for", async () => {
    const l = createLine();
    let rechecks = 0;
    l.rechecks.add(() => rechecks++);
    // A save that changed the file: its run is waited for.
    await pageWrite(l, async () => 1, () => recordSave(l, { version: "a", at: "2026-11-24T00:00:01Z", content: null }));
    expect(rechecks).toBe(0);
    // An unchanged one, a failed one, one whose answer can't be taken.
    await pageWrite(l, async () => 1, () => null);
    expect(rechecks).toBe(1);
    await expect(pageWrite(l, () => Promise.reject(new Error("409")), () => null)).rejects.toThrow("409");
    expect(rechecks).toBe(2);
    await expect(
      pageWrite(
        l,
        async () => 1,
        () => {
          throw new Error("bad");
        },
      ),
    ).rejects.toThrow("bad");
    expect(rechecks).toBe(3);
    // Told after the line counts the write done, so the runs it reads are placed.
    let writesThen = -1;
    l.rechecks.clear();
    l.rechecks.add(() => (writesThen = l.writes));
    await pageWrite(l, async () => 1, () => null);
    expect(writesThen).toBe(0);
    writesThen = -1;
    await expect(pageWrite(l, () => Promise.reject(new Error("409")), () => null)).rejects.toThrow("409");
    expect(writesThen).toBe(0);
  });
});
