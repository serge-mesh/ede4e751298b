// The UI on core's follow-up API (F1–F8): save times from every manual-feed write and in runs and
// `feed_run` events, the feed status's file version and retry, import settings core checks
// (422 with issues) and the plain-list settings it takes, `job` events, core's rule-policy
// descriptions, and device paths with dots. Against the stateful mock of core's manual feed
// (test/manual-core.ts) and core's request contract (test/contract.ts), which models the refusals.
import { describe, expect, it, vi } from "vitest";
import { act, render, renderHook, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { EditorView } from "@codemirror/view";
import { mockApi, reply, type Call, type Route } from "@/test/mock-api";
import { manualCore } from "@/test/manual-core";
import { feedRunFrame, jobFrame } from "@/test/events";
import { contractViolations } from "@/test/contract";
import { renderApp } from "@/test/render";
import { applyEvent, useConnection, useEventStream, useJobReports } from "@/api/events";
import { ApiError } from "@/api/errors";
import { qk } from "@/api/queries";
import { fieldDescription } from "@/lib/openapi";
import { jobState } from "@/components/common/job-progress";
import { ImportIssues, importNewQuery } from "./feeds";
import { importIntoQuery } from "./feed-detail";

const T = { timeout: 8000 };

interface FakeSocket {
  open: () => void;
  emit: (d: unknown) => void;
}
const socket = () => (globalThis.WebSocket as unknown as { instances: FakeSocket[] }).instances.at(-1)!;
/** Opens the page's event socket: call once the page shows (the app creates it as it mounts). */
const openSocket = () => act(() => socket().open());
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const runEvent = (core: ReturnType<typeof manualCore>, run: number) => act(() => socket().emit({ type: "feed_run", data: core.event(run) }));
const runsReads = (calls: Call[]) => calls.filter((c) => c.method === "GET" && c.path === "/feeds/manual-block/runs").length;

function editorView(): EditorView {
  const host = screen.getByTestId("code-editor");
  return EditorView.findFromDOM(host.querySelector(".cm-editor") as HTMLElement)!;
}
async function typeAtEnd(text: string) {
  await screen.findByTestId("code-editor", undefined, T);
  const view = editorView();
  act(() => view.dispatch({ changes: { from: view.state.doc.length, insert: text } }));
}

/** A job event as core sends it (test/events.ts `jobFrame`: JobEvent with its `run` and `dropped`). */
const job = jobFrame;

/** core's refusal of an import as `issues` (feeds/transfer.rs `conflict`, entity validation): what test/contract.ts says core refuses. */
function refusal(feed: string, violations: string[]) {
  const issues = violations.map((v) => ({
    severity: "error",
    entity: "feed",
    id: feed,
    field: /field (\w+)/.exec(v)?.[1] ?? null,
    code: "import_setting_conflict",
    message: v.replace(/^POST \S+: 422( \(field \w+\))?: /, ""),
  }));
  return reply(422, { error: { code: "validation", message: issues.map((i) => i.message).join("; "), issues } });
}

/** `POST feeds/import` as core answers it: 422 with issues for what core refuses, else the new feed. */
function coreImportNew(sent: Call[]): Route {
  return {
    method: "POST",
    path: "/feeds/import",
    refuses: true,
    body: (c: Call) => {
      sent.push(c);
      const refused = contractViolations("POST", "/feeds/import", c.query, c.body, (p) => (p === "/bundles" ? { items: [{ id: "warn-common", action: "warn" }, { id: "block-common", action: "block" }] } : undefined));
      if (refused.length) return refusal(c.query.get("id") ?? "", refused);
      return reply(201, { feed: c.query.get("id"), created: true, version: "0123456789abcdef", saved_at: "2026-11-24T00:00:00.000000Z", changed: true, run_queued: false, entries: null });
    },
  };
}

async function openImportNew(user: ReturnType<typeof userEvent.setup>, file: File) {
  renderApp("/feeds");
  await user.click(await screen.findByRole("button", { name: /Import…/ }, T));
  const dialog = await screen.findByRole("dialog");
  await user.upload(within(dialog).getByLabelText("File"), file);
  return dialog;
}

// ---------------------------------------------------------------------------------------------

describe("F3, F5: a save's run is matched by core's save time alone (feeds.md §1)", () => {
  it("takes the save time from the save's answer, ignores an older run's event without reading, and reads the runs on its own run's event", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    // An earlier save whose run is still in flight when the editor opens and saves.
    const v1 = core.append("||first.example^");
    const { calls } = mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await typeAtEnd("||mine.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    await sleep(300);
    const before = runsReads(calls);
    runEvent(core, core.finishRun(v1));
    await sleep(300);
    // An earlier save's run: placed from the event alone.
    expect(runsReads(calls)).toBe(before);
    expect(screen.getByText(/Waiting for the run's result/)).toBeInTheDocument();
    const mine = core.finishRun();
    runEvent(core, mine);
    // On its event, before the poll's next read (2 s after the save).
    expect(await screen.findByText(`Run ${mine}`, undefined, { timeout: 800 })).toBeInTheDocument();
    expect(runsReads(calls)).toBe(before + 1);
    expect(screen.queryByText(/changed again/)).toBeNull();
    expect(core.st.fileReads).toBe(1);
  });

  it("takes another writer's save from its feed_run event: a clean editor reloads, without reading the runs", async () => {
    const core = manualCore();
    const { calls } = mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    await sleep(300);
    const before = runsReads(calls);
    const v = core.append("||elsewhere.example^");
    runEvent(core, core.finishRun(v));
    await waitFor(() => expect(editorView().state.doc.toString()).toContain("||elsewhere.example^"), T);
    expect(screen.getByText(v)).toBeInTheDocument();
    expect(runsReads(calls)).toBe(before);
    expect(core.st.fileReads).toBe(2);
  });

  it("ignores events of runs that read no save (a re-ingest, a confirmation) and of other feeds", async () => {
    const core = manualCore();
    const { calls } = mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    await sleep(300);
    const before = runsReads(calls);
    const v = core.append("||elsewhere.example^");
    // One coalesced event (core a3eb6d5) or one each: none of them places a save.
    const runs = [
      { feed: "manual-block", run: 9, kind: "reingest", version: v, saved_at: core.st.savedAt },
      { feed: "manual-block", run: 10, kind: "download", version: v, saved_at: core.st.savedAt, source_run: 7 },
      { feed: "manual-allow", run: 11, kind: "download", version: v, saved_at: core.st.savedAt },
    ];
    act(() => socket().emit(feedRunFrame(runs)));
    for (const r of runs) act(() => socket().emit(feedRunFrame([r])));
    await sleep(500);
    expect(editorView().state.doc.toString()).not.toContain("||elsewhere.example^");
    expect(core.st.fileReads).toBe(1);
    expect(runsReads(calls)).toBe(before);
  });
});

describe("F3: the page's writes in flight", () => {
  it("doesn't take a file read that shows a save still in flight as another writer's", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    const { fetchMock } = mockApi(core.routes);
    const { queryClient } = renderApp("/feeds/manual-block");
    await typeAtEnd("||mine.example^\n");
    await sleep(50);
    // core stores the save at once; its answer reaches the page on release.
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let held = false;
    vi.stubGlobal("fetch", async (req: Request) => {
      if (held || req.method !== "PUT") return fetchMock(req);
      held = true;
      const res = await fetchMock(req);
      await gate;
      return res;
    });
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(held).toBe(true), T);
    // A read of the file now shows that save, before its answer arrived.
    await act(async () => {
      await queryClient.refetchQueries({ queryKey: qk.manualFile("manual-block") });
    });
    await sleep(200);
    expect(screen.queryByText("The file changed elsewhere")).toBeNull();
    await act(async () => release());
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    await sleep(300);
    expect(screen.queryByText("The file changed elsewhere")).toBeNull();
    vi.stubGlobal("fetch", fetchMock);
  });

  it("doesn't wait for a run after an import that changed nothing", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    const { calls } = mockApi([...core.routes, core.importRoute(core.st.content)]);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    await user.click(screen.getByRole("button", { name: /Import…/ }));
    const dialog = await screen.findByRole("dialog");
    await user.upload(within(dialog).getByLabelText("File"), new File([core.st.content], "same.txt"));
    await within(dialog).findByText(/a plain list file/, undefined, T);
    await user.click(within(dialog).getByRole("button", { name: "Import" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull(), T);
    expect(calls.some((c) => c.method === "POST" && c.path === "/feeds/manual-block/import")).toBe(true);
    await sleep(300);
    expect(screen.queryByText(/Waiting for the run's result/)).toBeNull();
    expect(screen.queryByText(/Core made no new run/)).toBeNull();
    // Nor is the run of the file it left unchanged taken as its run.
    expect(screen.queryByText("Run 7")).toBeNull();
    expect(core.st.saves).toHaveLength(1);
  });
});

describe("F3: what the editor learns saves from", () => {
  it("takes another writer's save from the runs read after a reconnect (events missed)", async () => {
    const core = manualCore();
    mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    openSocket();
    await sleep(100);
    const reads = core.st.fileReads;
    // The socket drops; meanwhile another writer saves and its run ends; the socket comes back.
    act(() => (socket() as unknown as { onclose: () => void }).onclose());
    const v = core.append("||missed.example^");
    core.finishRun(v);
    await sleep(1200);
    openSocket();
    await waitFor(() => expect(editorView().state.doc.toString()).toContain("||missed.example^"), T);
    expect(core.st.fileReads).toBe(reads + 1);
  });

  it("takes a newer file a refetch brings (e.g. Retry after a failed read)", async () => {
    const core = manualCore();
    mockApi(core.routes);
    const { queryClient } = renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    await sleep(100);
    core.append("||elsewhere.example^");
    await act(async () => {
      await queryClient.refetchQueries({ queryKey: qk.manualFile("manual-block") });
    });
    await waitFor(() => expect(editorView().state.doc.toString()).toContain("||elsewhere.example^"), T);
    expect(screen.getByText(core.st.version)).toBeInTheDocument();
  });

  it("places neither the status nor the runs a poll reads while a save is in flight", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    const { fetchMock } = mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await typeAtEnd("||one.example^\n");
    openSocket();
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    await typeAtEnd("||two.example^\n");
    // core stores the second save and ends its run at once; its answer reaches the page on release.
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let held = false;
    vi.stubGlobal("fetch", async (req: Request) => {
      if (held || req.method !== "PUT") return fetchMock(req);
      held = true;
      const res = await fetchMock(req);
      core.finishRun();
      await gate;
      return res;
    });
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(held).toBe(true), T);
    await sleep(50);
    // A job of the feed ends: the poll reads the status and runs now, during the save.
    const reads = core.st.statusReads;
    act(() => socket().emit(job("feed_ingest", "manual-block", "end")));
    await waitFor(() => expect(core.st.statusReads).toBe(reads + 1), T);
    await sleep(300);
    expect(screen.queryByText("The file changed elsewhere")).toBeNull();
    expect(screen.queryByText(/changed again/)).toBeNull();
    await act(async () => release());
    expect(await screen.findByText(/^Run \d+$/, undefined, T)).toBeInTheDocument();
    expect(screen.queryByText(/changed again/)).toBeNull();
    expect(screen.queryByText("The file changed elsewhere")).toBeNull();
    vi.stubGlobal("fetch", fetchMock);
  });

  it("says no run comes when the feed was disabled elsewhere after the save", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await typeAtEnd("||one.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    core.st.enabled = false;
    core.st.busy = false;
    expect(await screen.findByText(/The feed is disabled, so no run reads the file/, undefined, T)).toBeInTheDocument();
  }, 15000);
});

describe("F6: the event socket's state", () => {
  it("is closed again once the app that opened it is gone", async () => {
    mockApi();
    const { unmount } = renderApp("/system");
    await screen.findByLabelText("Job lanes now", undefined, T);
    openSocket();
    expect(renderHook(() => useConnection()).result.current).toBe("open");
    unmount();
    expect(renderHook(() => useConnection()).result.current).toBe("closed");
  });
});

describe("F2: warn_on for a new feed", () => {
  it("starts from the category's default when it stops following it", async () => {
    const user = userEvent.setup();
    const sent: Call[] = [];
    mockApi([coreImportNew(sent)]);
    const dialog = await openImportNew(user, new File(["ads.example\n"], "list.txt", { type: "text/plain" }));
    await within(dialog).findByText(/a plain list file/, undefined, T);
    await user.click(within(dialog).getByLabelText("Category"));
    await user.click(await screen.findByRole("option", { name: "security" }));
    expect(within(dialog).getByText("Follows the category (warn-common)")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("switch", { name: "warn_on follows the category" }));
    expect(within(dialog).getByText("warn-common")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Import" }));
    await waitFor(() => expect(sent).toHaveLength(1), T);
    expect(sent[0].query.get("warn_on")).toBe("warn-common");
    expect(sent[0].query.get("category")).toBe("security");
  });

  it("shows a field's name once when core's message starts with it", () => {
    const err = new ApiError(422, "validation", "x", [
      { severity: "error", entity: "feed", id: "x", field: "category", code: "import_setting_conflict", message: "category: the export declares security and the query says privacy" },
      { severity: "error", entity: "feed", id: "x", field: "warn_on", code: "warn_on_not_warn", message: '"block-common" is a block bundle' },
    ]);
    render(<ImportIssues error={err} />);
    const list = screen.getByRole("list", { name: "Import issues" });
    expect(within(list).queryByText("Category:")).toBeNull();
    expect(within(list).getByText(/^category: the export declares/)).toBeInTheDocument();
    expect(within(list).getByText("warn_on:")).toBeInTheDocument();
  });
});

describe("F5: a feed_run marks a closed editor's file stale only for a later save", () => {
  it("keeps the cached file for a run of its own save or an earlier one", () => {
    const qc = new QueryClient();
    const at = "2026-11-23T10:00:05.000000Z";
    const stale = () => qc.getQueryState(qk.manualFile("manual-block"))?.isInvalidated;
    qc.setQueryData(qk.manualFile("manual-block"), { version: "a", saved_at: at, content: "x", size: 1 });
    applyEvent(qc, feedRunFrame([{ feed: "manual-block", run: 8, kind: "download", version: "a", saved_at: at }]));
    applyEvent(qc, feedRunFrame([{ feed: "manual-block", run: 9, kind: "reingest", version: "z", saved_at: "2026-11-23T10:00:01.000000Z" }]));
    expect(stale()).toBe(false);
    applyEvent(qc, feedRunFrame([{ feed: "manual-block", run: 10, kind: "download", version: "b", saved_at: "2026-11-23T10:00:06.000000Z" }]));
    expect(stale()).toBe(true);
  });
});

describe("F4: the feed's status says whether a run is coming", () => {
  it("keeps waiting, saying nothing, while core is idle with nothing to retry but no run read the file yet", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await typeAtEnd("||one.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    // core frees the feed just before it starts a save queued behind its run.
    core.st.busy = false;
    await sleep(2600);
    expect(screen.getByText(/Waiting for the run's result/)).toBeInTheDocument();
    expect(screen.queryByText(/Core made no new run|tries it again/)).toBeNull();
    const id = core.finishRun();
    runEvent(core, id);
    expect(await screen.findByText(`Run ${id}`, undefined, T)).toBeInTheDocument();
  }, 15000);

  it("says core made no run when the file changed again and the newest run already read the newer text", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await typeAtEnd("||one.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    // Another writer puts the original text back before the save's run started: core skips it.
    core.save("||original.example^\n");
    core.st.busy = false;
    expect(await screen.findByText(/changed again before this save's run started, and run 7 already read the newer text/, undefined, T)).toBeInTheDocument();
    expect(screen.getByText("Run 7")).toBeInTheDocument();
    // The status told the clean editor of the other writer's save (no run, no event): it takes it.
    await waitFor(() => expect(editorView().state.doc.toString()).toBe("||original.example^\n"), T);
  }, 15000);

  it("shows a manual feed's file version and pending retry on its Status tab", async () => {
    const { fixtures } = mockApi([
      {
        method: "GET",
        path: "/feeds/manual-block/status",
        body: () => ({ ...(fixtures["/feeds/manual-block/status"] as object), manual_retry_at: "2026-11-23T10:42:00.000000Z" }),
      },
    ]);
    renderApp("/feeds/manual-block?tab=overview");
    expect(await screen.findByText("406dfda686b20c67", undefined, T)).toBeInTheDocument();
    expect(screen.getByText(/core tries again at/)).toBeInTheDocument();
  });

  it("polls at once when a job of the feed ends (job event), e.g. a run that failed and is retried", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await typeAtEnd("||one.example^\n");
    openSocket();
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    act(() => socket().emit(job("feed_ingest", "manual-block", "start")));
    expect(await screen.findByText(/A run of this feed is running now/, undefined, T)).toBeInTheDocument();
    // Another feed's job isn't this one's.
    act(() => socket().emit(job("feed_ingest", "manual-allow", "end")));
    expect(screen.getByText(/A run of this feed is running now/)).toBeInTheDocument();
    // A re-ingest that held the feed ends too: any run of the feed counts.
    act(() => socket().emit(job("feed_reingest", "manual-block", "end")));
    await waitFor(() => expect(screen.queryByText(/A run of this feed is running now/)).toBeNull(), T);
    await sleep(300);
    core.st.busy = false;
    core.st.retryAt = "2026-11-23T10:01:30.000000Z";
    const reads = core.st.statusReads;
    act(() => socket().emit(job("feed_ingest", "manual-block", "end", { outcome: "failed" })));
    // Before the next poll of the backoff (2 s).
    await waitFor(() => expect(core.st.statusReads).toBe(reads + 1), { timeout: 1000 });
    expect(await screen.findByText(/Core tries it again at/, undefined, { timeout: 1000 })).toBeInTheDocument();
  });
});

describe("F1: core refuses an import setting that conflicts with the export (feeds.md §4)", () => {
  const q = (s = "") => new URLSearchParams(s);
  const header = (lines: string[]) => ({ file: ["! picket-feed-export: 1", ...lines, "! picket-first-seen: none", "||a.example^", ""].join("\n") });
  const exportBody = (feed: Record<string, unknown>) => ({ picket_feed_export: 1, feed, entries: [] });

  it("test/contract.ts models core's comparisons", () => {
    // A JSON export's category; equal is fine, a key the export leaves out is filled from the query.
    expect(contractViolations("POST", "/feeds/import", q("id=x&category=privacy"), exportBody({ category: "security" }))).toEqual([expect.stringMatching(/field category/)]);
    expect(contractViolations("POST", "/feeds/import", q("id=x&category=security"), exportBody({ category: "security" }))).toEqual([]);
    expect(contractViolations("POST", "/feeds/import", q("id=x&category=privacy"), exportBody({ format: "adblock" }))).toEqual([]);
    // A file export's header; format_options compared by domains_as (default exact).
    expect(contractViolations("POST", "/feeds/import", q("id=x&format=plain"), header(["! format: adblock"]))).toEqual([expect.stringMatching(/field format/)]);
    expect(contractViolations("POST", "/feeds/import", q("id=x&domains_as=subdomains"), header(["! format_options: {}"]))).toEqual([expect.stringMatching(/field format_options/)]);
    expect(contractViolations("POST", "/feeds/import", q("id=x&domains_as=exact"), header(["! format_options: {}"]))).toEqual([]);
    // warn_on as it applies: null follows the category.
    expect(contractViolations("POST", "/feeds/import", q("id=x&warn_on=warn-common"), exportBody({ category: "security", warn_on: null }))).toEqual([]);
    expect(contractViolations("POST", "/feeds/import", q("id=x&warn_on="), exportBody({ category: "security", warn_on: null }))).toEqual([expect.stringMatching(/field warn_on/)]);
    // rule_policy resolved for a manual feed (left out: keep).
    expect(contractViolations("POST", "/feeds/import", q("id=x&redirects=keep"), exportBody({ rule_policy: {} }))).toEqual([]);
    expect(contractViolations("POST", "/feeds/import", q("id=x&client_rules=drop"), exportBody({ rule_policy: { client_rules: "keep" } }))).toEqual([expect.stringMatching(/field rule_policy/)]);
    // A MISP export brings its format; a format named for a bare MISP list makes core read it as text.
    expect(contractViolations("POST", "/feeds/import", q("id=x&format=adblock"), { file: JSON.stringify({ type: "hostname", list: ["a.example"], picket_feed: { category: "mixed" } }) })).toEqual([expect.stringMatching(/field format/)]);
    expect(contractViolations("POST", "/feeds/import", q("id=x&format=adblock"), { file: JSON.stringify({ type: "hostname", list: ["a.example"] }) })).toEqual([expect.stringMatching(/reads it as text/)]);
    expect(contractViolations("POST", "/feeds/import", q("id=x&category=privacy"), { file: JSON.stringify({ type: "hostname", list: ["a.example"] }) })).toEqual([]);
    // A plain list takes the query; the new params take core's enums.
    expect(contractViolations("POST", "/feeds/import", q("id=x&format=plain&redirects=drop&client_rules=keep&browser_changes=drop&warn_on="), { file: "a.example\n" })).toEqual([]);
    expect(contractViolations("POST", "/feeds/import", q("id=x&redirects=off"), { file: "a.example\n" })).toEqual([expect.stringMatching(/redirects=off/)]);
    // F2: warn_on names warn bundles.
    const bundles = () => ({ items: [{ id: "warn-common", action: "warn" }, { id: "block-common", action: "block" }] });
    expect(contractViolations("POST", "/feeds/import", q("id=x&warn_on=warn-common"), { file: "a.example\n" }, bundles)).toEqual([]);
    expect(contractViolations("POST", "/feeds/import", q("id=x&warn_on=block-common"), { file: "a.example\n" }, bundles)).toEqual([expect.stringMatching(/field warn_on/)]);
  });

  it("test/contract.ts models an import into a feed: the query's settings and an export's format must be the feed's", () => {
    const feed = (def: Record<string, unknown>) => (p: string) => (p === "/feeds/f" ? { format: "adblock", format_options: {}, provider: null, ...def } : undefined);
    expect(contractViolations("POST", "/feeds/f/import", q("mode=merge&format=adblock"), { file: "a\n" }, feed({}))).toEqual([]);
    expect(contractViolations("POST", "/feeds/f/import", q("mode=merge&format=hosts"), { file: "a\n" }, feed({}))).toEqual([expect.stringMatching(/field format/)]);
    expect(contractViolations("POST", "/feeds/f/import", q("mode=merge&domains_as=subdomains"), { file: "a\n" }, feed({ format: "plain" }))).toEqual([expect.stringMatching(/field format_options/)]);
    expect(contractViolations("POST", "/feeds/f/import", q("mode=merge"), exportBody({ format: "hosts" }), feed({}))).toEqual([expect.stringMatching(/isn't the feed's adblock/)]);
    expect(contractViolations("POST", "/feeds/f/import", q("mode=replace"), { file: "a\n" }, feed({ provider: "p" }))).toEqual([expect.stringMatching(/replace on a provider feed/)]);
    // Without the feed's definition, a query format another than the export's is refused either way.
    expect(contractViolations("POST", "/feeds/f/import", q("mode=merge&format=plain"), exportBody({ format: "hosts" }))).toEqual([expect.stringMatching(/the export hosts/)]);
    // The other settings must be the feed's own; warn_on compares as a set.
    expect(contractViolations("POST", "/feeds/f/import", q("mode=merge&category=mixed"), { file: "a\n" }, feed({ category: "security" }))).toEqual([expect.stringMatching(/field category/)]);
    expect(contractViolations("POST", "/feeds/f/import", q("mode=merge&category=security&warn_on=warn-x,warn-common"), { file: "a\n" }, feed({ category: "security", warn_on: ["warn-common", "warn-x"] }))).toEqual([]);
    expect(contractViolations("POST", "/feeds/f/import", q("mode=merge&redirects=keep"), { file: "a\n" }, feed({ rule_policy: { redirects: "drop" } }))).toEqual([expect.stringMatching(/rule_policy.redirects/)]);
    // A query parameter the OpenAPI document doesn't list is still flagged.
    expect(contractViolations("POST", "/feeds/f/import", q("mode=merge&nonsense=1"), { file: "a\n" })).toEqual([expect.stringMatching(/ignores the query parameter nonsense/)]);
  });

  it("shows core's issues in the dialog and keeps it open", async () => {
    const user = userEvent.setup();
    const sent: Call[] = [];
    mockApi([coreImportNew(sent)]);
    const dialog = await openImportNew(user, new File(["ads.example\n"], "list.txt", { type: "text/plain" }));
    await within(dialog).findByText(/a plain list file/, undefined, T);
    // A bundle that isn't a warn bundle: core validates warn_on as the feed's own field (F2).
    await user.click(within(dialog).getByRole("switch", { name: "warn_on follows the category" }));
    const tags = within(dialog).getByPlaceholderText(/Warn bundles/);
    await user.type(tags, "block-common{Enter}");
    await user.click(within(dialog).getByRole("button", { name: "Import" }));
    const issues = await within(dialog).findByRole("list", { name: "Import issues" }, T);
    expect(within(dialog).getByText("Core refused the import")).toBeInTheDocument();
    expect(within(issues).getByText(/warn_on:/)).toBeInTheDocument();
    expect(within(issues).getByText(/isn't a warn bundle/)).toBeInTheDocument();
    // In the dialog only, not in a toast as well.
    await sleep(100);
    expect(screen.getAllByText(/isn't a warn bundle/)).toHaveLength(1);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(sent.at(-1)!.query.get("warn_on")).toBe("block-common");
    // Another file: the issues were the earlier one's.
    await user.upload(within(dialog).getByLabelText("File"), new File(["more.example\n"], "list.txt", { type: "text/plain" }));
    await waitFor(() => expect(within(dialog).queryByRole("list", { name: "Import issues" })).toBeNull(), T);
    // Fixing it sends again and creates the feed.
    await user.click(within(dialog).getByRole("switch", { name: "warn_on follows the category" }));
    await user.click(within(dialog).getByRole("button", { name: "Import" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull(), T);
    expect(sent.at(-1)!.query.has("warn_on")).toBe(false);
  });
});

describe("F2: a plain list's rule policy and warn_on when importing a new manual feed (feeds.md §4)", () => {
  it("offers both for a plain list and sends only what is set", async () => {
    const user = userEvent.setup();
    const sent: Call[] = [];
    mockApi([coreImportNew(sent)]);
    const dialog = await openImportNew(user, new File(["ads.example\n"], "list.txt", { type: "text/plain" }));
    await within(dialog).findByText(/a plain list file/, undefined, T);
    const policy = within(dialog).getByRole("group", { name: "Rule policy" });
    // A manual feed keeps all three by default.
    expect(within(policy).getByRole("switch", { name: "redirects: keep" })).toHaveAttribute("data-state", "checked");
    await user.click(within(policy).getByRole("switch", { name: "client_rules: keep" }));
    await user.click(within(dialog).getByRole("switch", { name: "warn_on follows the category" }));
    await user.type(within(dialog).getByPlaceholderText(/Warn bundles/), "warn-common{Enter}");
    await user.click(within(dialog).getByRole("button", { name: "Import" }));
    await waitFor(() => expect(sent).toHaveLength(1), T);
    expect(Object.fromEntries(sent[0].query)).toEqual({ id: "list", format: "plain", category: "mixed", domains_as: "exact", client_rules: "drop", warn_on: "warn-common" });
  });

  it("sends none for an export, and only warn_on (with the category) for a MISP list without picket_feed", async () => {
    const user = userEvent.setup();
    const sent: Call[] = [];
    mockApi([coreImportNew(sent)]);
    const dialog = await openImportNew(user, new File([JSON.stringify({ name: "x", type: "hostname", list: ["a.example"] })], "misp.json", { type: "application/json" }));
    await within(dialog).findByText(/a MISP warninglist,/, undefined, T);
    expect(within(dialog).queryByRole("group", { name: "Rule policy" })).toBeNull();
    await user.click(within(dialog).getByRole("switch", { name: "warn_on follows the category" }));
    await user.click(within(dialog).getByRole("button", { name: "Import" }));
    await waitFor(() => expect(sent).toHaveLength(1), T);
    expect(Object.fromEntries(sent[0].query)).toEqual({ id: "misp", category: "mixed", warn_on: "" });
    const v = { id: "x", name: "", format: "plain", category: "security", domainsAs: "subdomains", rulePolicy: { redirects: "drop" as const }, warnOn: ["warn-common"] };
    expect(importNewQuery("file-export", v)).toEqual({ id: "x", name: undefined });
    expect(importNewQuery("json-export", v)).toEqual({ id: "x", name: undefined });
    expect(importNewQuery("misp-export", v)).toEqual({ id: "x", name: undefined });
    expect(importNewQuery("json", v)).toEqual({ id: "x", name: undefined, format: "plain", category: "security", domains_as: "subdomains", redirects: "drop", warn_on: "warn-common" });
    expect(importNewQuery("list", { ...v, warnOn: null, rulePolicy: { redirects: null } })).toEqual({ id: "x", name: undefined, format: "plain", category: "security", domains_as: "subdomains" });
  });
});

describe("F1: importIntoFeed's format and domains_as where they apply", () => {
  it("pins the feed's format for a plain list, misp-warninglist for a MISP list, nothing for an export", () => {
    const plain = { format: "plain" as const, format_options: { domains_as: "subdomains" as const } };
    const adblock = { format: "adblock" as const, format_options: {} };
    expect(importIntoQuery("list", plain)).toEqual({ format: "plain", domains_as: "subdomains" });
    expect(importIntoQuery("json", { format: "plain", format_options: {} })).toEqual({ format: "plain", domains_as: "exact" });
    expect(importIntoQuery("list", adblock)).toEqual({ format: "adblock", domains_as: undefined });
    expect(importIntoQuery("misp-list", adblock)).toEqual({ format: "misp-warninglist" });
    for (const k of ["json-export", "file-export", "misp-export"] as const) expect(importIntoQuery(k, adblock)).toEqual({});
  });

  it("shows core's refusal of a MISP list into a line-format feed in the dialog", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    mockApi([
      ...core.routes,
      {
        method: "POST",
        path: "/feeds/manual-block/import",
        refuses: true,
        body: (c: Call) => {
          const refused = contractViolations("POST", c.path, c.query, c.body, (p) => (p === "/feeds/manual-block" ? { format: "adblock", format_options: {}, provider: null } : undefined));
          return refused.length ? refusal("manual-block", refused) : { feed: "manual-block", created: false, version: core.st.version, saved_at: core.st.savedAt, changed: false, run_queued: false, entries: null };
        },
      },
    ]);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    await user.click(screen.getByRole("button", { name: /Import…/ }));
    const dialog = await screen.findByRole("dialog");
    await user.upload(within(dialog).getByLabelText("File"), new File([JSON.stringify({ type: "hostname", list: ["a.example"] })], "m.json"));
    expect(await within(dialog).findByText(/a MISP warninglist goes only into a misp-warninglist feed/, undefined, T)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Import" }));
    const issues = await within(dialog).findByRole("list", { name: "Import issues" }, T);
    expect(within(issues).getByText("Format:")).toBeInTheDocument();
    expect(within(issues).getByText(/the feed's is adblock/)).toBeInTheDocument();
    await sleep(100);
    expect(screen.getAllByText(/the feed's is adblock/)).toHaveLength(1);
    expect(core.st.saves).toHaveLength(1);
    // Another file: the issues were the earlier one's.
    await user.upload(within(dialog).getByLabelText("File"), new File(["ads.example\n"], "l.txt"));
    await waitFor(() => expect(within(dialog).queryByRole("list", { name: "Import issues" })).toBeNull(), T);
  });
});

describe("F6: job events", () => {
  it("set the jobs view without a request, and a bundle build's refresh its status", () => {
    const qc = new QueryClient();
    const spy: unknown[] = [];
    const orig = qc.invalidateQueries.bind(qc);
    qc.invalidateQueries = ((f: { queryKey?: unknown }) => {
      spy.push(f?.queryKey);
      return orig(f as never);
    }) as typeof qc.invalidateQueries;
    applyEvent(qc, job("feed_ingest", "manual-block", "start"));
    expect(qc.getQueryData(qk.jobs)).toEqual({ light_depth: 0, light_dropped: 0, heavy_depth: 0, heavy_dropped: 0, heavy_completed: 30, heavy_failed: 0, heavy_running: "feed_ingest:manual-block" });
    expect(spy).toEqual([]);
    applyEvent(qc, job("bundle_build", "block-common", "end"));
    expect(spy).toEqual(expect.arrayContaining([qk.bundleStatus, qk.bundle("block-common", "status")]));
    expect((qc.getQueryData(qk.jobs) as { heavy_running: unknown }).heavy_running).toBeNull();
    expect(jobState({ phase: "end", outcome: "failed", ms: 3000 })).toBe("failed after 3 s");
    expect(jobState({ phase: "end", outcome: "superseded", ms: 10 })).toMatch(/superseded/);
  });

  it("System shows the lanes and the heavy jobs that ended from events", async () => {
    const { calls } = mockApi();
    renderApp("/system");
    expect(await screen.findByLabelText("Job lanes now", undefined, T)).toBeInTheDocument();
    openSocket();
    const reads = calls.filter((c) => c.path === "/jobs").length;
    act(() => socket().emit(job("bundle_build", "block-common", "start")));
    expect(await screen.findByText("bundle_build:block-common", undefined, T)).toBeInTheDocument();
    act(() => socket().emit(job("bundle_build", "block-common", "end", { outcome: "failed", ms: 2000 })));
    const recent = await screen.findByRole("table", { name: "Recent heavy jobs" }, T);
    expect(within(recent).getByText("failed after 2 s")).toBeInTheDocument();
    expect(calls.filter((c) => c.path === "/jobs").length).toBe(reads);
  });

  it("are kept per job, at most 50, the job reported last at the end", () => {
    const qc = new QueryClient();
    const { result } = renderHook(
      () => {
        useEventStream();
        return useJobReports(0, (j) => j.kind === "feed_ingest");
      },
      { wrapper: ({ children }) => <QueryClientProvider client={qc}>{children}</QueryClientProvider> },
    );
    act(() => socket().open());
    for (let i = 0; i < 60; i++) act(() => socket().emit(job("feed_ingest", `f${i}`, "end")));
    act(() => socket().emit(job("feed_ingest", "f59", "start")));
    act(() => socket().emit(job("bundle_build", "b", "start")));
    act(() => socket().emit(job("feed_ingest", "f30", "end", { outcome: "failed" })));
    expect(result.current).toHaveLength(50);
    expect(result.current.map((r) => r.job).slice(-3)).toEqual(["feed_ingest:f58", "feed_ingest:f59", "feed_ingest:f30"]);
    expect(result.current.at(-1)!.outcome).toBe("failed");
    expect(result.current.find((r) => r.job === "feed_ingest:f59")!.phase).toBe("start");
  });

  it("System polls the lanes every 5 s while the event socket is down, every 30 s while it is open", async () => {
    mockApi();
    const { queryClient } = renderApp("/system");
    await screen.findByLabelText("Job lanes now", undefined, T);
    const interval = () => (queryClient.getQueryCache().find({ queryKey: qk.jobs })?.observers[0]?.options as { refetchInterval?: unknown }).refetchInterval;
    expect(interval()).toBe(5000);
    openSocket();
    await waitFor(() => expect(interval()).toBe(30_000), T);
  });

  it("Build now follows its build: queued, running, then how it ended", async () => {
    const user = userEvent.setup();
    // core's status says `building` from the request to the build's end (compiler busy).
    let building = false;
    const { fixtures } = mockApi([
      {
        method: "POST",
        path: "/bundles/block-common/build",
        status: 202,
        body: () => {
          building = true;
          return { queued: true };
        },
      },
      { method: "GET", path: "/bundles/block-common/status", body: () => ({ ...(fixtures["/bundles/block-common/status"] as object), building }) },
    ]);
    renderApp("/bundles/block-common");
    const buildNow = await screen.findByRole("button", { name: /Build now/ }, T);
    openSocket();
    await user.click(buildNow);
    const progress = await screen.findByLabelText("Build progress", undefined, T);
    expect(within(progress).getByText("queued")).toBeInTheDocument();
    // Another bundle's build isn't this one's.
    act(() => socket().emit(job("bundle_build", "allow-common", "start")));
    await sleep(100);
    expect(within(progress).getByText("queued")).toBeInTheDocument();
    act(() => socket().emit(job("bundle_build", "block-common", "start")));
    expect(await within(progress).findByText("running", undefined, T)).toBeInTheDocument();
    building = false;
    act(() => socket().emit(job("bundle_build", "block-common", "end", { ms: 1500 })));
    expect(await within(progress).findByText("done in 2 s", undefined, T)).toBeInTheDocument();
    // Build now again: its own build is followed from the start.
    await user.click(screen.getByRole("button", { name: /Build now/ }));
    expect(await within(screen.getByLabelText("Build progress")).findByText("queued", undefined, T)).toBeInTheDocument();
  });

  it("Build now doesn't take a status read before it as its build's result", async () => {
    const user = userEvent.setup();
    let building = false;
    const { fetchMock, fixtures } = mockApi([
      {
        method: "POST",
        path: "/bundles/block-common/build",
        status: 202,
        body: () => {
          building = true;
          return { queued: true };
        },
      },
      { method: "GET", path: "/bundles/block-common/status", body: () => ({ ...(fixtures["/bundles/block-common/status"] as object), building }) },
    ]);
    renderApp("/bundles/block-common");
    const buildNow = await screen.findByRole("button", { name: /Build now/ }, T);
    await screen.findAllByText("ok", undefined, T);
    // The status read before the click says no build runs; reads after it are held.
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    vi.stubGlobal("fetch", async (req: Request) => {
      if (req.method === "GET" && new URL(req.url).pathname.endsWith("/bundles/block-common/status")) await gate;
      return fetchMock(req);
    });
    await user.click(buildNow);
    const progress = await screen.findByLabelText("Build progress", undefined, T);
    await sleep(200);
    expect(within(progress).getByText("queued")).toBeInTheDocument();
    release();
    vi.stubGlobal("fetch", fetchMock);
  });

  it("Build now polls the bundle's status while the event socket is down", async () => {
    const user = userEvent.setup();
    let building = false;
    const { fixtures } = mockApi([
      {
        method: "POST",
        path: "/bundles/block-common/build",
        status: 202,
        body: () => {
          building = true;
          return { queued: true };
        },
      },
      { method: "GET", path: "/bundles/block-common/status", body: () => ({ ...(fixtures["/bundles/block-common/status"] as object), building, status: "failed", error: "out of memory" }) },
    ]);
    renderApp("/bundles/block-common");
    await user.click(await screen.findByRole("button", { name: /Build now/ }, T));
    const progress = await screen.findByLabelText("Build progress", undefined, T);
    expect(within(progress).getByText("queued")).toBeInTheDocument();
    building = false;
    expect(await within(progress).findByText("failed", undefined, { timeout: 6000 })).toBeInTheDocument();
  }, 15000);

  it("Check now shows the check until core's status says it ended, and its feeds' runs from job events", async () => {
    const user = userEvent.setup();
    let checking = true;
    const { fixtures } = mockApi([
      { method: "POST", path: "/feed-providers/hagezi/check", status: 202, body: { result: "started" } },
      { method: "GET", path: "/feed-providers/hagezi/status", body: () => ({ ...(fixtures["/feed-providers/hagezi/status"] as object), checking }) },
      {
        method: "GET",
        path: "/feeds",
        body: () => ({
          items: [...(fixtures["/feeds"] as { items: object[] }).items, { ...(fixtures["/feeds/manual-block"] as object), id: "hagezi-tif", name: "HaGeZi TIF", provider: "hagezi", file: "adblock/tif.txt", system: false }],
          next_cursor: null,
        }),
      },
    ]);
    renderApp("/feed-providers/hagezi");
    const checkNow = await screen.findByRole("button", { name: /Check now/ }, T);
    openSocket();
    await user.click(checkNow);
    const progress = await screen.findByLabelText("Check progress", undefined, T);
    expect(within(progress).getByText("checking")).toBeInTheDocument();
    // A run of another feed isn't the provider's.
    act(() => socket().emit(job("feed_ingest", "manual-block", "start")));
    act(() => socket().emit(job("feed_ingest", "hagezi-tif", "start")));
    expect(await within(progress).findByText("HaGeZi TIF", undefined, T)).toBeInTheDocument();
    expect(within(progress).queryByText("manual-block")).toBeNull();
    checking = false;
    act(() => socket().emit(job("feed_ingest", "hagezi-tif", "end", { ms: 800 })));
    expect(await within(progress).findByText("done in 800 ms", undefined, T)).toBeInTheDocument();
    expect(await within(progress).findByText("check done", undefined, { timeout: 6000 })).toBeInTheDocument();
  }, 15000);
});

describe("F6: Check now's fallback", () => {
  it("doesn't take a status read before the click as the check's end", async () => {
    const user = userEvent.setup();
    let checking = false;
    const { fetchMock, fixtures } = mockApi([
      {
        method: "POST",
        path: "/feed-providers/hagezi/check",
        status: 202,
        body: () => {
          checking = true;
          return { result: "started" };
        },
      },
      { method: "GET", path: "/feed-providers/hagezi/status", body: () => ({ ...(fixtures["/feed-providers/hagezi/status"] as object), checking }) },
    ]);
    renderApp("/feed-providers/hagezi");
    const checkNow = await screen.findByRole("button", { name: /Check now/ }, T);
    await screen.findByText("Trigger", undefined, T);
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    vi.stubGlobal("fetch", async (req: Request) => {
      if (req.method === "GET" && new URL(req.url).pathname.endsWith("/feed-providers/hagezi/status")) await gate;
      return fetchMock(req);
    });
    await user.click(checkNow);
    const progress = await screen.findByLabelText("Check progress", undefined, T);
    await sleep(200);
    expect(within(progress).getByText("checking")).toBeInTheDocument();
    release();
    vi.stubGlobal("fetch", fetchMock);
  });

  it("shows no progress for a check scheduled later", async () => {
    const user = userEvent.setup();
    mockApi([{ method: "POST", path: "/feed-providers/hagezi/check", status: 202, body: { result: "scheduled", at: "2026-11-24T01:00:00Z" } }]);
    renderApp("/feed-providers/hagezi");
    await user.click(await screen.findByRole("button", { name: /Check now/ }, T));
    expect(await screen.findByText(/Scheduled for/, undefined, T)).toBeInTheDocument();
    expect(screen.queryByLabelText("Check progress")).toBeNull();
  });
});

describe("F8: rule policy tooltips are core's descriptions", () => {
  it("shows core's text alone, without the UI's own default and browser-mode lines", async () => {
    const user = userEvent.setup();
    mockApi();
    renderApp("/feeds/manual-block?tab=settings");
    await user.hover(await screen.findByRole("button", { name: "About browser_changes" }, T));
    const tip = await screen.findByRole("tooltip", undefined, T);
    expect(tip.textContent).toBe(fieldDescription("RulePolicy", "browser_changes")!.replace(/`/g, ""));
    expect(tip.textContent).toMatch(/No effect while the feed's browser mode is drop/);
  });
});

describe("F7: device paths with dots", () => {
  it("renders the device view from the path too (bookmarks keep ?key=)", async () => {
    mockApi();
    const { router } = renderApp("/clients/device/192.168.1.20");
    expect(await screen.findByText("192.168.1.20", undefined, T)).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/clients/device/192.168.1.20");
  });
});
