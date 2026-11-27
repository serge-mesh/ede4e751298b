// Review round 3 of the web UI (W1–W8): each test reproduces a final-check reviewer's finding and
// asserts the fixed behaviour, against the stateful mock of core's manual feed (test/manual-core.ts)
// and core's request contract (test/contract.ts).
import * as React from "react";
import { describe, expect, it, vi } from "vitest";
import { act, render, renderHook, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider, QueryObserver } from "@tanstack/react-query";
import { EditorView } from "@codemirror/view";
import { mockApi, mutations, reply, type Call } from "@/test/mock-api";
import { manualCore } from "@/test/manual-core";
import { renderApp } from "@/test/render";
import { invalidateAll } from "@/api/events";
import { StaleSettings, qk, useSaveSettings } from "@/api/queries";
import { QueryView } from "@/components/common/states";
import { EMPTY_SOURCE, HEADER_LINES, HeaderReader, hasSource, importBody, inspectFile, inspectImport, readHeader } from "@/lib/import-file";
import { ImportSource, importNewQuery } from "./feeds";
import { createLine, learn, movedPast, pageWrite, placeable, recordSave } from "./manual-line";

const T = { timeout: 8000 };

interface FakeSocket {
  open: () => void;
  emit: (d: unknown) => void;
}
const socket = () => (globalThis.WebSocket as unknown as { instances: FakeSocket[] }).instances.at(-1)!;
/** The `feed_run` event core sends for a stored run of the mock (its version and save time). */
const runEvent = (core: ReturnType<typeof manualCore>, run: number) => act(() => socket().emit({ type: "feed_run", data: core.event(run) }));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const t = (s: number) => `2026-11-23T10:00:${String(s).padStart(2, "0")}.000000Z`;

function editorView(): EditorView {
  const host = screen.getByTestId("code-editor");
  return EditorView.findFromDOM(host.querySelector(".cm-editor") as HTMLElement)!;
}
async function typeAtEnd(text: string) {
  await screen.findByTestId("code-editor", undefined, T);
  const view = editorView();
  act(() => view.dispatch({ changes: { from: view.state.doc.length, insert: text } }));
}
/** Holds the first request `match` takes until `release()`; the rest go through. */
function holdFirst(fetchMock: (req: Request) => Promise<Response>, match: (req: Request) => boolean, answer?: () => Response) {
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  let held = false;
  vi.stubGlobal("fetch", async (req: Request) => {
    if (!held && match(req)) {
      held = true;
      await gate;
      if (answer) return answer();
    }
    return fetchMock(req);
  });
  return { release: () => release(), held: () => held };
}
const busy = () => new Response(JSON.stringify({ error: { code: "busy", message: "temporary failure" } }), { status: 503, headers: { "content-type": "application/json" } });

describe("W1: a failed refetch never takes away a draft (core.md §12)", () => {
  it("keeps an entity form's draft, says the refresh failed, and Retry keeps it", async () => {
    const user = userEvent.setup();
    let failing = false;
    mockApi([{ method: "GET", path: "/profiles/kids", body: () => (failing ? reply(503, { error: { code: "busy", message: "temporary failure" } }) : { id: "kids", name: "Kids", allow: [], block: [], upstream: "cloudflare" }) }]);
    const { queryClient } = renderApp("/profiles/kids");
    await user.clear(await screen.findByLabelText("Name", undefined, T));
    await user.type(screen.getByLabelText("Name"), "Unsaved profile name");
    failing = true;
    await act(async () => {
      await queryClient.invalidateQueries({ queryKey: qk.entity("profiles", "kids") });
    });
    expect(await screen.findByTestId("refetch-error", undefined, T)).toHaveTextContent("temporary failure");
    expect(screen.queryByTestId("error-state")).toBeNull();
    expect(screen.getByLabelText("Name")).toHaveValue("Unsaved profile name");
    failing = false;
    await user.click(within(screen.getByTestId("refetch-error")).getByRole("button", { name: "Retry" }));
    await waitFor(() => expect(screen.queryByTestId("refetch-error")).toBeNull(), T);
    expect(screen.getByLabelText("Name")).toHaveValue("Unsaved profile name");
  });

  it("keeps text typed while a clean editor's reload downloads when the reload fails, and offers Reload", async () => {
    const core = manualCore();
    const { fetchMock } = mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    await sleep(100);
    const hold = holdFirst(fetchMock, (req) => req.method === "GET" && new URL(req.url).pathname.endsWith("/file"), busy);
    const v = core.append("||elsewhere.example^");
    runEvent(core, core.finishRun(v));
    await waitFor(() => expect(hold.held()).toBe(true), T);
    await typeAtEnd("||my-draft.example^\n");
    await act(async () => hold.release());
    expect(await screen.findByText("The file changed elsewhere", undefined, T)).toBeInTheDocument();
    expect(screen.getByTestId("refetch-error")).toHaveTextContent("temporary failure");
    expect(editorView().state.doc.toString()).toContain("||my-draft.example^");
    // Reload (the admin's choice) takes the other writer's file.
    vi.stubGlobal("fetch", fetchMock);
    await userEvent.setup().click(screen.getByRole("button", { name: /Reload the file/ }));
    await waitFor(() => expect(editorView().state.doc.toString()).toContain("||elsewhere.example^"), T);
  });

  it("keeps the editor's text when the feed's own refetch fails", async () => {
    const core = manualCore();
    let failing = false;
    const { fixtures } = mockApi([...core.routes, { method: "GET", path: "/feeds/manual-block", body: () => (failing ? reply(503, { error: { code: "busy", message: "temporary failure" } }) : fixtures["/feeds/manual-block"]) }]);
    const { queryClient } = renderApp("/feeds/manual-block");
    await typeAtEnd("||draft.example^\n");
    failing = true;
    await act(async () => {
      await queryClient.invalidateQueries({ queryKey: qk.entity("feeds", "manual-block") });
    });
    await sleep(100);
    expect(screen.queryByTestId("error-state")).toBeNull();
    expect(editorView().state.doc.toString()).toContain("||draft.example^");
    expect(screen.getByRole("button", { name: "Save" })).toBeEnabled();
  });

  it("keeps a settings draft when a refetch fails", async () => {
    const user = userEvent.setup();
    let failing = false;
    const { fixtures } = mockApi([{ method: "GET", path: "/settings", body: () => (failing ? reply(503, { error: { code: "busy", message: "temporary failure" } }) : fixtures["/settings"]) }]);
    const { queryClient } = renderApp("/settings?tab=retention");
    const input = await screen.findByLabelText("Metrics", undefined, T);
    await user.clear(input);
    await user.type(input, "6h");
    failing = true;
    await act(async () => {
      await queryClient.invalidateQueries({ queryKey: qk.settings });
    });
    expect(await screen.findByTestId("refetch-error", undefined, T)).toBeInTheDocument();
    expect(screen.getByLabelText("Metrics")).toHaveValue("6h");
  });

  it.each([
    { name: "a feed provider", path: "/feed-providers/hagezi?tab=settings", api: "/feed-providers/hagezi", key: qk.entity("feed-providers", "hagezi") },
    { name: "a bundle", path: "/bundles/block-common?tab=settings", api: "/bundles/block-common", key: qk.entity("bundles", "block-common") },
    { name: "a lookup provider", path: "/lookup-providers/q9?tab=settings", api: "/lookup-providers/q9", key: qk.entity("lookup-providers", "q9"), body: { id: "q9", name: "Quad9", module: "dns", category: "security", config: {} } },
    { name: "an edge", path: "/edges/e-cacc845b?tab=settings", api: "/edges", key: qk.edges },
  ])("keeps $name's form draft when its page's refetch fails", async ({ path, api, key, body }) => {
    const user = userEvent.setup();
    let failing = false;
    const { fixtures } = mockApi([{ method: "GET", path: api, body: () => (failing ? reply(503, { error: { code: "busy", message: "temporary failure" } }) : (body ?? fixtures[api])) }]);
    const { queryClient } = renderApp(path);
    const name = await screen.findByLabelText("Name", undefined, T);
    await user.clear(name);
    await user.type(name, "Draft name");
    failing = true;
    await act(async () => {
      await queryClient.invalidateQueries({ queryKey: key });
    });
    await waitFor(() => expect(queryClient.getQueryState(key)?.status).toBe("error"), T);
    expect(screen.queryByTestId("error-state")).toBeNull();
    expect(screen.getByLabelText("Name")).toHaveValue("Draft name");
  });

  it("keeps an alert shown, with the error, when its refetch fails", async () => {
    let failing = false;
    const alert = { id: 5, kind: "feed_stale", type: "operational", severity: "warning", state: "open", title: "Stale feed", count: 1, dedupe_key: "k", first_seen: "2026-11-23T10:00:00Z", last_seen: "2026-11-23T10:00:00Z", details: {} };
    mockApi([{ method: "GET", path: "/alerts/5", body: () => (failing ? reply(503, { error: { code: "busy", message: "temporary failure" } }) : { alert, history: [] }) }]);
    const { queryClient } = renderApp("/alerts/5");
    expect(await screen.findByText("Stale feed", undefined, T)).toBeInTheDocument();
    failing = true;
    await act(async () => {
      await queryClient.invalidateQueries({ queryKey: qk.alert(5) });
    });
    expect(await screen.findByTestId("refetch-error", undefined, T)).toBeInTheDocument();
    expect(screen.getByText("Stale feed")).toBeInTheDocument();
  });

  it("QueryView keeps what it shows on a failed refetch", () => {
    const refetch = vi.fn();
    render(
      <QueryView query={{ data: "shown", error: new Error("boom"), isPending: false, refetch }}>
        {(d) => <p>{d}</p>}
      </QueryView>,
    );
    expect(screen.getByText("shown")).toBeInTheDocument();
    expect(screen.getByTestId("refetch-error")).toHaveTextContent("boom");
    act(() => screen.getByRole("button", { name: "Retry" }).click());
    expect(refetch).toHaveBeenCalled();
  });
});

describe("W2: a file export's header is read as core reads it, past the head (feeds.md §4)", () => {
  const longComments = Array.from({ length: 5 }, () => "! " + "x".repeat(60000) + "\n").join("");
  const lateHeader = longComments + "! picket-feed-export: 1\n! feed: late-header\n! format: adblock\n! category: security\n||ads.example^\n";

  it("tells an export whose marker is past 256 KiB but within 64 lines, and sends none of its settings", async () => {
    const file = new File([lateHeader], "late-header.txt");
    const info = await inspectFile(file);
    expect(info).toMatchObject({ kind: "list", partial: true });
    const built = await importBody({ file, text: "", info });
    expect(built.kind).toBe("file-export");
    expect(importNewQuery(built.kind, { id: "late-header", name: "", format: "plain", category: "mixed", domainsAs: "exact" })).toEqual({ id: "late-header" });
    // Pasted text the same way.
    expect((await importBody({ file: null, text: lateHeader, info: null })).kind).toBe("file-export");
  });

  it("sends no format or category from the Import dialog for such a file", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([{ method: "POST", path: "/feeds/import", status: 201, body: (c: Call) => ({ feed: c.query.get("id"), created: true, version: "x", changed: true, run_queued: false, entries: null }) }]);
    renderApp("/feeds");
    await user.click(await screen.findByRole("button", { name: /Import…/ }, T));
    const dialog = await screen.findByRole("dialog");
    await user.upload(within(dialog).getByLabelText("File"), new File([lateHeader], "late.txt"));
    expect(await within(dialog).findByText(/Its comment header goes on past them/, undefined, T)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Import" }));
    await waitFor(() => expect(mutations(calls).some((c) => c.path === "/feeds/import")).toBe(true), T);
    expect(Object.fromEntries(mutations(calls).find((c) => c.path === "/feeds/import")!.query)).toEqual({ id: "late" });
  });

  it("still treats a long plain list as one, and a header settled in the head as final", async () => {
    const list = new File(["a.example\n" + "b.example\n".repeat(30000)], "list.txt");
    const l = await inspectFile(list);
    expect([l.kind, l.partial]).toEqual(["list", undefined]);
    const exp = new File(["! picket-feed-export: 1\n! format: hosts\n! category: privacy\n0.0.0.0 a.example\n" + "0.0.0.0 b.example\n".repeat(20000)], "e.txt");
    const e = await inspectFile(exp);
    expect(e).toMatchObject({ kind: "file-export", declared: { format: "hosts", category: "privacy" } });
    expect(e.partial).toBeUndefined();
  });

  it("mirrors core's read_header: 64 lines of any length, Unicode trim, first-seen and blank lines end it", () => {
    const comments = (n: number) => "! c\n".repeat(n);
    expect(readHeader(comments(63) + "! picket-feed-export: 1\n")).not.toBeNull();
    expect(HEADER_LINES).toBe(64);
    expect(readHeader(comments(64) + "! picket-feed-export: 1\n")).toBeNull();
    // A last line without a line break is a line.
    expect(readHeader(comments(63) + "! picket-feed-export: 1")).not.toBeNull();
    expect(readHeader("! picket-first-seen: 2026-01-01\n! picket-feed-export: 1\n")).toBeNull();
    expect(readHeader("! a\n\n! picket-feed-export: 1\n")).toBeNull();
    expect(readHeader("a.example\n! picket-feed-export: 1\n")).toBeNull();
    // Rust's trim: U+0085 is whitespace, U+FEFF isn't.
    expect(readHeader("\u0085# picket-feed-export: 1\n")).not.toBeNull();
    expect(readHeader("﻿# picket-feed-export: 1\n")).toBeNull();
    // Key and value trimmed, split at the first colon, CRLF lines, `#` comments; a key with text after it isn't the key.
    expect(readHeader("#\t picket-feed-export \t: 1\r\n# name:  a: b  \r\n# format_options: {\"x\": 1}\r\n")).toMatchObject({ name: "a: b", format_options: { x: 1 } });
    expect(readHeader("! picket-feed-export-x: 1\n")).toBeNull();
    expect(readHeader("!:picket-feed-export\n")).toBeNull();
    // Any line length: a long value is left out, the rest still read.
    expect(readHeader(`! name: ${"n".repeat(70000)}\n! picket-feed-export: 1\n! format: plain\n`)).toMatchObject({ name: undefined, format: "plain" });
    expect(readHeader(`! ${" ".repeat(100000)}picket-feed-export   ${" ".repeat(70000)}: 1\n`)).not.toBeNull();
  });

  it("reads across chunks, and stops at the end of the header", () => {
    const r = new HeaderReader();
    for (const c of ["!", " picket-fe", "ed-export", ": 1\n! cat", "egory: secu", "rity\nlist.example\n! format: hosts\n"]) r.push(c);
    expect(r.finished).toBe(true);
    r.end();
    expect(r.result()).toMatchObject({ category: "security", format: undefined });
    const open = new HeaderReader();
    open.push("! a\n! b");
    expect(open.finished).toBe(false);
    expect(inspectImport("! a\n! b", false).partial).toBe(true);
    expect(inspectImport("! a\n! b", true).partial).toBeUndefined();
  });
});

describe("W3: the latest chosen file is the one sent", () => {
  function Host() {
    const [source, setSource] = React.useState(EMPTY_SOURCE);
    return (
      <>
        <ImportSource value={source} onChange={setSource} />
        <p data-testid="chosen">{source.file?.name}</p>
        <p data-testid="sendable">{String(hasSource(source))}</p>
      </>
    );
  }
  /** A file whose head read waits for `release`. */
  function slowFile(name: string) {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const f = new File(["a.example"], name);
    const slice = f.slice.bind(f);
    vi.spyOn(f, "slice").mockImplementation((...args) => {
      const b = slice(...args);
      const text = b.text.bind(b);
      vi.spyOn(b, "text").mockImplementation(async () => {
        await gate;
        return text();
      });
      return b;
    });
    return { f, release: () => release() };
  }

  it("ignores an earlier file's inspection that ends after a later choice's", async () => {
    const user = userEvent.setup();
    const a = slowFile("first.txt");
    render(<Host />);
    await user.upload(screen.getByLabelText("File"), a.f);
    await user.upload(screen.getByLabelText("File"), new File(["b.example"], "second.txt"));
    await waitFor(() => expect(screen.getByTestId("chosen")).toHaveTextContent("second.txt"), T);
    await act(async () => {
      a.release();
      await sleep(10);
    });
    expect(screen.getByTestId("chosen")).toHaveTextContent("second.txt");
    expect(screen.getByTestId("sendable")).toHaveTextContent("true");
  });

  it("can't send the previous file while the next one is being read", async () => {
    const user = userEvent.setup();
    render(<Host />);
    await user.upload(screen.getByLabelText("File"), new File(["a.example"], "first.txt"));
    await waitFor(() => expect(screen.getByTestId("sendable")).toHaveTextContent("true"), T);
    const b = slowFile("second.txt");
    await user.upload(screen.getByLabelText("File"), b.f);
    expect(screen.getByTestId("chosen")).toHaveTextContent("second.txt");
    expect(screen.getByTestId("sendable")).toHaveTextContent("false");
    await act(async () => {
      b.release();
      await sleep(10);
    });
    expect(screen.getByTestId("sendable")).toHaveTextContent("true");
  });
});

describe("W3: the reading note follows the latest choice", () => {
  it("keeps saying it reads while the latest file is still being read, and stops when the choice is cleared", async () => {
    const user = userEvent.setup();
    const gates: (() => void)[] = [];
    const slow = (name: string) => {
      const f = new File(["a.example"], name);
      const slice = f.slice.bind(f);
      let open!: () => void;
      const gate = new Promise<void>((r) => (open = r));
      gates.push(() => open());
      vi.spyOn(f, "slice").mockImplementation((...args) => {
        const b = slice(...args);
        const text = b.text.bind(b);
        vi.spyOn(b, "text").mockImplementation(async () => {
          await gate;
          return text();
        });
        return b;
      });
      return f;
    };
    function Host() {
      const [source, setSource] = React.useState(EMPTY_SOURCE);
      return <ImportSource value={source} onChange={setSource} />;
    }
    render(<Host />);
    await user.upload(screen.getByLabelText("File"), slow("first.txt"));
    await user.upload(screen.getByLabelText("File"), slow("second.txt"));
    await act(async () => {
      gates[0]();
      await sleep(10);
    });
    expect(screen.getByText("Reading the file…")).toBeInTheDocument();
    await act(async () => {
      gates[1]();
      await sleep(10);
    });
    expect(screen.queryByText("Reading the file…")).toBeNull();
    await user.upload(screen.getByLabelText("File"), slow("third.txt"));
    expect(screen.getByText("Reading the file…")).toBeInTheDocument();
    await user.upload(screen.getByLabelText("File"), []);
    expect(screen.queryByText("Reading the file…")).toBeNull();
  });
});

describe("W4: the page's line of saves stays small and lives with the page", () => {
  it("holds only the newest save, however many saves get no run (e.g. a disabled feed's)", () => {
    const l = createLine();
    learn(l, { version: "v0", at: t(0) });
    for (let i = 1; i <= 40; i++) recordSave(l, { version: `v${i}`, at: t(i), content: null });
    expect(l.newest).toEqual({ version: "v40", at: t(40) });
    // Older saves still read as older: the known time decides.
    expect(learn(l, { version: "x", at: t(0) })).toBe(false);
    expect(Object.keys(l).sort()).toEqual(["era", "listeners", "newest", "rechecks", "recorded", "restores", "writes"]);
    expect(l.recorded).toBe(40);
  });

  it("starts a new line for each page (no state shared between pages or tests)", () => {
    const a = createLine();
    learn(a, { version: "a", at: t(1) });
    expect(createLine().newest).toBeNull();
  });
});

describe("W5: a save that lands after its editor closed (a tab switch) reaches the editor open then", () => {
  it("shows the saved text, its version and run, and the next save is based on it", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    const v0 = core.st.version;
    const { fetchMock, calls } = mockApi(core.routes);
    const hold = holdFirst(fetchMock, (req) => req.method === "PUT" && new URL(req.url).pathname.endsWith("/file"));
    renderApp("/feeds/manual-block");
    await typeAtEnd("||mine.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(hold.held()).toBe(true), T);
    await user.click(screen.getByRole("tab", { name: "Status" }));
    await sleep(100);
    await user.click(screen.getByRole("tab", { name: "File" }));
    await screen.findByTestId("code-editor", undefined, T);
    await act(async () => hold.release());
    await waitFor(() => expect(core.st.content).toContain("||mine.example^"), T);
    const v1 = core.st.version;
    await waitFor(() => expect(editorView().state.doc.toString()).toContain("||mine.example^"), T);
    expect(screen.getByText(v1)).toBeInTheDocument();
    // The save's text came with it: the file isn't read again.
    expect(core.st.fileReads).toBe(1);
    expect(await screen.findByText(/Waiting for the run's result/, undefined, T)).toBeInTheDocument();
    const run = core.finishRun();
    runEvent(core, run);
    expect(await screen.findByText(`Run ${run}`, undefined, T)).toBeInTheDocument();
    expect(screen.queryByText(/Core made no new run/)).toBeNull();
    expect(screen.queryByText("The file changed elsewhere")).toBeNull();
    await typeAtEnd("||more.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(core.st.content).toContain("||more.example^"), T);
    expect(mutations(calls).filter((c) => c.method === "PUT").map((c) => (c.body as { base_version: string }).base_version)).toEqual([v0, v1]);
    expect(screen.queryByText("The file changed since you opened it")).toBeNull();
  }, 20000);

  it("an editor whose save is out stays open over a tab switch (its draft: polish V1): the save lands as its own, and text typed after it stays", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    const { fetchMock } = mockApi(core.routes);
    const hold = holdFirst(fetchMock, (req) => req.method === "PUT" && new URL(req.url).pathname.endsWith("/file"));
    renderApp("/feeds/manual-block");
    await typeAtEnd("||mine.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(hold.held()).toBe(true), T);
    const editor = editorView();
    await user.click(screen.getByRole("tab", { name: "Status" }));
    await sleep(100);
    await user.click(screen.getByRole("tab", { name: "File" }));
    expect(editorView()).toBe(editor);
    await typeAtEnd("||typed-after.example^\n");
    await act(async () => hold.release());
    await waitFor(() => expect(screen.getByText(core.st.version)).toBeInTheDocument(), T);
    expect(core.st.fileReads).toBe(1);
    expect(screen.queryByText("The file changed elsewhere")).toBeNull();
    expect(editorView().state.doc.toString()).toContain("||typed-after.example^");
  }, 20000);
});

describe("W5: the page's writes in flight", () => {
  /** Answers the first request `match` takes at once (core's state changes then) but delivers it on `release()`. */
  function delayFirst(fetchMock: (req: Request) => Promise<Response>, match: (req: Request) => boolean) {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let held = false;
    vi.stubGlobal("fetch", async (req: Request) => {
      if (held || !match(req)) return fetchMock(req);
      held = true;
      const res = await fetchMock(req);
      await gate;
      return res;
    });
    return { release: () => release(), held: () => held };
  }
  const isFile = (method: string) => (req: Request) => req.method === method && new URL(req.url).pathname.endsWith("/file");

  it("doesn't take a run of a save still in flight as another writer's", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    const { fetchMock } = mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await typeAtEnd("||mine.example^\n");
    await sleep(50);
    const put = delayFirst(fetchMock, isFile("PUT"));
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(put.held()).toBe(true), T);
    // core stored the save and its run ended before the save's answer reached the page.
    const run = core.finishRun();
    runEvent(core, run);
    await sleep(300);
    expect(screen.queryByText("The file changed elsewhere")).toBeNull();
    await act(async () => put.release());
    expect(await screen.findByText(`Run ${run}`, undefined, T)).toBeInTheDocument();
    expect(screen.queryByText("The file changed elsewhere")).toBeNull();
    expect(screen.queryByText(/changed again/)).toBeNull();
  });

  it("doesn't take a file read that overlapped a save as another writer's save", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    const { fetchMock, calls } = mockApi(core.routes);
    const { queryClient } = renderApp("/feeds/manual-block");
    await typeAtEnd("||one.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    const v1 = core.st.version;
    await typeAtEnd("||two.example^\n");
    const put = delayFirst(fetchMock, isFile("PUT"));
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(put.held()).toBe(true), T);
    // A read of the file starts while the save is in flight, answered before core stored it (v1)
    // and delivered after the save landed.
    vi.stubGlobal("fetch", async (req: Request) => {
      if (isFile("GET")(req)) {
        const res = new Response(JSON.stringify({ version: v1, content: "||original.example^\n||one.example^\n", saved_at: core.st.saves[1].at, size: 1 }), { headers: { "content-type": "application/json" } });
        await sleep(300);
        return res;
      }
      return fetchMock(req);
    });
    void queryClient.refetchQueries({ queryKey: qk.manualFile("manual-block") });
    await sleep(50);
    await act(async () => put.release());
    await sleep(600);
    vi.stubGlobal("fetch", fetchMock);
    expect(editorView().state.doc.toString()).toContain("||two.example^");
    expect(screen.queryByText("The file changed elsewhere")).toBeNull();
    await typeAtEnd("||three.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(core.st.content).toContain("||three.example^"), T);
    expect(screen.queryByText("The file changed since you opened it")).toBeNull();
    expect(mutations(calls).filter((c) => c.method === "PUT")).toHaveLength(3);
  });

  it("doesn't take a file read that a save started during as another writer's save", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    const { fetchMock } = mockApi(core.routes);
    const { queryClient } = renderApp("/feeds/manual-block");
    await typeAtEnd("||one.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    // A read starts (no write in flight) and core answers it with v1 at once; it is delivered
    // after the next save, started meanwhile, landed.
    const answer = JSON.stringify({ version: core.st.version, content: core.st.content, saved_at: core.st.savedAt, size: 1 });
    let deliver!: () => void;
    const delivered = new Promise<void>((r) => (deliver = r));
    vi.stubGlobal("fetch", async (req: Request) => {
      if (isFile("GET")(req)) {
        await delivered;
        return new Response(answer, { headers: { "content-type": "application/json" } });
      }
      return fetchMock(req);
    });
    void queryClient.refetchQueries({ queryKey: qk.manualFile("manual-block") });
    await sleep(50);
    await typeAtEnd("||two.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(core.st.content).toContain("||two.example^"), T);
    await sleep(100);
    await act(async () => deliver());
    await sleep(300);
    vi.stubGlobal("fetch", fetchMock);
    expect(editorView().state.doc.toString()).toContain("||two.example^");
    expect(screen.queryByText("The file changed elsewhere")).toBeNull();
  });

  it("keeps text typed while its save is in flight, unsaved", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    const { fetchMock } = mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await typeAtEnd("||sent.example^\n");
    const hold = holdFirst(fetchMock, isFile("PUT"));
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(hold.held()).toBe(true), T);
    await typeAtEnd("||typed-meanwhile.example^\n");
    await act(async () => hold.release());
    await waitFor(() => expect(core.st.content).toContain("||sent.example^"), T);
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    expect(editorView().state.doc.toString()).toContain("||typed-meanwhile.example^");
    expect(core.st.content).not.toContain("||typed-meanwhile.example^");
    expect(screen.getByRole("button", { name: "Save" })).toBeEnabled();
    expect(screen.queryByText("The file changed elsewhere")).toBeNull();
  });
});

describe("W5: what an editor opens on", () => {
  it("opens on a file whose run hasn't ended without reading it again or calling it another writer's", async () => {
    const core = manualCore();
    // Saved elsewhere; its run hasn't ended, so the newest run is of an earlier text.
    core.append("||saved.example^");
    mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    await sleep(500);
    expect(core.st.fileReads).toBe(1);
    expect(screen.queryByText("The file changed elsewhere")).toBeNull();
  });

  it("takes the file when its cache is older than a save the page saw", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    const { calls } = mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    await sleep(50);
    await typeAtEnd("||draft.example^\n");
    const v = core.append("||elsewhere.example^");
    runEvent(core, core.finishRun(v));
    expect(await screen.findByText("The file changed elsewhere", undefined, T)).toBeInTheDocument();
    // The draft dropped, another tab and back: the editor opens on the cached (older) file, then
    // takes the new one. (A draft keeps the editor open over a tab switch: polish V1.)
    await user.click(screen.getByRole("button", { name: "Discard" }));
    await user.click(screen.getByRole("tab", { name: "Status" }));
    await user.click(screen.getByRole("tab", { name: "File" }));
    await waitFor(() => expect(editorView().state.doc.toString()).toContain("||elsewhere.example^"), T);
    await typeAtEnd("||mine.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(core.st.content).toContain("||mine.example^"), T);
    expect((mutations(calls).filter((c) => c.method === "PUT").at(-1)!.body as { base_version: string }).base_version).toBe(v);
  });

  it("doesn't show the banner again after Keep editing", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    await sleep(50);
    await typeAtEnd("||draft.example^\n");
    const run = core.finishRun(core.append("||elsewhere.example^"));
    runEvent(core, run);
    await user.click(await screen.findByRole("button", { name: "Keep editing" }, T));
    expect(screen.queryByText("The file changed elsewhere")).toBeNull();
    // The runs are read again (another event): the same save isn't news.
    runEvent(core, run);
    act(() => socket().emit({ type: "lagged", data: null }));
    await sleep(500);
    expect(screen.queryByText("The file changed elsewhere")).toBeNull();
    expect(editorView().state.doc.toString()).toContain("||draft.example^");
  });
});

describe("W6: another writer's save of an earlier text of the page isn't taken as the page's", () => {
  it("ends the wait with that run, reloads the clean editor, and the next save is based on the file", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    const { calls } = mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await typeAtEnd("||one.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    const v1text = core.st.content;
    await typeAtEnd("||two.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(core.st.content).toContain("||two.example^"), T);
    // Another writer puts the first save's text back before any run starts; the queued run reads it.
    const v1 = core.save(v1text);
    const run = core.finishRun(v1);
    runEvent(core, run);
    expect(await screen.findByText(/changed again before this save's run started/, undefined, T)).toBeInTheDocument();
    expect(screen.getByText(`Run ${run}`)).toBeInTheDocument();
    expect(screen.queryByText(/Core is idle and has stored no run/)).toBeNull();
    await waitFor(() => expect(editorView().state.doc.toString()).toBe(v1text), T);
    await typeAtEnd("||three.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(core.st.content).toContain("||three.example^"), T);
    expect((mutations(calls).filter((c) => c.method === "PUT").at(-1)!.body as { base_version: string }).base_version).toBe(v1);
  }, 20000);

  it("tells a run of the page's own earlier save by its time, without reading the file (F3)", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await typeAtEnd("||one.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    const v1 = core.st.version;
    await typeAtEnd("||two.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(core.st.content).toContain("||two.example^"), T);
    // v1's run was in flight; v2's couldn't start yet (the heavy lane was full).
    const early = core.finishRun(v1);
    core.st.busy = false;
    core.st.retryAt = "2026-11-23T10:01:30.000000Z";
    runEvent(core, early);
    expect(await screen.findByText(/Core tries it again at/, undefined, T)).toBeInTheDocument();
    // The save time told whose run it was: no file read.
    expect(core.st.fileReads).toBe(1);
    expect(screen.queryByText(`Run ${early}`)).toBeNull();
    expect(screen.queryByText("The file changed elsewhere")).toBeNull();
    const mine = core.finishRun();
    runEvent(core, mine);
    expect(await screen.findByText(`Run ${mine}`, undefined, T)).toBeInTheDocument();
    expect(screen.queryByText(/changed again/)).toBeNull();
  }, 20000);

  it("places a run or read that may be of a write in flight only once the write landed", async () => {
    const l = createLine();
    learn(l, { version: "a", at: t(1) });
    let land!: (r: { version: string; at: string }) => void;
    const write = pageWrite(
      l,
      () => new Promise<{ version: string; at: string }>((r) => (land = r)),
      (r) => recordSave(l, { version: r.version, at: r.at, content: null }),
    );
    // While it is in flight, a read showing its save can't be told from another writer's.
    expect(placeable(l)).toBe(false);
    land({ version: "b", at: t(2) });
    await write;
    expect(placeable(l)).toBe(true);
    // Placed afterwards by time: the write's own save, or an older one, moves nothing.
    expect(learn(l, { version: "b", at: t(2) })).toBe(false);
    expect(learn(l, { version: "a", at: t(1) })).toBe(false);
    expect(movedPast(l, t(2))).toBe(false);
  });
});

describe("W7: a missed or one-click change marks a closed editor's file stale", () => {
  it("marks it stale on a reconnect or lagged stream, without reading it; an open one isn't touched", () => {
    const qc = new QueryClient();
    qc.setQueryData(qk.manualFile("closed"), { version: "a" });
    qc.setQueryData(qk.manualFile("open"), { version: "b" });
    const read = vi.fn(() => new Promise<never>(() => {}));
    const stop = new QueryObserver(qc, { queryKey: qk.manualFile("open"), queryFn: read, staleTime: Infinity }).subscribe(() => {});
    invalidateAll(qc);
    expect(qc.getQueryState(qk.manualFile("closed"))).toMatchObject({ isInvalidated: true, fetchStatus: "idle" });
    expect(qc.getQueryState(qk.manualFile("open"))?.isInvalidated).toBe(false);
    expect(read).not.toHaveBeenCalled();
    stop();
  });

  it("marks manual-block stale after an alert's Add to manual block feed", async () => {
    const user = userEvent.setup();
    const alert = { id: 5, kind: "category_answered", type: "security", severity: "warning", state: "open", title: "Category answered", count: 1, dedupe_key: "k", first_seen: "2026-11-23T10:00:00Z", last_seen: "2026-11-23T10:00:00Z", details: { domain: "bad.example" } };
    const { calls } = mockApi([
      { method: "GET", path: "/alerts/5", body: { alert, history: [] } },
      { method: "POST", path: "/feeds/manual-block/file/lines", body: { version: "x", changed: true } },
    ]);
    const { queryClient } = renderApp("/alerts/5");
    queryClient.setQueryData(qk.manualFile("manual-block"), { version: "a", content: "", saved_at: "2026-11-23T10:00:00Z", size: 0 });
    queryClient.setQueryData(qk.feedStatus, []);
    await user.click(await screen.findByRole("button", { name: /Add to manual block feed/ }, T));
    await user.click(await screen.findByRole("button", { name: "Add" }));
    await waitFor(() => expect(mutations(calls).some((c) => c.path === "/feeds/manual-block/file/lines")).toBe(true), T);
    await waitFor(() => expect(queryClient.getQueryState(qk.manualFile("manual-block"))?.isInvalidated).toBe(true), T);
    expect(queryClient.getQueryState(qk.feedStatus)?.isInvalidated).toBe(true);
  });
});

describe("W8: a settings save never reverts a section changed elsewhere (api.md §7: no version check)", () => {
  function settingsCore(fixtures: Record<string, unknown>) {
    const st = structuredClone(fixtures["/settings"]) as { settings: Record<string, Record<string, unknown>> };
    return {
      st,
      routes: [
        { method: "GET", path: "/settings", body: () => structuredClone(st) },
        {
          method: "PUT",
          path: "/settings",
          body: (c: Call) => {
            // core writes every leaf the patch names (settings.rs apply_patch).
            for (const [k, v] of Object.entries(c.body as Record<string, Record<string, unknown>>)) st.settings[k] = { ...st.settings[k], ...v };
            return {};
          },
        },
      ],
    };
  }

  it("re-reads the settings in its turn and sends nothing when a section it covers changed; Keep my changes keeps both", async () => {
    const user = userEvent.setup();
    const fx = mockApi().fixtures;
    const core = settingsCore(fx);
    const { calls } = mockApi(core.routes);
    renderApp("/settings?tab=retention");
    const input = await screen.findByLabelText("Metrics", undefined, T);
    await user.clear(input);
    await user.type(input, "6h");
    // Another admin saves another leaf of the same section; no event tells this page.
    core.st.settings.retention.query_logs = "1d";
    // The save's own read answers; the refetch after it is held: the refusal itself says so.
    const live = globalThis.fetch;
    let reads = 0;
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    vi.stubGlobal("fetch", async (req: Request) => {
      if (req.method === "GET" && new URL(req.url).pathname.endsWith("/settings") && ++reads > 1) await held;
      return live(req);
    });
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("These settings changed elsewhere", undefined, T)).toBeInTheDocument();
    expect(mutations(calls)).toHaveLength(0);
    release();
    vi.stubGlobal("fetch", live);
    expect(screen.getByLabelText("Metrics")).toHaveValue("6h");
    await user.click(screen.getByRole("button", { name: "Keep my changes" }));
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(mutations(calls)).toHaveLength(1), T);
    expect(core.st.settings.retention).toMatchObject({ metrics: "6h", query_logs: "1d" });
  });

  it("queues the page's settings saves, so the second re-reads after the first landed", async () => {
    const fx = mockApi().fixtures;
    const core = settingsCore(fx);
    const { calls } = mockApi(core.routes);
    const qc = new QueryClient();
    const { result } = renderHook(() => useSaveSettings(), { wrapper: ({ children }) => <QueryClientProvider client={qc}>{children}</QueryClientProvider> });
    const base = structuredClone(core.st.settings) as never;
    const first = result.current.mutateAsync({ patch: { retention: { metrics: "6h" } }, check: { base, keys: ["retention"] } });
    const second = result.current.mutateAsync({ patch: { retention: { metrics: "12h" } }, check: { base, keys: ["retention"] } });
    await first;
    await expect(second).rejects.toBeInstanceOf(StaleSettings);
    expect(mutations(calls)).toHaveLength(1);
    expect(core.st.settings.retention.metrics).toBe("6h");
  });

  it("saves when only sections it doesn't cover changed", async () => {
    const user = userEvent.setup();
    const fx = mockApi().fixtures;
    const core = settingsCore(fx);
    const { calls } = mockApi(core.routes);
    renderApp("/settings?tab=retention");
    const input = await screen.findByLabelText("Metrics", undefined, T);
    await user.clear(input);
    await user.type(input, "6h");
    core.st.settings.dnssec.enabled = false;
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(mutations(calls)).toHaveLength(1), T);
    expect(Object.keys(mutations(calls)[0].body as object)).toEqual(["retention"]);
    expect(core.st.settings.dnssec.enabled).toBe(false);
    expect(screen.queryByText("These settings changed elsewhere")).toBeNull();
  });
});
