// Review round 2 of the web UI (V1–V12): each test reproduces a re-check reviewer's finding and
// asserts the fixed behaviour, against stateful mocks of core (test/manual-core.ts: a version is a
// hash of the text, a run carries its save's time) and core's request contract (test/contract.ts).
import { W5, captured } from "@/test/core-w5";
import { describe, expect, it, vi } from "vitest";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryObserver } from "@tanstack/react-query";
import { EditorView } from "@codemirror/view";
import { mockApi, mutations, reply, type Call } from "@/test/mock-api";
import { manualCore } from "@/test/manual-core";
import { feedRunFrame } from "@/test/events";
import { renderApp } from "@/test/render";
import { applyEvent, invalidateAll } from "@/api/events";
import { qk } from "@/api/queries";
import { contractViolations } from "@/test/contract";
import { ruleSafe } from "@/components/common/append-rule";
import { TopLevelKeys, importBody, inspectFile, withoutBom } from "@/lib/import-file";
import { COUPLED_FIELDS, mergeKeepingMine } from "@/lib/merge";
import { entryName } from "./feed-detail";
import { createLine, learn, movedPast, recordSave, timeOrder } from "./manual-line";

const T = { timeout: 8000 };

interface FakeSocket {
  open: () => void;
  emit: (d: unknown) => void;
}
const socket = () => (globalThis.WebSocket as unknown as { instances: FakeSocket[] }).instances.at(-1)!;
/** The `feed_run` event core sends for a stored run of the mock (its version and save time). */
const runEvent = (core: ReturnType<typeof manualCore>, run: number) => act(() => socket().emit({ type: "feed_run", data: core.event(run) }));

function editorView(): EditorView {
  const host = screen.getByTestId("code-editor");
  return EditorView.findFromDOM(host.querySelector(".cm-editor") as HTMLElement)!;
}
async function typeAtEnd(text: string) {
  await screen.findByTestId("code-editor", undefined, T);
  const view = editorView();
  act(() => view.dispatch({ changes: { from: view.state.doc.length, insert: text } }));
}
function replaceText(text: string) {
  const view = editorView();
  act(() => view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: text } }));
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Holds the first request `match` takes until `release()`; the rest go through. */
function holdFirst(fetchMock: (req: Request) => Promise<Response>, match: (req: Request) => boolean) {
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  let held = false;
  vi.stubGlobal("fetch", async (req: Request) => {
    if (!held && match(req)) {
      held = true;
      await gate;
    }
    return fetchMock(req);
  });
  return { release: () => release(), held: () => held };
}
const isPut = (path: string) => (req: Request) => req.method === "PUT" && new URL(req.url).pathname.endsWith(path);

function profileCore() {
  let profile: Record<string, unknown> = { id: "kids", name: "Kids", allow: [], block: ["block-common"], trial_bundles: ["trial-x"], upstream: "cloudflare" };
  return {
    get: () => profile,
    routes: [
      { method: "GET", path: "/profiles/kids", body: () => profile },
      {
        method: "PUT",
        path: "/profiles/kids",
        body: (c: Call) => {
          profile = c.body as Record<string, unknown>;
          return { id: "kids", entity: profile, warnings: [] };
        },
      },
    ],
  };
}

describe("V1: every write to an entity goes through its write queue (api.md §7: no version check)", () => {
  it("runs Enforce after a form save still in flight, so neither undoes the other", async () => {
    const user = userEvent.setup();
    const core = profileCore();
    const { fetchMock } = mockApi(core.routes);
    const hold = holdFirst(fetchMock, isPut("/profiles/kids"));
    renderApp("/profiles/kids");
    const name = await screen.findByLabelText("Name", undefined, T);
    await user.clear(name);
    await user.type(name, "Kids renamed");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(hold.held()).toBe(true), T);
    await user.click(screen.getByRole("button", { name: "Enforce" }));
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Enforce" }));
    // Enforce waits its turn: it reads the profile only after the save's PUT landed.
    await sleep(200);
    expect(core.get().trial_bundles).toEqual(["trial-x"]);
    await act(async () => hold.release());
    await waitFor(() => expect(core.get().trial_bundles).toEqual([]), T);
    expect(core.get()).toMatchObject({ name: "Kids renamed", block: ["block-common", "trial-x"], trial_bundles: [] });
  });

  it("sends a form save queued behind an action only if the entity is still its base; else it says it changed", async () => {
    const user = userEvent.setup();
    const core = profileCore();
    const { calls, fetchMock } = mockApi(core.routes);
    const hold = holdFirst(fetchMock, isPut("/profiles/kids"));
    renderApp("/profiles/kids");
    await user.click(await screen.findByRole("button", { name: "Enforce" }, T));
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Enforce" }));
    await waitFor(() => expect(hold.held()).toBe(true), T);
    const name = screen.getByLabelText("Name");
    await user.clear(name);
    await user.type(name, "Kids renamed");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await act(async () => hold.release());
    expect(await screen.findByText("This profile changed elsewhere", undefined, T)).toBeInTheDocument();
    // Only Enforce reached core: the form's body, edited from the profile before it, didn't.
    expect(mutations(calls).filter((c) => c.method === "PUT")).toHaveLength(1);
    expect(core.get()).toMatchObject({ name: "Kids", block: ["block-common", "trial-x"], trial_bundles: [] });
    expect(screen.getByLabelText("Name")).toHaveValue("Kids renamed");
    await user.click(screen.getByRole("button", { name: "Keep my changes" }));
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(core.get().name).toBe("Kids renamed"), T);
    expect(core.get()).toMatchObject({ block: ["block-common", "trial-x"], trial_bundles: [] });
  });
});

describe("V2: a clean editor's automatic reload applies only to the text it started from", () => {
  it("keeps text typed while the reload downloads, and says the file changed", async () => {
    const core = manualCore();
    const { fetchMock } = mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    await sleep(50);
    const hold = holdFirst(fetchMock, (req) => req.method === "GET" && new URL(req.url).pathname.endsWith("/file"));
    const v = core.append("||elsewhere.example^");
    runEvent(core, core.finishRun(v));
    await waitFor(() => expect(hold.held()).toBe(true), T);
    await typeAtEnd("||draft-during-download.example^\n");
    await act(async () => hold.release());
    expect(await screen.findByText("The file changed elsewhere", undefined, T)).toBeInTheDocument();
    expect(screen.getByText(v)).toBeInTheDocument();
    expect(editorView().state.doc.toString()).toContain("||draft-during-download.example^");
    expect(editorView().state.doc.toString()).not.toContain("||elsewhere.example^");
    expect(screen.getByRole("button", { name: "Save" })).toBeEnabled();
  });
});

describe("V3: the wait ends with this save's run or a later save's, by core's save time (feeds.md §1)", () => {
  it("keeps waiting when a run of an older save, in flight before this save, ends after it", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    // v1 and v2 were saved; v1's run is still in flight, and the editor opens on v2.
    const v1 = core.append("||first.example^");
    core.append("||already-saved.example^");
    mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await typeAtEnd("||mine.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    const v3 = core.st.version;
    const old = core.finishRun(v1);
    runEvent(core, old);
    await sleep(300);
    expect(screen.queryByText(`Run ${old}`)).toBeNull();
    expect(screen.getByText(/Waiting for the run's result/)).toBeInTheDocument();
    const mine = core.finishRun(v3);
    runEvent(core, mine);
    expect(await screen.findByText(`Run ${mine}`, undefined, T)).toBeInTheDocument();
    expect(screen.queryByText(/changed again before this save's run/)).toBeNull();
  });

  it("doesn't take an earlier run of a text that comes back as this save's run", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    const x0 = core.st.version;
    // One read of the runs fails (a blip) when the revert is saved: nothing may depend on it.
    let failRuns = false;
    mockApi([
      {
        method: "GET",
        path: "/feeds/manual-block/runs",
        body: (c: Call) => {
          if (failRuns) {
            failRuns = false;
            return reply(503, { error: { code: "busy", message: "try again later" } });
          }
          return { items: core.st.runs.slice(0, Number(c.query.get("limit") ?? 50)), next_cursor: null };
        },
      },
      ...core.routes,
    ]);
    renderApp("/feeds/manual-block");
    await typeAtEnd("||one.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    const r1 = core.finishRun();
    runEvent(core, r1);
    expect(await screen.findByText(`Run ${r1}`, undefined, T)).toBeInTheDocument();
    // Back to the original text: version x0 again, whose earlier run (7) is in the list.
    replaceText("||original.example^\n");
    failRuns = true;
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(core.st.version).toBe(x0), T);
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    runEvent(core, 7);
    await sleep(300);
    expect(screen.queryByText("Run 7")).toBeNull();
    const r2 = core.finishRun(x0);
    runEvent(core, r2);
    expect(await screen.findByText(`Run ${r2}`, undefined, T)).toBeInTheDocument();
  });

  it("notices another writer's save of a text the editor saw before", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    const x0 = core.st.version;
    mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await typeAtEnd("||one.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    runEvent(core, core.finishRun());
    await screen.findByText(/^Run \d+$/, undefined, T);
    // Another writer puts the original text back after the editor's save.
    core.save("||original.example^\n");
    runEvent(core, core.finishRun(x0));
    await waitFor(() => expect(editorView().state.doc.toString()).toBe("||original.example^\n"), T);
    expect(screen.getByText(x0)).toBeInTheDocument();
  });

  it("places saves by time, not by version (learn)", () => {
    const t = (s: number) => `2026-11-23T10:00:0${s}.000000Z`;
    // Read a at t1, then the page saved b and a again (manual-line.ts).
    const line = createLine();
    learn(line, { version: "a", at: t(1) });
    recordSave(line, { version: "b", at: t(2), content: null });
    recordSave(line, { version: "a", at: t(3), content: null });
    // A run of the first a: the same text, an earlier save.
    expect(learn(line, { version: "a", at: t(1) })).toBe(false);
    expect(learn(line, { version: "b", at: t(2) })).toBe(false);
    expect(line.newest).toEqual({ version: "a", at: t(3) });
    expect(movedPast(line, t(3))).toBe(false);
    // Another writer's save of b after the page's newest.
    expect(learn(line, { version: "b", at: t(4) })).toBe(true);
    expect(movedPast(line, t(3))).toBe(true);
    expect(timeOrder("2026-11-23T10:00:00.000001Z", "2026-11-23T10:00:00.000002Z")).toBe(-1);
    expect(timeOrder(null, "2026-11-23T10:00:00Z")).toBe(-1);
  });
});

describe("V4: an import never sends a setting a file might declare past its head (feeds.md §4)", () => {
  const list = Array.from({ length: 22000 }, (_, i) => `name${i}.example`);
  const misp = (extra: Record<string, unknown> = {}) => new File([JSON.stringify({ name: "Threats", type: "hostname", list, ...extra })], "threats.json");
  const importRoute = { method: "POST", path: "/feeds/import", status: 201, body: (c: Call) => ({ feed: c.query.get("id"), created: true, version: "x", changed: true, run_queued: false, entries: null }) };

  async function importNew(file: File) {
    const user = userEvent.setup();
    const { calls } = mockApi([importRoute]);
    renderApp("/feeds");
    await user.click(await screen.findByRole("button", { name: /Import…/ }, T));
    const dialog = await screen.findByRole("dialog");
    await user.upload(within(dialog).getByLabelText("File"), file);
    await within(dialog).findByText(/Only the file's first/, undefined, T);
    await user.click(within(dialog).getByRole("button", { name: "Import" }));
    await waitFor(() => expect(mutations(calls).some((c) => c.path === "/feeds/import")).toBe(true), T);
    return Object.fromEntries(mutations(calls).find((c) => c.path === "/feeds/import")!.query);
  }

  it("reads a picket_feed after a long list while sending, and sends none of the export's settings", async () => {
    const file = misp({ picket_feed: { id: "threats", format: "misp-warninglist", category: "security", name: "Threats" } });
    expect((await inspectFile(file)).kind).toBe("misp-list");
    expect(await importNew(file)).toEqual({ id: "threats" });
  });

  it("still sends the category for a long MISP list without picket_feed", async () => {
    expect(await importNew(misp())).toEqual({ id: "threats", category: "mixed" });
  });

  it("reads top-level keys across chunks, escapes and nesting", async () => {
    const k = new TopLevelKeys();
    for (const c of ['{"list":["picket_feed",{"picket_feed":1}],"na', 'me":"x","pi', "cket\\u005ffe", 'ed":{"a":"}"}}']) k.push(c);
    // Only what tells the kind is kept (J3): the first key, then picket_feed and list as they appear.
    expect(k.keys).toEqual(["list", "picket_feed"]);
    expect(k.kind()).toBe("misp-export");
    const split = new TopLevelKeys();
    for (const c of ['{"picket_f', "eed\u005fexp", 'ort":1,"list":[]}']) split.push(c);
    expect(split.kind()).toBe("json-export");
    const small = new File([JSON.stringify({ list: ["a"], picket_feed: { category: "security" } })], "s.json");
    const info = await inspectFile(small);
    expect(info).toMatchObject({ kind: "misp-export" });
    expect(info.partial).toBeUndefined();
    expect((await importBody({ file: small, text: "", info })).kind).toBe("misp-export");
  });
});

describe("V5: an import into a manual feed sends a fresh base_version", () => {
  async function importOnce(user: ReturnType<typeof userEvent.setup>) {
    await user.click(screen.getByRole("button", { name: /Import…/ }));
    const dialog = await screen.findByRole("dialog");
    await user.upload(within(dialog).getByLabelText("File"), new File(["ads.example\n"], "l.txt"));
    await within(dialog).findByText(/a plain list file/, undefined, T);
    await user.click(within(dialog).getByRole("button", { name: "Import" }));
  }
  const posts = (calls: Call[]) => mutations(calls).filter((c) => c.path === "/feeds/manual-block/import");

  it("reads the version from the feed's status after a feed_run while the editor was closed", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    const { calls } = mockApi([...core.routes, core.importRoute("ads.example\n")]);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    await user.click(screen.getByRole("tab", { name: "Status" }));
    await waitFor(() => expect(screen.queryByTestId("code-editor")).toBeNull(), T);
    const v = core.append("||elsewhere.example^");
    runEvent(core, core.finishRun(v));
    await importOnce(user);
    await waitFor(() => expect(posts(calls)).toHaveLength(1), T);
    expect(posts(calls)[0].query.get("base_version")).toBe(v);
    // The version came without the file's content (F4).
    expect(core.st.fileReads).toBe(1);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull(), T);
  }, 20000);

  it("reads the version again after a 409, so the next try goes through", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    const v0 = core.st.version;
    const { calls } = mockApi([...core.routes, core.importRoute("ads.example\n")]);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    await user.click(screen.getByRole("tab", { name: "Status" }));
    await waitFor(() => expect(screen.queryByTestId("code-editor")).toBeNull(), T);
    // Another writer appends while this page's event stream is down: no feed_run arrives.
    const v1 = core.append("||missed.example^");
    await importOnce(user);
    expect(await screen.findByText(/The file changed since this page read it/, undefined, T)).toBeInTheDocument();
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Import" }));
    await waitFor(() => expect(posts(calls)).toHaveLength(2), T);
    expect(posts(calls).map((p) => p.query.get("base_version"))).toEqual([v0, v1]);
    expect(core.st.fileReads).toBe(1);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull(), T);
  }, 20000);
});

describe("V6, V7: no endless wait when core makes no run (feeds.md §1)", () => {
  it("doesn't wait after an import into a disabled feed", async () => {
    const user = userEvent.setup();
    const core = manualCore("manual-block", { enabled: false });
    const { fixtures } = mockApi([
      ...core.routes,
      { method: "GET", path: "/feeds/manual-block", body: () => ({ ...(fixtures["/feeds/manual-block"] as object), enabled: false }) },
      core.importRoute("ads.example\n"),
    ]);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    await user.click(screen.getByRole("button", { name: /Import…/ }));
    const dialog = await screen.findByRole("dialog");
    await user.upload(within(dialog).getByLabelText("File"), new File(["ads.example\n"], "l.txt"));
    await within(dialog).findByText(/a plain list file/, undefined, T);
    await user.click(within(dialog).getByRole("button", { name: "Import" }));
    await waitFor(() => expect(editorView().state.doc.toString()).toContain("ads.example"), T);
    expect(await screen.findByText(/The feed is disabled, so no run reads the file/, undefined, T)).toBeInTheDocument();
    expect(screen.queryByText(/Waiting for the run's result/)).toBeNull();
  }, 20000);

  it("stops waiting when the newest run already read the saved text, and says so", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    const x0 = core.st.version;
    mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await typeAtEnd("||one.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    // Back to X0 before X1's run started (a re-ingest of X0 held the feed).
    replaceText("||original.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(core.st.version).toBe(x0), T);
    // The re-ingest of X0 ends; core then skips the save's run: the newest run with a blob read X0.
    const reingest = core.finishRun(x0, { kind: "reingest", updated_at: core.st.saves[0].at });
    expect(await screen.findByText(/Core made no new run: run \d+ already read this text/, undefined, T)).toBeInTheDocument();
    expect(screen.getByText(`Run ${reingest}`)).toBeInTheDocument();
    expect(screen.queryByText(/Waiting for the run's result/)).toBeNull();
  }, 15000);

  it("says when core tries the run again (manual_retry_at), and still shows that run", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await typeAtEnd("||one.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    // The heavy lane was full: core freed the feed and tries the run again in a minute.
    core.st.busy = false;
    core.st.retryAt = "2026-11-23T10:01:30.000000Z";
    expect(await screen.findByText(/its run couldn't start .* Core tries it again at/, undefined, T)).toBeInTheDocument();
    const id = core.finishRun();
    runEvent(core, id);
    expect(await screen.findByText(`Run ${id}`, undefined, T)).toBeInTheDocument();
  }, 15000);
});

describe("V8: a JSON document is sent without a UTF-8 BOM", () => {
  const BOM = new Uint8Array([0xef, 0xbb, 0xbf]);
  async function rawBodies(run: () => Promise<void>, routes: Parameters<typeof mockApi>[0]) {
    const { fetchMock } = mockApi(routes);
    const raw: Uint8Array[] = [];
    vi.stubGlobal("fetch", async (req: Request) => {
      if (req.method !== "GET") raw.push(new Uint8Array(await req.clone().arrayBuffer()));
      return fetchMock(req);
    });
    await run();
    return raw;
  }

  it("imports a JSON export saved with a BOM", async () => {
    const user = userEvent.setup();
    const exp = { picket_feed_export: 1, feed: { id: "x", name: "X", format: "adblock", category: "security" }, entries: [] };
    const raw = await rawBodies(
      async () => {
        renderApp("/feeds");
        await user.click(await screen.findByRole("button", { name: /Import…/ }, T));
        const dialog = await screen.findByRole("dialog");
        await user.upload(within(dialog).getByLabelText("File"), new File([BOM, JSON.stringify(exp)], "x.json"));
        await within(dialog).findByText(/x\.json: a JSON export/, undefined, T);
        await user.click(within(dialog).getByRole("button", { name: "Import" }));
        await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull(), T);
      },
      [{ method: "POST", path: "/feeds/import", status: 201, body: { feed: "x", created: true, version: "v", changed: true, run_queued: false, entries: 0 } }],
    );
    expect(raw).toHaveLength(1);
    expect(raw[0][0]).toBe("{".charCodeAt(0));
    expect(JSON.parse(new TextDecoder().decode(raw[0]))).toEqual(exp);
  });

  it("restores a config export saved with a BOM", async () => {
    const user = userEvent.setup();
    const doc = W5["GET /config/export"];
    const raw = await rawBodies(
      async () => {
        renderApp("/settings?tab=export");
        await user.upload(await screen.findByLabelText("File", undefined, T), new File([BOM, JSON.stringify(doc)], "picket-config.json", { type: "application/json" }));
        await user.click(await screen.findByRole("button", { name: /Restore/ }, T));
        await user.click(await screen.findByRole("button", { name: "Restore" }));
        await screen.findByText(/Restored/, undefined, T);
      },
      [{ method: "PUT", path: "/config/export", body: captured("PUT /config/export").body }],
    );
    expect(raw).toHaveLength(1);
    expect(raw[0][0]).toBe("{".charCodeAt(0));
    expect(JSON.parse(new TextDecoder().decode(raw[0]))).toEqual(doc);
    const plain = new Blob(["{}"]);
    expect(await withoutBom(plain)).toBe(plain);
  });
});

describe("V9: no one-click Allow for an IPv6 address (rules.md §1)", () => {
  it("offers Allow for names and IPv4 addresses only", () => {
    expect(entryName({ kind: "ip_range", key: "2001:db8::1" })).toBeNull();
    expect(entryName({ kind: "ip_literal", key: "2001:db8::5" })).toBeNull();
    expect(entryName({ kind: "ip_range", key: "10.0.0.0/8" })).toBeNull();
    expect(entryName({ kind: "ip_literal", key: "10.1.2.3" })).toBe("10.1.2.3");
    expect(entryName({ kind: "name", key: "org.example" })).toBe("example.org");
    expect(ruleSafe("2001:db8::1")).toBe(false);
    expect(ruleSafe("10.1.2.3")).toBe(true);
  });
});

describe("V10: a cleared id follows the name again", () => {
  it("in a create dialog", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([{ method: "POST", path: "/feeds", status: 201, body: (c: Call) => ({ id: (c.body as { id: string }).id, warnings: [] }) }]);
    renderApp("/feeds");
    await user.click(await screen.findByRole("button", { name: /New manual feed/ }, T));
    const dialog = await screen.findByRole("dialog");
    const name = within(dialog).getByLabelText("Name");
    await user.type(name, "My List");
    const id = within(dialog).getByLabelText("Id");
    await user.clear(id);
    expect(id).toHaveValue("");
    expect(id).toHaveAttribute("placeholder", "my-list");
    await user.type(name, " Two");
    expect(id).toHaveAttribute("placeholder", "my-list-two");
    expect(within(dialog).getByText(/From the name; edit it if you like/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() => expect(mutations(calls).some((c) => c.path === "/feeds")).toBe(true), T);
    expect(mutations(calls)[0].body).toMatchObject({ id: "my-list-two", name: "My List Two" });
  });

  it("in an entity create form", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([
      { method: "POST", path: "/profiles", status: 201, body: (c: Call) => ({ id: (c.body as { id: string }).id, entity: c.body, warnings: [] }) },
      { method: "GET", path: /^\/profiles\/[a-z-]+$/, body: { id: "kids-tablet", name: "Kids Tablet", allow: [], block: [], upstream: "cloudflare" } },
    ]);
    renderApp("/profiles/new");
    await user.type(await screen.findByLabelText("Name", undefined, T), "Kids");
    const id = screen.getByLabelText("Id");
    await user.clear(id);
    expect(id).toHaveAttribute("placeholder", "kids");
    await user.type(screen.getByLabelText("Name"), " Tablet");
    expect(id).toHaveValue("kids-tablet");
    await user.clear(id);
    await user.click(screen.getByRole("button", { name: "Create profile" }));
    await waitFor(() => expect(mutations(calls).some((c) => c.path === "/profiles")).toBe(true), T);
    expect(mutations(calls)[0].body).toMatchObject({ id: "kids-tablet", name: "Kids Tablet" });
  });
});

describe("V11: a reconnect or lagged stream never downloads an open manual file again", () => {
  it("refetches everything else; a feed_run marks only a closed editor's file stale", () => {
    const qc = new QueryClient();
    // An open editor observes its file (round 3: a closed one's is marked stale by a reconnect too, W7).
    qc.setQueryData(qk.manualFile("manual-block"), { version: "a" });
    const read = vi.fn(() => new Promise<never>(() => {}));
    const stop = new QueryObserver(qc, { queryKey: qk.manualFile("manual-block"), queryFn: read, staleTime: Infinity }).subscribe(() => {});
    qc.setQueryData(qk.config("feeds"), []);
    invalidateAll(qc);
    expect(qc.getQueryState(qk.manualFile("manual-block"))?.isInvalidated).toBe(false);
    expect(qc.getQueryState(qk.config("feeds"))?.isInvalidated).toBe(true);
    applyEvent(qc, { type: "lagged", data: null });
    expect(qc.getQueryState(qk.manualFile("manual-block"))?.isInvalidated).toBe(false);
    expect(read).not.toHaveBeenCalled();
    stop();
    // No editor observes it: a feed_run marks it stale, so the next read takes the new file.
    applyEvent(qc, feedRunFrame([{ feed: "manual-block", run: 9 }]));
    expect(qc.getQueryState(qk.manualFile("manual-block"))?.isInvalidated).toBe(true);
  });

  it("an open editor reads its runs after a reconnect instead of the file", async () => {
    const core = manualCore();
    const { calls } = mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    await sleep(50);
    const reads = core.st.fileReads;
    const runsBefore = calls.filter((c) => c.path === "/feeds/manual-block/runs").length;
    act(() => {
      const s = socket() as unknown as { open: () => void; close?: () => void; onclose?: () => void };
      s.open();
      s.onclose?.();
    });
    await sleep(1500);
    act(() => socket().open());
    await waitFor(() => expect(calls.filter((c) => c.path === "/feeds/manual-block/runs").length).toBeGreaterThan(runsBefore), T);
    expect(core.st.fileReads).toBe(reads);
  });
});

describe("V12: Keep my changes merges fields core checks together as one value (core.md §2)", () => {
  it("never leaves a bundle Enforce moved in neither list", () => {
    const base = { name: "Kids", block: ["block-common"], trial_bundles: ["trial-x"], lookups: [] };
    const mine = { ...base, name: "Kids 2", block: ["block-common", "ads"] };
    const theirs = { ...base, block: ["block-common", "trial-x"], trial_bundles: [] };
    const { value, replaced } = mergeKeepingMine(base, mine, theirs, COUPLED_FIELDS.profiles);
    expect(value).toEqual({ name: "Kids 2", block: ["block-common", "ads"], trial_bundles: ["trial-x"], lookups: [] });
    expect(replaced).toEqual([["block", "trial_bundles", "lookups"]]);
    // A change elsewhere to the group with none here is taken as it is.
    expect(mergeKeepingMine(base, { ...base, name: "Kids 2" }, theirs, COUPLED_FIELDS.profiles)).toEqual({ value: { ...theirs, name: "Kids 2" }, replaced: [] });
    expect(theirs.trial_bundles).toEqual([]);
  });

  it("never keeps a stale lanca.zones in settings: the zones aren't grouped with web.names (core c58ba80)", () => {
    // A zones change elsewhere is a rotation; a merged settings form takes it as it is, so a stale
    // value can never travel back (core needs lanca.rotate_from to rotate, and checks web.names
    // against the zones it has).
    const base = { web: { names: ["a.lan"], port: 443 }, lanca: { zones: ["lan"] } };
    const mine = { web: { names: ["a.lan", "b.lan"], port: 443 }, lanca: { zones: ["lan"] } };
    const theirs = { web: { names: ["a.lan"], port: 8443 }, lanca: { zones: ["home.arpa"] } };
    expect(COUPLED_FIELDS.settings).toEqual([]);
    const { value, replaced } = mergeKeepingMine(base, mine, theirs, COUPLED_FIELDS.settings);
    expect(value).toEqual({ web: { names: ["a.lan", "b.lan"], port: 8443 }, lanca: { zones: ["home.arpa"] } });
    expect(replaced).toEqual([]);
  });
});

describe("test/contract.ts checks GET query names too", () => {
  it("flags a query parameter core doesn't take on a read", () => {
    const q = (s = "") => new URLSearchParams(s);
    expect(contractViolations("GET", "/config/issues", q("limit=500"), undefined)).toEqual([expect.stringMatching(/ignores the query parameter limit/)]);
    expect(contractViolations("GET", "/feeds/x/runs", q("limit=20"), undefined)).toEqual([]);
    expect(contractViolations("GET", "/feeds/x/runs", q("limt=20"), undefined)).toEqual([expect.stringMatching(/limt/)]);
  });
});
