// Review round 1 of the web UI (UI1–UI15): each test reproduces a reviewer's finding and asserts
// the fixed behaviour. The mocks model core where the finding depends on it (a 409 on a stale
// base_version, the run row written only when a run ends, the import's settings), and every
// request is checked against what core accepts (test/contract.ts).
import { describe, expect, it, vi } from "vitest";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient } from "@tanstack/react-query";
import { Text } from "@codemirror/state";
import { EditorView } from "@codemirror/view";
import { mockApi, mutations, reply, type Call } from "@/test/mock-api";
import { manualCore } from "@/test/manual-core";
import { alertFrame, feedRunFrame } from "@/test/events";
import { registerNotBuilt } from "@/test/registry";
import { W5, captured } from "@/test/core-w5";
import { renderApp } from "@/test/render";
import { applyEvent } from "@/api/events";
import { fetchChart } from "@/api/queries";
import { isNotBuiltSeries } from "@/api/availability";
import { ApiError, isNotAvailable } from "@/api/errors";
import { contractViolations } from "@/test/contract";
import { entryName } from "./feed-detail";
import { importNewQuery } from "./feeds";
import { deepEqual, merge3 } from "@/lib/merge";
import { profileIdFromName, slugFromName } from "@/lib/ids";

const T = { timeout: 8000 };

interface FakeSocket {
  open: () => void;
  emit: (d: unknown) => void;
}
const socket = () => (globalThis.WebSocket as unknown as { instances: FakeSocket[] }).instances.at(-1)!;

function editorView(): EditorView {
  const host = screen.getByTestId("code-editor");
  return EditorView.findFromDOM(host.querySelector(".cm-editor") as HTMLElement)!;
}
async function typeAtEnd(text: string) {
  await screen.findByTestId("code-editor", undefined, T);
  const view = editorView();
  act(() => view.dispatch({ changes: { from: view.state.doc.length, insert: text } }));
}

// ---------------------------------------------------------------------------------------------

describe("UI1: importing an export into a new feed keeps the export's settings (feeds.md §4)", () => {
  const header = [
    "! picket-feed-export: 1",
    "! feed: sec-a",
    "! name: Sec A",
    "! provider: ",
    "! exported_at: 2026-11-23T11:15:56Z",
    "! format: adblock",
    "! format_options: {}",
    '! rule_policy: {"redirects":"keep","client_rules":"keep","browser_changes":"keep"}',
    "! category: security",
    "! warn_on: null",
    "! picket-first-seen: 2026-11-23T11:15:54Z",
    "||evil.example^",
    "||bad.example^",
    "! picket-first-seen: none",
    "",
  ].join("\n");

  /** core's `POST feeds/import` for a file export: the query's format and category win over the header (feeds/transfer.rs). */
  const created: Record<string, unknown>[] = [];
  const importRoute = {
    method: "POST",
    path: "/feeds/import",
    status: 201,
    body: (c: Call) => {
      const file = (c.body as { file?: string }).file ?? "";
      const h = Object.fromEntries(
        file
          .split("\n")
          .filter((l) => l.startsWith("! ") && l.includes(": "))
          .map((l) => [l.slice(2, l.indexOf(":")), l.slice(l.indexOf(":") + 2)]),
      );
      const feed = {
        id: c.query.get("id") ?? h.feed,
        format: c.query.get("format") ?? h.format ?? "adblock",
        category: c.query.get("category") ?? h.category ?? "mixed",
      };
      created.push(feed);
      return { feed: feed.id, created: true, version: "x", changed: true, run_queued: false, entries: null };
    },
  };

  it("sends no format or category for a text file export, and shows what it declares", async () => {
    const user = userEvent.setup();
    created.length = 0;
    const { calls } = mockApi([importRoute]);
    renderApp("/feeds");
    await user.click(await screen.findByRole("button", { name: /Import…/ }, T));
    const dialog = await screen.findByRole("dialog");
    await user.upload(within(dialog).getByLabelText("File"), new File([header], "sec-a.txt", { type: "text/plain" }));
    const declared = await within(dialog).findByLabelText("What the file declares", undefined, T);
    expect(within(declared).getByText("security")).toBeInTheDocument();
    expect(within(declared).getByText("adblock")).toBeInTheDocument();
    // The file isn't put into the paste box, and no format or category picker is offered.
    expect(within(dialog).queryByLabelText("…or paste")).toBeNull();
    expect(within(dialog).queryByLabelText("Format")).toBeNull();
    const id = within(dialog).getByLabelText("New feed id");
    expect(id).toHaveValue("sec-a");
    await user.clear(id);
    await user.type(id, "sec-b");
    await user.click(within(dialog).getByRole("button", { name: "Import" }));
    await waitFor(() => expect(mutations(calls).some((c) => c.path === "/feeds/import")).toBe(true), T);
    const post = mutations(calls).find((c) => c.path === "/feeds/import")!;
    expect([...post.query.keys()].sort()).toEqual(["id"]);
    expect(post.query.get("id")).toBe("sec-b");
    expect(post.body).toEqual({ file: header });
    expect(created.at(-1)).toEqual({ id: "sec-b", format: "adblock", category: "security" });
  });

  it("sends the picked format, category and domains_as for a plain list", async () => {
    const user = userEvent.setup();
    created.length = 0;
    const { calls } = mockApi([importRoute]);
    renderApp("/feeds");
    await user.click(await screen.findByRole("button", { name: /Import…/ }, T));
    const dialog = await screen.findByRole("dialog");
    await user.upload(within(dialog).getByLabelText("File"), new File(["ads.example\ntracker.example\n"], "my list.txt", { type: "text/plain" }));
    expect(await within(dialog).findByText(/a plain list file/, undefined, T)).toBeInTheDocument();
    expect(within(dialog).getByLabelText("New feed id")).toHaveValue("my-list");
    await user.click(within(dialog).getByRole("button", { name: "Import" }));
    await waitFor(() => expect(mutations(calls).some((c) => c.path === "/feeds/import")).toBe(true), T);
    const post = mutations(calls).find((c) => c.path === "/feeds/import")!;
    expect(Object.fromEntries(post.query)).toEqual({ id: "my-list", format: "plain", category: "mixed", domains_as: "exact" });
  });

  it("builds the query from the file's kind", () => {
    const v = { id: "x", name: "", format: "hosts", category: "privacy", domainsAs: "exact" };
    expect(importNewQuery("json-export", v)).toEqual({ id: "x", name: undefined });
    expect(importNewQuery("file-export", v)).toEqual({ id: "x", name: undefined });
    expect(importNewQuery("misp-export", v)).toEqual({ id: "x", name: undefined });
    expect(importNewQuery("misp-list", v)).toEqual({ id: "x", name: undefined, category: "privacy" });
    expect(importNewQuery("list", v)).toEqual({ id: "x", name: undefined, format: "hosts", category: "privacy", domains_as: undefined });
  });
});

describe("UI2: the editor's base is the version its save returned (api.md §7 base_version)", () => {
  it("never reads the file after a save, so a later append makes the next save a 409, not a silent overwrite", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    const v1 = core.st.version;
    const { calls } = mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await typeAtEnd("||mine.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(core.st.version).not.toBe(v1), T);
    const v2 = core.st.version;
    // Another writer appends right after the save.
    core.append("||concurrent.example^");
    await screen.findByText(v2, undefined, T);
    expect(core.st.fileReads).toBe(1);
    await typeAtEnd("||more.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("The file changed since you opened it", undefined, T)).toBeInTheDocument();
    const puts = mutations(calls).filter((c) => c.method === "PUT");
    expect(puts.map((c) => (c.body as { base_version: string }).base_version)).toEqual([v1, v2]);
    expect(core.st.content).toContain("||concurrent.example^");
    // Reload shows the other writer's line.
    await user.click(screen.getByRole("button", { name: /Reload the file/ }));
    await waitFor(() => expect(editorView().state.doc.toString()).toContain("||concurrent.example^"), T);
  });

  it("reloads a clean editor when a run of another version arrives, and warns a dirty one", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    await waitFor(() => expect(screen.getByText(core.st.version)).toBeInTheDocument(), T);
    // Let the editor note the newest run before the other writer's.
    await new Promise((r) => setTimeout(r, 50));
    const v = core.append("||elsewhere.example^");
    const r8 = core.finishRun(v);
    act(() => socket().emit({ type: "feed_run", data: core.event(r8) }));
    await waitFor(() => expect(editorView().state.doc.toString()).toContain("||elsewhere.example^"), T);
    expect(screen.getByText(v)).toBeInTheDocument();
    // Now with edits: the text stays and the page says the file changed.
    await typeAtEnd("||draft.example^\n");
    const v3 = core.append("||third.example^");
    const r9 = core.finishRun(v3);
    act(() => socket().emit({ type: "feed_run", data: core.event(r9) }));
    expect(await screen.findByText("The file changed elsewhere", undefined, T)).toBeInTheDocument();
    expect(editorView().state.doc.toString()).toContain("||draft.example^");
    expect(editorView().state.doc.toString()).not.toContain("||third.example^");
    await user.click(screen.getByRole("button", { name: /Reload the file/ }));
    await waitFor(() => expect(editorView().state.doc.toString()).toContain("||third.example^"), T);
  });
});

describe("UI3: the post-save result is the run of the saved version (core.md §12)", () => {
  it("keeps waiting past 4 s instead of showing the previous run, then shows the matching run", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    const { calls } = mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await typeAtEnd("||mine.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    await new Promise((r) => setTimeout(r, 4500));
    expect(screen.queryByText("Run 7")).toBeNull();
    expect(screen.getByText(/Waiting for the run's result/)).toBeInTheDocument();
    const id = core.finishRun(core.st.version, { status: "rejected", gate: "parse_errors", error: "1 of 3 rule lines can't be read" });
    act(() => socket().emit({ type: "feed_run", data: core.event(id) }));
    expect(await screen.findByText(`Run ${id}`, undefined, T)).toBeInTheDocument();
    expect(screen.getByText("Rejected by a sanity gate")).toBeInTheDocument();
    expect(calls.filter((c) => c.path.endsWith("/runs")).length).toBeGreaterThan(1);
  }, 15000);

  it("finds the run by polling when no event comes", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await typeAtEnd("||mine.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    const id = core.finishRun(core.st.version);
    expect(await screen.findByText(`Run ${id}`, undefined, T)).toBeInTheDocument();
  });

  it("says so when a newer save took the run, and when the feed is disabled", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await typeAtEnd("||mine.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    const other = core.append("||newer.example^");
    const id = core.finishRun(other);
    act(() => socket().emit({ type: "feed_run", data: core.event(id) }));
    expect(await screen.findByText(/changed again before this save's run started/, undefined, T)).toBeInTheDocument();
    expect(screen.getByText(`Run ${id}`)).toBeInTheDocument();
  });

  it("doesn't wait for a run of a disabled feed", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    const { fixtures } = mockApi([...core.routes, { method: "GET", path: "/feeds/manual-block", body: () => ({ ...(fixtures["/feeds/manual-block"] as object), enabled: false }) }]);
    renderApp("/feeds/manual-block");
    await typeAtEnd("||mine.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText(/The feed is disabled, so no run reads the file/, undefined, T)).toBeInTheDocument();
    expect(screen.queryByText(/Waiting for the run's result/)).toBeNull();
  });
});

describe("UI4: an entry's Allow writes the entry's own name (feeds.md §6)", () => {
  it("turns core's reversed key back into the name", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([
      {
        method: "GET",
        path: "/feeds/manual-block/entries",
        body: {
          items: [
            { id: 100, rule_type: "dns", kind: "name", key: "org.example", raw: "||example.org^", first_seen_at: "2026-11-23T00:00:00Z", last_seen_at: "2026-11-23T00:00:00Z", flags: 3, first_run: 7 },
            { id: 101, rule_type: "dns", kind: "pattern", key: "ads*.example^", raw: "||ads*.example^", first_seen_at: "2026-11-23T00:00:00Z", last_seen_at: "2026-11-23T00:00:00Z", flags: 0, first_run: 7 },
          ],
          next_cursor: null,
        },
      },
      { method: "POST", path: "/feeds/manual-allow/file/lines", body: { version: "v2", changed: true } },
    ]);
    renderApp("/feeds/manual-block?tab=entries");
    const allows = await screen.findAllByRole("button", { name: "Allow" }, T);
    expect(allows).toHaveLength(1); // a pattern decides no single name
    await user.click(allows[0]);
    expect(await screen.findByText("@@||example.org^", undefined, T)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Append" }));
    await waitFor(() => expect(mutations(calls)[0]?.body).toEqual({ lines: ["@@||example.org^"] }), T);
  });

  it("maps each kind of key", () => {
    expect(entryName({ kind: "name", key: "org.example.ads" })).toBe("ads.example.org");
    expect(entryName({ kind: "host_mapping", key: "lan.router" })).toBe("router.lan");
    expect(entryName({ kind: "ip_literal", key: "192.0.2.1" })).toBe("192.0.2.1");
    expect(entryName({ kind: "ip_range", key: "192.0.2.7" })).toBe("192.0.2.7");
    expect(entryName({ kind: "ip_range", key: "10.0.0.0/8" })).toBeNull();
    expect(entryName({ kind: "regex", key: "/ad[0-9]/" })).toBeNull();
    expect(entryName({ kind: "network", key: "||x^$script" })).toBeNull();
  });
});

describe("UI5: a format or format_options edit warns and offers Export first (feeds.md §3)", () => {
  it("shows the warning with Export, and asks before saving", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([{ method: "PUT", path: "/feeds/manual-block", body: (c: Call) => ({ id: "manual-block", entity: c.body, warnings: [] }) }]);
    renderApp("/feeds/manual-block?tab=settings");
    const form = await screen.findByRole("form", { name: "Edit feed" }, T);
    expect(within(form).queryByText("Saving replaces the feed's entries")).toBeNull();
    await user.click(within(form).getByLabelText("Format"));
    await user.click(await screen.findByRole("option", { name: "hosts" }));
    const warning = await within(form).findByText("Saving replaces the feed's entries", undefined, T);
    const alert = warning.closest("[role=alert]") as HTMLElement;
    expect(within(alert).getByRole("button", { name: /^Export$/ })).toBeInTheDocument();
    expect(within(alert).getByText(/entries collected under the old settings close/)).toBeInTheDocument();
    await user.click(within(form).getByRole("button", { name: "Save" }));
    const confirm = await screen.findByRole("alertdialog");
    expect(within(confirm).getByText("Replace the feed's entries?")).toBeInTheDocument();
    expect(mutations(calls)).toHaveLength(0);
    await user.click(within(confirm).getByRole("button", { name: "Save and replace them" }));
    await waitFor(() => expect(mutations(calls).some((c) => c.path === "/feeds/manual-block")).toBe(true), T);
    expect((mutations(calls)[0].body as { format: string }).format).toBe("hosts");
  });
});

describe("UI9: large files", () => {
  it("tracks the editor's dirtiness without turning the document into a string per keystroke", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    core.st.content = "||line.example^\n".repeat(20000);
    mockApi(core.routes);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    const spy = vi.spyOn(Text.prototype, "toString");
    for (let i = 0; i < 30; i++) await typeAtEnd("x");
    expect(screen.getByRole("button", { name: "Save" })).toBeEnabled();
    // Typing the same text back makes it clean again (Text.eq on shared subtrees).
    const view = editorView();
    act(() => view.dispatch({ changes: { from: view.state.doc.length - 30, to: view.state.doc.length } }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Save" })).toBeDisabled());
    expect(spy).not.toHaveBeenCalled();
    await typeAtEnd("||new.example^\n");
    const v1 = core.st.version;
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(core.st.version).not.toBe(v1), T);
    expect(spy).toHaveBeenCalledTimes(1);
    spy.mockRestore();
  });

  it("imports into a manual feed with the editor's version, without reading the file again", async () => {
    const user = userEvent.setup();
    const core = manualCore();
    const v1 = core.st.version;
    let readsBefore = -1;
    let statusBefore = -1;
    const { calls } = mockApi([
      ...core.routes,
      {
        method: "POST",
        path: "/feeds/manual-block/import",
        body: () => {
          readsBefore = core.st.fileReads;
          statusBefore = core.st.statusReads;
          return { feed: "manual-block", created: false, version: core.append("ads.example"), saved_at: core.st.savedAt, changed: true, run_queued: false, entries: null };
        },
      },
    ]);
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    await user.click(screen.getByRole("button", { name: /Import…/ }));
    const dialog = await screen.findByRole("dialog");
    await user.upload(within(dialog).getByLabelText("File"), new File(["ads.example\n"], "l.txt"));
    await within(dialog).findByText(/a plain list file/, undefined, T);
    await user.click(within(dialog).getByRole("button", { name: "Import" }));
    await waitFor(() => expect(mutations(calls).some((c) => c.path === "/feeds/manual-block/import")).toBe(true), T);
    const post = mutations(calls).find((c) => c.path === "/feeds/manual-block/import")!;
    // A plain list is read in the feed's format: the dialog pins the one it showed (F1).
    expect(Object.fromEntries(post.query)).toEqual({ mode: "replace", base_version: v1, format: "adblock" });
    expect(post.body).toEqual({ file: "ads.example\n" });
    expect(readsBefore).toBe(1);
    expect(statusBefore).toBe(0);
    // The import changed the file: the clean editor reads it again and waits for its run.
    await waitFor(() => expect(editorView().state.doc.toString()).toContain("ads.example"), T);
    expect(await screen.findByText(/Waiting for the run's result/, undefined, T)).toBeInTheDocument();
  });

  it("restores a config export from the file as it is, never through the text box", async () => {
    const user = userEvent.setup();
    // A document a real core wrote (manual files as base64 chunk lists), and core's reply.
    const doc = JSON.stringify(W5["GET /config/export"]);
    const { calls } = mockApi([{ method: "PUT", path: "/config/export", body: captured("PUT /config/export").body }]);
    renderApp("/settings?tab=export");
    await user.upload(await screen.findByLabelText("File", undefined, T), new File([doc], "picket-config.json", { type: "application/json" }));
    expect(screen.queryByLabelText("…or paste")).toBeNull();
    await user.click(await screen.findByRole("button", { name: /Restore/ }, T));
    await user.click(await screen.findByRole("button", { name: "Restore" }));
    await waitFor(() => expect(mutations(calls).some((c) => c.path === "/config/export")).toBe(true), T);
    expect(mutations(calls).find((c) => c.path === "/config/export")!.body).toEqual(JSON.parse(doc));
  });
});

describe("UI6a: an edit form follows saved data and never reverts it", () => {
  function profileCore() {
    let profile: Record<string, unknown> = { id: "kids", name: "Kids", allow: [], block: ["block-common"], trial_bundles: ["trial-x"], upstream: "cloudflare" };
    return {
      get: () => profile,
      set: (p: Record<string, unknown>) => (profile = p),
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

  it("keeps Enforce when the profile is renamed and saved afterwards", async () => {
    const user = userEvent.setup();
    const core = profileCore();
    const { calls } = mockApi(core.routes);
    renderApp("/profiles/kids");
    await user.click(await screen.findByRole("button", { name: "Enforce" }, T));
    await user.click((await screen.findAllByRole("button", { name: "Enforce" })).at(-1)!);
    await waitFor(() => expect(core.get().trial_bundles).toEqual([]), T);
    await waitFor(() => expect(calls.filter((c) => c.method === "GET" && c.path === "/profiles/kids").length).toBeGreaterThan(2), T);
    // The clean form followed the saved profile.
    await waitFor(() => expect(screen.getByRole("button", { name: "Save" })).toBeDisabled(), T);
    const name = screen.getByLabelText("Name");
    await user.clear(name);
    await user.type(name, "Kids 2");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(mutations(calls).filter((c) => c.method === "PUT").length).toBe(2), T);
    const second = mutations(calls).filter((c) => c.method === "PUT")[1].body as Record<string, unknown>;
    expect(second).toMatchObject({ name: "Kids 2", trial_bundles: [], block: ["block-common", "trial-x"] });
  });

  it("keeps a dirty draft when the profile changes elsewhere, and keeps the admin's changes on top", async () => {
    const user = userEvent.setup();
    const core = profileCore();
    const { calls, fixtures } = mockApi(core.routes);
    void fixtures;
    const { queryClient } = renderApp("/profiles/kids");
    const name = await screen.findByLabelText("Name", undefined, T);
    await user.clear(name);
    await user.type(name, "Kids 2");
    core.set({ ...core.get(), trial_bundles: [], block: ["block-common", "trial-x"] });
    await act(async () => {
      await queryClient.invalidateQueries({ queryKey: ["config", "profiles"] });
    });
    expect(await screen.findByText("This profile changed elsewhere", undefined, T)).toBeInTheDocument();
    expect(screen.getByLabelText("Name")).toHaveValue("Kids 2");
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Keep my changes" }));
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(mutations(calls).filter((c) => c.method === "PUT").length).toBe(1), T);
    expect(mutations(calls)[0].body).toMatchObject({ name: "Kids 2", trial_bundles: [], block: ["block-common", "trial-x"] });
  });

  it("merges three ways", () => {
    const base = { a: 1, b: { c: 1, d: [1] }, e: "x" };
    const mine = { a: 2, b: { c: 1, d: [1] }, e: "x" };
    const theirs = { a: 1, b: { c: 5, d: [2] }, e: "y" };
    expect(merge3(base, mine, theirs)).toEqual({ a: 2, b: { c: 5, d: [2] }, e: "y" });
    expect(merge3(base, { ...base, e: "mine" }, { ...base, e: "theirs" })).toEqual({ ...base, e: "mine" });
    expect(deepEqual({ a: null }, {})).toBe(true);
    expect(deepEqual({ a: [1, 2] }, { a: [2, 1] })).toBe(false);
  });
});

describe("UI6b: a live settings refresh keeps an unsaved draft", () => {
  it("keeps the draft and offers reload or keep-mine; a clean form follows", async () => {
    const user = userEvent.setup();
    const live: Record<string, string> = { metrics: "3d" };
    const { calls, fixtures } = mockApi([
      {
        method: "GET",
        path: "/settings",
        body: () => {
          const s = structuredClone(fixtures["/settings"]) as { settings: { retention: Record<string, string> } };
          Object.assign(s.settings.retention, live);
          return s;
        },
      },
      { method: "PUT", path: "/settings", body: {} },
    ]);
    const { queryClient } = renderApp("/settings?tab=retention");
    const refresh = () =>
      act(async () => {
        await queryClient.invalidateQueries({ queryKey: ["settings"] });
      });
    const input = await screen.findByLabelText("Metrics", undefined, T);
    await user.clear(input);
    await user.type(input, "6h");
    live.metrics = "1d";
    await refresh();
    expect(await screen.findByText("These settings changed elsewhere", undefined, T)).toBeInTheDocument();
    expect(screen.getByLabelText("Metrics")).toHaveValue("6h");
    await user.click(screen.getByRole("button", { name: "Reload" }));
    expect(screen.getByLabelText("Metrics")).toHaveValue("1d");
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    // A clean form follows new data.
    live.query_logs = "2d";
    await refresh();
    await waitFor(() => expect(screen.getByLabelText("Query logs")).toHaveValue("2d"), T);
    expect(screen.queryByText("These settings changed elsewhere")).toBeNull();
    // Keep my changes: my edit on top of the other change.
    await user.clear(screen.getByLabelText("Metrics"));
    await user.type(screen.getByLabelText("Metrics"), "12h");
    live.query_logs = "1d";
    await refresh();
    await user.click(await screen.findByRole("button", { name: "Keep my changes" }, T));
    expect(screen.getByLabelText("Query logs")).toHaveValue("1d");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(mutations(calls).some((c) => c.path === "/settings")).toBe(true), T);
    expect((mutations(calls)[0].body as { retention: Record<string, string> }).retention).toMatchObject({ metrics: "12h", query_logs: "1d" });
  });
});

describe("UI6c: Add to bundle… reads the bundle fresh and adds one at a time", () => {
  it("keeps both feeds when two are added quickly", async () => {
    const user = userEvent.setup();
    const { fixtures } = mockApi();
    let bundle = structuredClone(fixtures["/bundles/block-common"]) as { feeds: { feed: string }[] };
    mockApi([
      {
        method: "GET",
        path: "/feed-providers-review",
        body: [
          { feed: "hagezi-tif", name: "tif.txt", alert: 3, provider: "hagezi", file: "adblock/tif.txt", since: "2026-11-23T10:00:00Z" },
          { feed: "hagezi-pro", name: "pro.txt", alert: 4, provider: "hagezi", file: "adblock/pro.txt", since: "2026-11-23T10:00:00Z" },
        ],
      },
      { method: "GET", path: "/bundles/block-common", body: () => bundle },
      {
        method: "PUT",
        path: "/bundles/block-common",
        body: (c: Call) => {
          bundle = c.body as typeof bundle;
          return { id: "block-common", warnings: [] };
        },
      },
    ]);
    renderApp("/feed-providers");
    for (const _ of [0, 1]) {
      const buttons = await screen.findAllByRole("button", { name: "Add to bundle…" }, T);
      await user.click(buttons[_]);
      const dialog = await screen.findByRole("dialog");
      await user.click(within(dialog).getByRole("combobox"));
      await user.click(await screen.findByRole("option", { name: /block-common/ }));
      await user.click(within(dialog).getByRole("button", { name: "Add" }));
      await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull(), T);
    }
    await waitFor(() => expect(bundle.feeds.map((f) => f.feed)).toEqual(expect.arrayContaining(["hagezi-tif", "hagezi-pro"])), T);
  });
});

describe("UI7: warnings are paged (api.md §7 cursors)", () => {
  const w = (id: number, value: string) => ({ id, kind: "warninglist", value, first_seen: "2026-11-23T00:00:00Z", last_seen: "2026-11-23T00:00:00Z", status: "open" });
  const route = (bundle: string) => ({
    method: "GET",
    path: `/bundles/${bundle}/warnings`,
    body: (c: Call) =>
      c.query.get("cursor") === "MORE"
        ? { alerts: [], warnings: { items: [w(2, "second.example")], next_cursor: null } }
        : { alerts: [], warnings: { items: [w(1, "first.example")], next_cursor: "MORE" } },
  });

  it("loads the next page on a bundle's Warnings tab", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([route("block-common")]);
    renderApp("/bundles/block-common?tab=warnings");
    await screen.findByText("first.example", undefined, T);
    await user.click(screen.getByRole("button", { name: "Load more" }));
    expect(await screen.findByText("second.example", undefined, T)).toBeInTheDocument();
    expect(screen.getByText("first.example")).toBeInTheDocument();
    expect(calls.filter((c) => c.path.endsWith("/warnings") && c.query.get("cursor") === "MORE")).toHaveLength(1);
    expect(screen.queryByRole("button", { name: "Load more" })).toBeNull();
  });

  it("loads the next page on the Warninglists page", async () => {
    const user = userEvent.setup();
    mockApi([route("warn-common")]);
    renderApp("/warninglists");
    await screen.findByText("first.example", undefined, T);
    await user.click(screen.getByRole("button", { name: "Load more" }));
    expect(await screen.findByText("second.example", undefined, T)).toBeInTheDocument();
  });
});

describe("UI8: create dialogs derive the id from the name and show it", () => {
  it("rules", () => {
    expect(slugFromName("HaGeZi  Pro++ list!")).toBe("hagezi-pro-list");
    expect(slugFromName("x".repeat(80))).toHaveLength(64);
    expect(slugFromName("Ünïcode")).toBe("n-code");
    expect(profileIdFromName("Kids full")).toBe("kids");
    expect(profileIdFromName("Kids' tablet")).toBe("kids-tablet");
  });

  it("creates a manual feed from a name alone", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([{ method: "POST", path: "/feeds", status: 201, body: (c: Call) => ({ id: (c.body as { id: string }).id, warnings: [] }) }]);
    renderApp("/feeds");
    await user.click(await screen.findByRole("button", { name: /New manual feed/ }, T));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("Name"), "My Allow List");
    expect(within(dialog).getByLabelText("Id")).toHaveValue("my-allow-list");
    await user.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() => expect(mutations(calls).some((c) => c.path === "/feeds")).toBe(true), T);
    expect(mutations(calls)[0].body).toMatchObject({ id: "my-allow-list", name: "My Allow List" });
  });

  it("lets the admin edit the id, and refuses one core would refuse", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([{ method: "POST", path: "/feed-providers", status: 201, body: (c: Call) => ({ id: (c.body as { id: string }).id, warnings: [] }) }]);
    renderApp("/feed-providers");
    await user.click(await screen.findByRole("button", { name: /New provider/ }, T));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("Name"), "Big Lists");
    const id = within(dialog).getByLabelText("Id");
    expect(id).toHaveValue("big-lists");
    await user.clear(id);
    await user.type(id, "Bad Id");
    expect(within(dialog).getByText(/1–64 of a-z/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("combobox"));
    await user.click(await screen.findByRole("option", { name: /^http / }));
    expect(within(dialog).getByRole("button", { name: "Create provider" })).toBeDisabled();
    await user.clear(id);
    await user.type(id, "lists");
    await user.type(within(dialog).getAllByLabelText(/^url/i)[0], "https://example.org/lists/big.txt");
    await user.click(within(dialog).getByRole("button", { name: "Create provider" }));
    await waitFor(() => expect(mutations(calls).some((c) => c.path === "/feed-providers")).toBe(true), T);
    expect(mutations(calls)[0].body).toMatchObject({ id: "lists", name: "Big Lists", module: "http" });
  });

  it("creates a lookup provider from a name alone", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([{ method: "POST", path: "/lookup-providers", status: 201, body: (c: Call) => ({ id: (c.body as { id: string }).id, warnings: [] }) }]);
    renderApp("/lookup-providers");
    await user.click(await screen.findByRole("button", { name: /New lookup provider|Add/ }, T));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("Name"), "Quad9 Threats");
    expect(within(dialog).getByLabelText("Id")).toHaveValue("quad9-threats");
    // Core lists its lookup modules (captured from core 826b4d6): the module is picked from them.
    await user.click(within(dialog).getByLabelText("Module"));
    await user.click(await screen.findByRole("option", { name: "dns" }));
    await user.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() => expect(mutations(calls).some((c) => c.path === "/lookup-providers")).toBe(true), T);
    expect(mutations(calls)[0].body).toMatchObject({ id: "quad9-threats", name: "Quad9 Threats", module: "dns" });
  });

  it("gives a new profile a DNS-label id from its name", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([
      { method: "POST", path: "/profiles", status: 201, body: (c: Call) => ({ id: (c.body as { id: string }).id, entity: c.body, warnings: [] }) },
      { method: "GET", path: "/profiles/kids-tablet", body: { id: "kids-tablet", name: "Kids' Tablet", allow: [], block: [], upstream: "cloudflare" } },
    ]);
    renderApp("/profiles/new");
    await user.type(await screen.findByLabelText("Name", undefined, T), "Kids' Tablet");
    expect(screen.getByLabelText("Id")).toHaveValue("kids-tablet");
    await user.click(screen.getByRole("button", { name: "Create profile" }));
    await waitFor(() => expect(mutations(calls).some((c) => c.path === "/profiles")).toBe(true), T);
    expect(mutations(calls)[0].body).toMatchObject({ id: "kids-tablet", name: "Kids' Tablet" });
  });
});

describe("UI10: Firefox install steps (browser-extension.md §1, security.md §5)", () => {
  it("describes the unsigned build, the editions and the pref, and the accepted risk", async () => {
    mockApi();
    renderApp("/extension");
    expect(await screen.findByText(/Developer Edition, Nightly or ESR/, undefined, T)).toBeInTheDocument();
    expect(screen.getByText(/xpinstall\.signatures\.required to false/)).toBeInTheDocument();
    expect(screen.getByText(/an unsigned \.xpi/)).toBeInTheDocument();
    expect(screen.getByText(/Install Add-on From File/)).toBeInTheDocument();
    expect(screen.getByText(/Accepted risk: .*every add-on in that Firefox profile/)).toBeInTheDocument();
    expect(screen.queryByText(/a signed \.xpi/)).toBeNull();
  });
});

describe("UI11: a provider with feeds can't be deleted (providers.md §2)", () => {
  it("offers no Delete while a feed uses it, and says why", async () => {
    const { fixtures } = mockApi();
    const feeds = structuredClone(fixtures["/feeds"]) as { items: Record<string, unknown>[] };
    feeds.items.push({ ...feeds.items[0], id: "hagezi-tif", provider: "hagezi", file: "adblock/tif.txt", system: false });
    mockApi([{ method: "GET", path: "/feeds", body: feeds }]);
    renderApp("/feed-providers/hagezi?tab=settings");
    expect(await screen.findByText(/can't be deleted while a feed uses it \(hagezi-tif\)/, undefined, T)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Delete/ })).toBeNull();
  });
});

describe("UI12: device views keep the device out of the path's last segment", () => {
  it("links with ?key= and renders the view from it", async () => {
    const { router } = renderApp("/clients/device?key=192.168.1.20");
    mockApi();
    expect(await screen.findByText("192.168.1.20", undefined, T)).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/clients/device");
  });
});

describe("UI13: alert selection follows the filter", () => {
  it("clears the selection on a filter change, so Delete never takes hidden alerts", async () => {
    const user = userEvent.setup();
    const alert = (id: number, state: string) => ({ id, type: "operational", severity: "warning", kind: "feed_down", dedupe_key: String(id), title: `alert ${id}`, state, count: 1, first_seen: "2026-11-23T00:00:00Z", last_seen: "2026-11-23T00:00:00Z" });
    const { calls } = mockApi([
      { method: "GET", path: "/alerts", body: (c: Call) => ({ items: [alert(c.query.get("state") === "resolved" ? 2 : 1, c.query.get("state") ?? "open")], next_cursor: null }) },
      { method: "DELETE", path: "/alerts", body: { deleted: 1 } },
    ]);
    renderApp("/alerts");
    await user.click(await screen.findByRole("checkbox", { name: "Select alert 1" }, T));
    expect(screen.getByRole("button", { name: "Delete 1" })).toBeInTheDocument();
    await user.click(screen.getByRole("combobox", { name: "State" }));
    await user.click(screen.getByRole("option", { name: /^resolved$/ }));
    await screen.findByRole("checkbox", { name: "Select alert 2" }, T);
    expect(screen.queryByRole("button", { name: /Delete \d/ })).toBeNull();
    await user.click(screen.getByRole("checkbox", { name: "Select alert 2" }));
    await user.click(screen.getByRole("button", { name: "Delete 1" }));
    await user.click(await screen.findByRole("button", { name: "Delete" }));
    await waitFor(() => expect(mutations(calls).some((c) => c.method === "DELETE")).toBe(true), T);
    expect(mutations(calls).find((c) => c.method === "DELETE")!.body).toEqual({ ids: [2] });
  });
});

describe("UI14: live updates refresh the feed and provider lists (api.md §7)", () => {
  it("invalidates the lists on feed_run and alert, and has no config event", () => {
    const qc = new QueryClient();
    const spy = vi.spyOn(qc, "invalidateQueries");
    const keys = () => spy.mock.calls.map((c) => JSON.stringify((c[0] as { queryKey?: unknown })?.queryKey ?? null));
    for (const frame of [feedRunFrame([{ feed: "f", run: 1 }]), alertFrame([{ id: 1, kind: "feed_added" }])]) {
      spy.mockClear();
      applyEvent(qc, frame);
      expect(keys()).toEqual(expect.arrayContaining(['["config","feeds"]', '["config","feed-providers"]']));
    }
    spy.mockClear();
    applyEvent(qc, { type: "config", data: {} });
    expect(spy).not.toHaveBeenCalled();
  });

  it("shows a feed a provider check discovered on an open Feeds page", async () => {
    const { fixtures } = mockApi();
    const feeds = structuredClone(fixtures["/feeds"]) as { items: Record<string, unknown>[] };
    let discovered = false;
    mockApi([{ method: "GET", path: "/feeds", body: () => (discovered ? { ...feeds, items: [...feeds.items, { ...feeds.items[0], id: "hagezi-new", name: "new.txt", provider: "hagezi", system: false }] } : feeds) }]);
    renderApp("/feeds");
    await screen.findByRole("link", { name: (fixtures["/feeds"] as { items: { name: string }[] }).items[3].name }, T);
    discovered = true;
    act(() => socket().emit(alertFrame([{ id: 1, kind: "feed_added" }])));
    expect(await screen.findByText("new.txt", undefined, T)).toBeInTheDocument();
  });
});

describe("UI15: 'not available yet' only for what core hasn't built (api/availability.ts)", () => {
  const notFound = (path: string) => new ApiError(404, "not_found", "no such UI API endpoint", [], null, path);
  it("tells a missing endpoint from a typo", () => {
    registerNotBuilt({ endpoints: ["/future", "/future-providers/{id}/flush"], series: ["future_series"] });
    expect(isNotAvailable(notFound("/future"))).toBe(true);
    expect(isNotAvailable(notFound("/future-providers/q9/flush"))).toBe(true);
    expect(isNotAvailable(notFound("/futures"))).toBe(false);
    expect(isNotAvailable(notFound(undefined as unknown as string))).toBe(false);
    expect(isNotAvailable(new ApiError(501, "not_implemented", "not implemented yet"))).toBe(true);
    expect(isNotAvailable(new ApiError(422, "invalid", 'unknown series "future_series"'))).toBe(true);
    expect(isNotAvailable(new ApiError(422, "invalid", 'unknown series "future_serie"'))).toBe(false);
  });

  it("lists nothing core 826b4d6 serves or records", () => {
    // Wave 5 built every endpoint and series the screens use: a 404 or unknown series is an error.
    for (const p of ["/top", "/logs", "/logs/x", "/devices", "/query-summary", "/trial-results", "/temp-allows", "/lookup-modules", "/lookup-modules/dns/presets/quad9", "/lookup-providers/q9/flush", "/lookup-providers/q9/test", "/lookup-providers/q9/status", "/alerts/1/evidence", "/dnssec/queue", "/dnssec/results", "/extension", "/config/export"]) {
      expect(isNotAvailable(notFound(p)), p).toBe(false);
    }
    for (const s of ["feed_hits", "trial_would_block", "rechecks", "recheck_blocks", "core_rss", "core_cpu_ms", "core_disk_used", "core_disk_free", "db_bytes", "queue_depth", "job_ms.p50", "evidence_bytes", "dnssec_results", "dnssec_fallback", "dnssec_answers", "dnssec_coverage", "crosscheck", "retro_hits", "wire_mismatch"]) {
      expect(isNotAvailable(new ApiError(422, "invalid", `unknown series ${JSON.stringify(s)}`)), s).toBe(false);
    }
  });

  it("charts the series core has when one isn't recorded yet, and errors on an unknown one", async () => {
    registerNotBuilt({ series: ["future_series"] });
    mockApi([
      {
        method: "GET",
        path: "/metrics",
        body: (c: Call) => {
          const asked = (c.query.get("series") ?? "").split(",");
          const unknown = asked.find((s) => !["log_records", "spool.bytes"].includes(s));
          if (unknown) return reply(422, { error: { code: "invalid", message: `unknown series ${JSON.stringify(unknown)}` } });
          return { step_s: 300, series: asked.map((name) => ({ name, labels: {}, edge: null, points: [[1_800_000_000, 1]] })) };
        },
      },
    ]);
    const chart = await fetchChart(["log_records", "future_series", "spool.bytes"], "24h", "all");
    expect(chart.unavailable).toEqual(["future_series"]);
    expect(chart.series.map((l) => l.name)).toEqual(["log_records", "spool.bytes"]);
    await expect(fetchChart(["log_records", "log_record"], "24h", "all")).rejects.toThrow(/unknown series "log_record"/);
    await expect(fetchChart(["future_series"], "24h", "all")).rejects.toSatisfy(isNotAvailable);
    // A series core records is an error when core doesn't know it (a wrong name in the UI).
    await expect(fetchChart(["wire_mismatch"], "24h", "all")).rejects.toThrow(/unknown series "wire_mismatch"/);
  });

  it("names the series a chart leaves out under it", async () => {
    // feed_hits is recorded since wave 5; registered here to test the mechanism.
    registerNotBuilt({ series: ["feed_hits"] });
    mockApi([
      {
        method: "GET",
        path: "/metrics",
        body: (c: Call) => {
          const asked = (c.query.get("series") ?? "").split(",");
          const unknown = asked.find((s) => isNotBuiltSeries(s));
          if (unknown) return reply(422, { error: { code: "invalid", message: `unknown series ${JSON.stringify(unknown)}` } });
          return { step_s: 300, series: [] };
        },
      },
    ]);
    renderApp("/feeds/manual-block?tab=metrics");
    // "Hits" asks only for feed_hits (registered as not recorded): not available; the others chart.
    expect(await screen.findByText("Hits: not available yet", undefined, T)).toBeInTheDocument();
    expect(screen.queryAllByText(/Core refused|went wrong/)).toHaveLength(0);
  });
});

describe("test mocks check what core accepts (test/contract.ts)", () => {
  it("flags bodies and queries core would refuse", () => {
    const q = (s = "") => new URLSearchParams(s);
    expect(contractViolations("POST", "/feeds", q(), { name: "x", provider: null, file: null })).toEqual([expect.stringMatching(/needs an id/)]);
    expect(contractViolations("POST", "/profiles", q(), { id: "kids-full", name: "x" })).toEqual([expect.stringMatching(/isn't a valid id/)]);
    expect(contractViolations("POST", "/feeds/import", q("id=x&format=text"), { file: "a" })).toEqual([expect.stringMatching(/format=text/)]);
    expect(contractViolations("POST", "/feeds/import", q("id=x"), { text: "a" }).length).toBeGreaterThan(0);
    expect(contractViolations("PUT", "/feeds/x/file", q(), { content: "a" })).toEqual([expect.stringMatching(/base_version: required/)]);
    expect(contractViolations("POST", "/feeds/x/file/lines", q(), { lines: ["a\nb"] })).toEqual([expect.stringMatching(/line break/)]);
    expect(contractViolations("POST", "/feeds/x/import", q("mode=merge&base=1"), { file: "a" })).toEqual([expect.stringMatching(/ignores the query parameter base/)]);
    expect(contractViolations("GET", "/feedz", q(), undefined)).toEqual([expect.stringMatching(/no such endpoint/)]);
    expect(contractViolations("GET", "/top", q("kind=blocked"), undefined)).toEqual([]);
    expect(contractViolations("POST", "/feeds", q(), { id: "ok-id", name: "x", provider: null, file: null })).toEqual([]);
  });
});
