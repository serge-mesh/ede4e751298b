// Final-check fixes for the UI at 5d53a3f (dev/briefs/fix-5d5-ui.md): R1 the restoring tab waits
// for its restore's own event only on the socket that was open as it sent the restore; R2 a
// restore during the editor's first download reads the restored file; R3 reads begun before a
// restore are discarded; R4 a restore ends a save's wait for its run; R5 a feed's export size reads
// again only on its own runs. Built on the reviewers' probes (dev/briefs/r07/final5-*-probe*.tsx).
import { describe, expect, it, vi } from "vitest";
import { act, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { toast } from "sonner";
import { EditorView } from "@codemirror/view";
import { mockApi, mutations, reply, type Call, type Route } from "@/test/mock-api";
import { manualCore } from "@/test/manual-core";
import { renderApp } from "@/test/render";
import { feedRunFrame, truncatedRunFrame } from "@/test/events";
import { W5 } from "@/test/core-w5";
import { beforeRestoreEvent, restoreSent, resyncForRestore } from "@/api/events";
import { qk } from "@/api/queries";

const T = { timeout: 8000 };
const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));
const gets = (calls: Call[], path: string) => calls.filter((c) => c.method === "GET" && c.path === path);

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

/** An export's save time: older than every save the page saw (core keeps a restored file's own). */
const EXPORTED_AT = "2026-11-20T08:00:00.000000Z";
const RESTORED = "||restored.example^\n";
const RESTORE_DISCARDED = "A restore replaced the file before this save's run: the save was discarded.";
const RESTORE_UNCHECKED = "A restore replaced the file before this save's run, and the file couldn't be read to check whether the save survived: reload it to see.";
const editorView = () => EditorView.findFromDOM(screen.getByTestId("code-editor").querySelector(".cm-editor") as HTMLElement)!;
const editorText = () => editorView().state.doc.toString();
const typeAtEnd = (text: string) => act(() => editorView().dispatch({ changes: { from: editorView().state.doc.length, insert: text } }));
/** Core's `restore` event (RestoreEvent). */
const restoreEvent = (generation: number) => ({ type: "restore", data: { at: "2026-11-23T12:00:00.000000Z", generation } });

type Core = ReturnType<typeof manualCore>;
const routeOf = (core: Core, method: string, path: string) => core.routes.find((r) => r.method === method && r.path === path)!;
/**
 * A route of `core` whose answers `gate` holds: while it returns a promise, an answer (as core
 * gave it when asked, or, with `late`, as core gives it when let go) waits for it.
 */
function held(core: Core, method: string, path: string, gate: () => Promise<void> | null, late = false): Route {
  const route = routeOf(core, method, path);
  const answer = (c: Call) => (route.body as (c: Call) => unknown)(c);
  return {
    method,
    path,
    body: async (c: Call) => {
      const g = gate();
      if (late) {
        if (g) await g;
        return answer(c);
      }
      const a = answer(c);
      if (g) await g;
      return a;
    },
  };
}
/** A gate: after `hold()`, answers wait until `release()`; after `pass()`, answers asked for from then on don't (those waiting still do). */
function gate() {
  let current: Promise<void> | null = null;
  let open = () => {};
  return {
    get: () => current,
    hold: () => {
      current = new Promise<void>((r) => (open = r));
    },
    pass: () => {
      current = null;
    },
    release: () => {
      current = null;
      open();
    },
  };
}

/** The feed's page with its editor open on an open socket. */
async function openEditor(core: Core, extra: Route[] = []) {
  const { calls } = mockApi([...extra, ...core.routes]);
  const rendered = renderApp("/feeds/manual-block");
  await screen.findByTestId("code-editor", undefined, T);
  act(() => socket().open());
  await pause(300);
  return { calls, ...rendered };
}
/** Later runs checks (an event listing only some runs, twice) download nothing more. */
async function settled(core: Core) {
  const reads = core.st.fileReads;
  act(() => socket().emit(truncatedRunFrame()));
  await pause(400);
  act(() => socket().emit(truncatedRunFrame()));
  await pause(400);
  expect(core.st.fileReads).toBe(reads);
}
/** Another writer's save after everything, its run stored and announced: the open editor takes it. */
async function takesLaterSave(core: Core) {
  const later = core.finishRun(core.append("||a-real-later-save.example^"));
  act(() => socket().emit(feedRunFrame([core.item(later)])));
  await waitFor(() => expect(editorText()).toBe(core.st.content), T);
}

describe("R1: the restoring tab waits for its restore's own event only on the socket open as it sent the restore (Opus FO5-3, Codex FC5-1)", () => {
  it("the socket reconnects between the restore's event and its answer: no wait, later saves are taken", async () => {
    const core = manualCore();
    const { queryClient } = await openEditor(core);
    const sent = restoreSent();
    core.restore(RESTORED, EXPORTED_AT);
    act(() => socket().emit(restoreEvent(1)));
    await waitFor(() => expect(editorText()).toBe(RESTORED), T);
    await reconnect();
    act(() => resyncForRestore(queryClient, 1, sent));
    expect(beforeRestoreEvent(queryClient)).toBe(false);
    await pause(300);
    await takesLaterSave(core);
  });

  it("the restore commits while the socket is down and it opens before the answer: no wait, later saves are taken", async () => {
    const core = manualCore();
    mockApi(core.routes);
    const { queryClient } = renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    // Sent while the socket connects: core broadcasts the restore before this socket subscribes.
    const sent = restoreSent();
    core.restore(RESTORED, EXPORTED_AT);
    act(() => socket().open());
    act(() => resyncForRestore(queryClient, 1, sent));
    expect(beforeRestoreEvent(queryClient)).toBe(false);
    await waitFor(() => expect(editorText()).toBe(RESTORED), T);
    await pause(300);
    await takesLaterSave(core);
  });

  it("the socket opens during the restore, before it commits: the answer re-reads, and the restore's own event re-reads again, resetting what the events before it said", async () => {
    const core = manualCore();
    mockApi(core.routes);
    const { queryClient } = renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    const sent = restoreSent();
    act(() => socket().open());
    await pause(300);
    // Another writer's save is stored before the restore commits; its event goes out after the
    // restore's answer, then the restore's own event (core sends what it noted first).
    const before = core.item(core.finishRun(core.append("||before-restore.example^")));
    core.restore(RESTORED, EXPORTED_AT);
    act(() => resyncForRestore(queryClient, 1, sent));
    await waitFor(() => expect(editorText()).toBe(RESTORED), T);
    act(() => socket().emit(feedRunFrame([before])));
    await pause(300);
    act(() => socket().emit(restoreEvent(1)));
    await pause(300);
    expect(editorText()).toBe(RESTORED);
    await settled(core);
    await takesLaterSave(core);
  });

  it("an event of a later restore ends the wait too (generations only grow on one socket)", async () => {
    mockApi([]);
    const { queryClient } = renderApp("/");
    await waitFor(() => expect(sockets().length).toBeGreaterThan(0), T);
    act(() => socket().open());
    act(() => resyncForRestore(queryClient, 2, restoreSent()));
    expect(beforeRestoreEvent(queryClient)).toBe(true);
    act(() => socket().emit(restoreEvent(3)));
    expect(beforeRestoreEvent(queryClient)).toBe(false);
  });

  /** Settings → Export and restore with its answer held until `release`. */
  async function heldRestore() {
    const user = userEvent.setup();
    const answer = gate();
    answer.hold();
    mockApi([
      {
        method: "PUT",
        path: "/config/export",
        body: async () => {
          await answer.get();
          return { restored: true, generation: 1, missing_secrets: [], warnings: [] };
        },
      },
    ]);
    const n = sockets().length;
    const { queryClient } = renderApp("/settings?tab=export");
    const input = await screen.findByLabelText("File", undefined, T);
    await waitFor(() => expect(sockets().length).toBe(n + 1), T);
    act(() => socket().open());
    const doc = new File([JSON.stringify(W5["GET /config/export"])], "picket-config.json", { type: "application/json" });
    await user.upload(input, doc);
    await user.click(await screen.findByRole("button", { name: /^Restore$/ }, T));
    await user.click(await screen.findByRole("button", { name: "Restore" }));
    return { queryClient, release: answer.release };
  }

  it("Settings: a socket that reconnects while the restore is out doesn't wait for its event", async () => {
    const { queryClient, release } = await heldRestore();
    await pause(100);
    await reconnect();
    release();
    await screen.findByTestId("restore-result", undefined, T);
    expect(beforeRestoreEvent(queryClient)).toBe(false);
  });

  it("Settings: a socket open throughout waits for it", async () => {
    const { queryClient, release } = await heldRestore();
    await pause(100);
    release();
    await screen.findByTestId("restore-result", undefined, T);
    expect(beforeRestoreEvent(queryClient)).toBe(true);
  });
});

describe("R2: a restore during the editor's first download opens it on the restored file (Codex FC5-2)", () => {
  it("reads the file again: the editor opens on the restored file and saves with its base", async () => {
    const core = manualCore();
    const g = gate();
    g.hold();
    const { calls } = mockApi([held(core, "GET", "/feeds/manual-block/file", g.get), ...core.routes]);
    renderApp("/feeds/manual-block");
    await waitFor(() => expect(core.st.fileReads).toBe(1), T);
    act(() => socket().open());
    core.restore(RESTORED, EXPORTED_AT);
    act(() => socket().emit(restoreEvent(1)));
    await pause(300);
    g.release();
    await screen.findByTestId("code-editor", undefined, T);
    await pause(300);
    expect(editorText()).toBe(RESTORED);
    expect(core.st.fileReads).toBe(2);
    typeAtEnd("||mine.example^\n");
    await userEvent.setup().click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(mutations(calls).filter((c) => c.method === "PUT")).toHaveLength(1), T);
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    expect(screen.queryByText("The file changed since you opened it")).toBeNull();
  });
});

describe("R2: a restore during another read of the open editor's file", () => {
  it("a read out that isn't a reload (e.g. a refetch on opening): the restored file is read once, and taken", async () => {
    const core = manualCore();
    const g = gate();
    const { queryClient } = await openEditor(core, [held(core, "GET", "/feeds/manual-block/file", g.get)]);
    g.hold();
    void queryClient.refetchQueries({ queryKey: qk.manualFile("manual-block") });
    await waitFor(() => expect(core.st.fileReads).toBe(2), T);
    core.restore(RESTORED, EXPORTED_AT);
    act(() => socket().emit(restoreEvent(1)));
    await pause(200);
    g.release();
    await waitFor(() => expect(editorText()).toBe(RESTORED), T);
    await pause(300);
    expect(core.st.fileReads).toBe(3);
    await settled(core);
  });
});

describe("R3: reads begun before a restore are discarded (Codex FC5-3)", () => {
  it("a runs answer read before the restore doesn't bring back the replaced save: no reloads after", async () => {
    const core = manualCore();
    const g = gate();
    const { calls } = await openEditor(core, [held(core, "GET", "/feeds/manual-block/runs", g.get)]);
    const runsReads = gets(calls, "/feeds/manual-block/runs").length;
    g.hold();
    act(() => socket().emit(truncatedRunFrame()));
    await waitFor(() => expect(gets(calls, "/feeds/manual-block/runs").length).toBe(runsReads + 1), T);
    // Only that read waits (answered as core was before the restore: the original save's run).
    g.pass();
    core.restore(RESTORED, EXPORTED_AT);
    act(() => socket().emit(restoreEvent(1)));
    await waitFor(() => expect(editorText()).toBe(RESTORED), T);
    expect(core.st.fileReads).toBe(2);
    g.release();
    await pause(400);
    expect(core.st.fileReads).toBe(2);
    await settled(core);
  });

  it("a file answer read before the restore (a reload out) doesn't bring back the replaced save: the restored file is read once", async () => {
    const core = manualCore();
    const g = gate();
    const slow = { on: false };
    const file = routeOf(core, "GET", "/feeds/manual-block/file");
    // A held reload; once the restore is in, each read takes a while, as over a network (the page
    // renders the answers it already has meanwhile).
    await openEditor(core, [
      {
        method: "GET",
        path: "/feeds/manual-block/file",
        body: async (c: Call) => {
          const a = (file.body as (c: Call) => unknown)(c);
          const wait = g.get();
          if (wait) await wait;
          if (slow.on) await pause(150);
          return a;
        },
      },
    ]);
    g.hold();
    const run = core.finishRun(core.append("||elsewhere.example^"));
    act(() => socket().emit(feedRunFrame([core.item(run)])));
    await waitFor(() => expect(core.st.fileReads).toBe(2), T);
    core.restore(RESTORED, EXPORTED_AT);
    slow.on = true;
    const info = vi.spyOn(toast, "info");
    act(() => socket().emit(restoreEvent(1)));
    await pause(200);
    g.release();
    await waitFor(() => expect(editorText()).toBe(RESTORED), T);
    await pause(400);
    expect(core.st.fileReads).toBe(3);
    // The reload that was out took the restored file as the restore's.
    expect(info.mock.calls.map(([m]) => m)).toEqual(["A restore replaced the file: reloaded."]);
    info.mockRestore();
    await settled(core);
  });

  it("a status answer read before the restore (a waiting save's poll), landing before the restore's file read, doesn't bring back the replaced save", async () => {
    const core = manualCore();
    const status = gate();
    const file = gate();
    const { calls } = await openEditor(core, [held(core, "GET", "/feeds/manual-block/status", status.get), held(core, "GET", "/feeds/manual-block/file", file.get)]);
    typeAtEnd("||mine.example^\n");
    status.hold();
    await userEvent.setup().click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    // The poll's first status read is out, answered as core was before the restore (the save, busy).
    await waitFor(() => expect(gets(calls, "/feeds/manual-block/status").length).toBeGreaterThan(0), T);
    status.pass();
    file.hold();
    core.restore(RESTORED, EXPORTED_AT);
    act(() => socket().emit(restoreEvent(1)));
    await waitFor(() => expect(core.st.fileReads).toBe(2), T);
    status.release();
    await pause(300);
    file.release();
    await waitFor(() => expect(editorText()).toBe(RESTORED), T);
    expect(await screen.findByText(RESTORE_DISCARDED, undefined, T)).toBeInTheDocument();
    await pause(300);
    expect(core.st.fileReads).toBe(2);
    await settled(core);
  });
});

describe("R4: a restore ends a save's wait for its run (Opus FO5-1)", () => {
  /** The editor with its save of `||mine.example^` waiting for its run (core busy with it). */
  async function waitingSave(extra: Route[] = [], core = manualCore()) {
    const r = await openEditor(core, extra);
    typeAtEnd("||mine.example^\n");
    await userEvent.setup().click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(mutations(r.calls).filter((c) => c.method === "PUT")).toHaveLength(1), T);
    return { core, ...r };
  }

  it("another tab's restore lands while the save waits: the wait ends saying the save was discarded, never that core made no new run", async () => {
    const { core } = await waitingSave();
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    const v = core.restore(RESTORED, EXPORTED_AT);
    core.st.busy = true;
    act(() => socket().emit(restoreEvent(1)));
    await waitFor(() => expect(editorText()).toBe(RESTORED), T);
    expect(await screen.findByText(RESTORE_DISCARDED, undefined, T)).toBeInTheDocument();
    expect(screen.queryByText(/Waiting for the run's result/)).toBeNull();
    // The restored file's run is stored and announced; the poll has stopped.
    const statusReads = core.st.statusReads;
    const id = core.finishRun(v);
    act(() => socket().emit(feedRunFrame([core.item(id)])));
    await pause(2500);
    expect(screen.queryByText(/Core made no new run/)).toBeNull();
    expect(screen.getByText(RESTORE_DISCARDED)).toBeInTheDocument();
    expect(core.st.statusReads).toBe(statusReads);
  });

  it("a save the restore overtook (saved before it, answered after): the wait ends saying it was discarded", async () => {
    const core = manualCore();
    const g = gate();
    g.hold();
    await waitingSave([held(core, "PUT", "/feeds/manual-block/file", g.get)], core);
    // The save is stored as sent; the restore replaces it before its answer comes.
    const saved = core.st.content;
    expect(saved).toContain("||mine.example^");
    core.restore(RESTORED, EXPORTED_AT);
    act(() => socket().emit(restoreEvent(1)));
    await pause(300);
    g.release();
    expect(await screen.findByText(RESTORE_DISCARDED, undefined, T)).toBeInTheDocument();
    await waitFor(() => expect(editorText()).toBe(RESTORED), T);
    expect(screen.queryByText(/Waiting for the run's result/)).toBeNull();
    await settled(core);
    await takesLaterSave(core);
  });

  it("a save the restore overtook, shown before the restore's file read lands (a slow read): its save isn't taken back, no reloads after", async () => {
    const core = manualCore();
    const put = gate();
    const slow = { on: false };
    const file = routeOf(core, "GET", "/feeds/manual-block/file");
    put.hold();
    await waitingSave(
      [
        held(core, "PUT", "/feeds/manual-block/file", put.get),
        {
          method: "GET",
          path: "/feeds/manual-block/file",
          body: async (c: Call) => {
            const a = (file.body as (c: Call) => unknown)(c);
            if (slow.on) await pause(200);
            return a;
          },
        },
      ],
      core,
    );
    core.restore(RESTORED, EXPORTED_AT);
    act(() => socket().emit(restoreEvent(1)));
    await waitFor(() => expect(core.st.fileReads).toBe(2), T);
    await pause(300);
    slow.on = true;
    put.release();
    expect(await screen.findByText(RESTORE_DISCARDED, undefined, T)).toBeInTheDocument();
    await waitFor(() => expect(editorText()).toBe(RESTORED), T);
    await pause(400);
    expect(core.st.fileReads).toBe(3);
    await settled(core);
  });

  it("the restore's file read fails: the wait ends saying the save's fate couldn't be checked, never that it was discarded (final check FO6-2)", async () => {
    const core = manualCore();
    const failing = { on: false };
    const file = routeOf(core, "GET", "/feeds/manual-block/file");
    await waitingSave([{ method: "GET", path: "/feeds/manual-block/file", body: (c: Call) => (failing.on ? reply(500, { error: { code: "internal", message: "database is locked" } }) : (file.body as (c: Call) => unknown)(c)) }], core);
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    failing.on = true;
    core.restore(RESTORED, EXPORTED_AT);
    act(() => socket().emit(restoreEvent(1)));
    expect(await screen.findByText(RESTORE_UNCHECKED, undefined, T)).toBeInTheDocument();
    expect(screen.queryByText(RESTORE_DISCARDED)).toBeNull();
    expect(screen.queryByText(/Waiting for the run's result/)).toBeNull();
  });

  it("a save made after the restore lands while the restore's slow file read is out (that read predates it): the read is sent again, so the save still waits and its run is shown (final check FC6-1/FO6-1)", async () => {
    const core = manualCore();
    const put = gate();
    const slow = { on: false };
    const file = routeOf(core, "GET", "/feeds/manual-block/file");
    put.hold();
    await waitingSave(
      [
        // Core takes the save when its request is let go: after the restore.
        held(core, "PUT", "/feeds/manual-block/file", put.get, true),
        {
          method: "GET",
          path: "/feeds/manual-block/file",
          body: async (c: Call) => {
            // The answer is what the file is when the read arrives; a slow one comes later.
            const a = (file.body as (c: Call) => unknown)(c);
            if (slow.on) await pause(400);
            return a;
          },
        },
      ],
      core,
    );
    const original = core.st.content;
    slow.on = true;
    core.restore(original, EXPORTED_AT);
    act(() => socket().emit(restoreEvent(1)));
    await waitFor(() => expect(core.st.fileReads).toBe(2), T);
    put.release();
    await waitFor(() => expect(core.st.content).toBe(`${original}||mine.example^\n`), T);
    await pause(1200);
    expect(screen.queryByText(RESTORE_DISCARDED)).toBeNull();
    expect(screen.getByText(/Waiting for the run's result/)).toBeInTheDocument();
    slow.on = false;
    const mine = core.finishRun();
    act(() => socket().emit(feedRunFrame([core.item(mine)])));
    expect(await screen.findByText(`Run ${mine}`, undefined, T)).toBeInTheDocument();
  });

  it("a save made after the restore (the restored file had the text it was based on): it still waits, and its run is shown", async () => {
    const core = manualCore();
    const g = gate();
    g.hold();
    // Core takes the save when its request is let go: after the restore.
    await waitingSave([held(core, "PUT", "/feeds/manual-block/file", g.get, true)], core);
    const original = core.st.content;
    core.restore(original, EXPORTED_AT);
    act(() => socket().emit(restoreEvent(1)));
    await pause(300);
    g.release();
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    await waitFor(() => expect(core.st.fileReads).toBe(3), T);
    await pause(300);
    expect(screen.queryByText(RESTORE_DISCARDED)).toBeNull();
    expect(core.st.content).toBe(`${original}||mine.example^\n`);
    const mine = core.finishRun();
    act(() => socket().emit(feedRunFrame([core.item(mine)])));
    expect(await screen.findByText(`Run ${mine}`, undefined, T)).toBeInTheDocument();
  });

  it("the poll finds core idle on the restored file's run before the restore's file read lands: it leaves the wait to that read", async () => {
    const core = manualCore();
    const file = gate();
    await waitingSave([held(core, "GET", "/feeds/manual-block/file", file.get)], core);
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    // The restore, and the restored file's run already stored: core is idle on it.
    file.hold();
    core.finishRun(core.restore(RESTORED, EXPORTED_AT));
    // The restore's resync polls at once: status and runs read, core idle.
    const statusReads = core.st.statusReads;
    act(() => socket().emit(restoreEvent(1)));
    await waitFor(() => expect(core.st.fileReads).toBe(2), T);
    await waitFor(() => expect(core.st.statusReads).toBeGreaterThan(statusReads), T);
    await pause(300);
    expect(screen.queryByText(/Core made no new run/)).toBeNull();
    file.release();
    expect(await screen.findByText(RESTORE_DISCARDED, undefined, T)).toBeInTheDocument();
    await pause(300);
    expect(screen.queryByText(/Core made no new run/)).toBeNull();
  });

  it("a wait the restore found ends on its run before the restore's file read lands: that read leaves the run's result", async () => {
    const core = manualCore();
    const put = gate();
    const file = gate();
    put.hold();
    await waitingSave([held(core, "PUT", "/feeds/manual-block/file", put.get, true), held(core, "GET", "/feeds/manual-block/file", file.get, true)], core);
    // The restore brings back the text the save was based on; the save is taken after it.
    core.restore(core.st.content, EXPORTED_AT);
    act(() => socket().emit(restoreEvent(1)));
    await waitFor(() => expect(core.st.fileReads).toBe(2), T);
    await pause(200);
    file.hold();
    put.release();
    await screen.findByText(/Waiting for the run's result/, undefined, T);
    // The save's run comes while the file read the overtaken save asked for is out; then another
    // writer saves, so that read finds a later file.
    const mine = core.finishRun();
    act(() => socket().emit(feedRunFrame([core.item(mine)])));
    expect(await screen.findByText(`Run ${mine}`, undefined, T)).toBeInTheDocument();
    core.append("||other.example^");
    file.release();
    await waitFor(() => expect(core.st.fileReads).toBe(3), T);
    await pause(300);
    expect(screen.getByText(`Run ${mine}`)).toBeInTheDocument();
    expect(screen.queryByText(RESTORE_DISCARDED)).toBeNull();
  });
});

describe("R5: a feed's export size reads again only on its own runs (Opus FO5-2)", () => {
  it("an event listing another feed's run leaves it; one listing its run reads it once", async () => {
    const core = manualCore();
    const { calls, queryClient } = await openEditor(core);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    const sizes = () => gets(calls, "/feeds/manual-block/export-size").length;
    const n = sizes();
    expect(n).toBeGreaterThan(0);
    act(() => socket().emit(feedRunFrame([{ feed: "hagezi-tif", run: 60 }])));
    await pause(400);
    expect(sizes()).toBe(n);
    act(() => socket().emit(feedRunFrame([core.item(core.finishRun(core.append("||x.example^")))])));
    await waitFor(() => expect(sizes()).toBe(n + 1), T);
  });
});
