// Polish of the UI at 9c3bf0a (dev/briefs/polish-ui.md): U1 views kept fresh only by events read
// once more when the event socket first opens (Opus FO5-5); U2 the restoring tab's wait for its
// restore's own event is bounded (Opus FO6-3). And a Codex polish survey's items
// (dev/briefs/polish-codex-ui.md): V1 drafts survive tab switches and a sheet asks before dropping
// one; V2 a provider's unknown status isn't shown as healthy; V3 invalid JSON text blocks a save;
// V4 a failed refresh keeps loaded charts and journal rows; V5 map values are named by their key
// and field; V6 ordered pickers are labelled groups. And core's polish (dev/briefs/polish-core-report.md):
// the alerts.temporary_allow switch, a restore whose upload stalls (408), the temporary_allow and
// bundle_cold_share alerts' details.
import * as React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { EditorView } from "@codemirror/view";
import { mockApi, mutations, reply, type Call } from "@/test/mock-api";
import { W5 } from "@/test/core-w5";
import { renderApp } from "@/test/render";
import { alertFrame, feedRunFrame, jobFrame, truncatedAlertFrame, truncatedRunFrame } from "@/test/events";
import { RESTORE_EVENT_WAIT_MS, applyEvent, beforeRestoreEvent, isRestore, keptByEvents, restoreSent, resyncForRestore, useEventStream, useUiEvent, type UiEvent } from "@/api/events";
import { qk } from "@/api/queries";
import { toApiError } from "@/api/errors";
import { makeQueryClient } from "@/lib/query-client";
import { SchemaForm } from "@/components/schema-form/schema-form";
import { MetricPanel } from "@/components/charts/metric-panel";
import { TooltipProvider } from "@/components/ui/tooltip";

const T = { timeout: 8000 };
const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));
const gets = (calls: Call[], path: string, limit?: string) => calls.filter((c) => c.method === "GET" && c.path === path && (limit === undefined || c.query.get("limit") === limit));

interface FakeSocket {
  open(): void;
  emit(data: unknown): void;
  onclose: (() => void) | null;
}
const sockets = () => (globalThis.WebSocket as unknown as { instances: FakeSocket[] }).instances;
const socket = () => sockets().at(-1)!;

describe("U1: views kept fresh only by events read once more when the event socket first opens (Opus FO5-5)", () => {
  /** Opens the socket once the page's reads have landed; each count's reads from then, once they settle. */
  async function openAfterReads(queryClient: QueryClient, counts: (() => number)[]) {
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    const before = counts.map((n) => n());
    act(() => socket().open());
    await pause(300);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    return counts.map((n, i) => n() - before[i]);
  }

  it("the open-alerts badge and the alert list: one more read each, then none (events keep them fresh)", async () => {
    const { calls } = mockApi();
    const { queryClient } = renderApp("/alerts");
    await screen.findByRole("heading", { name: "Alerts" }, T);
    // The badge reads every open alert (500 a page); the list, its first 100.
    const badge = () => gets(calls, "/alerts", "500").length;
    const list = () => gets(calls, "/alerts", "100").length;
    await waitFor(() => expect([badge(), list()]).toEqual([1, 1]), T);
    expect(await openAfterReads(queryClient, [badge, list])).toEqual([1, 1]);
    await pause(300);
    expect([badge(), list()]).toEqual([2, 2]);
  });

  it("every feed's statuses (the feeds page): one more read, then none", async () => {
    const { calls } = mockApi();
    const { queryClient } = renderApp("/feeds");
    const statuses = () => gets(calls, "/feed-status").length;
    await waitFor(() => expect(statuses()).toBe(1), T);
    expect(await openAfterReads(queryClient, [statuses])).toEqual([1]);
    await pause(300);
    expect(statuses()).toBe(2);
  });

  it("an open manual feed: its definition and export size read once more; its file (the editor decides) doesn't", async () => {
    const { calls } = mockApi();
    const { queryClient } = renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    const reads = ["/feeds/manual-block", "/feeds/manual-block/export-size", "/feeds/manual-block/file"].map((p) => () => gets(calls, p).length);
    expect(await openAfterReads(queryClient, reads)).toEqual([1, 1, 0]);
  });

  it("names exactly the queries an event marks stale (unit)", () => {
    // A query of every shape the UI reads, by key.
    const keys: (readonly unknown[])[] = [
      qk.identity,
      qk.settings,
      qk.issues,
      qk.changes,
      qk.secrets,
      qk.config("feeds"),
      qk.config("feed-providers"),
      qk.config("bundles"),
      qk.config("profiles"),
      qk.entity("feeds", "manual-block"),
      qk.entity("profiles", "kids"),
      qk.edges,
      qk.edgeStatus("e1"),
      qk.edgeConfig("e1"),
      qk.pending,
      qk.alerts({ state: "open", all: true }),
      qk.alerts({ state: "open" }),
      qk.alert(7),
      qk.alertEvidence(7),
      [...qk.tempAllows, "active", "e1"],
      [...qk.querySummary, "device", "24h", "all"],
      [...qk.dnssecResults, "all"],
      qk.dnssecQueue,
      qk.metrics(["queries"], "24h", "all"),
      qk.jobs,
      qk.browserLists,
      qk.bundleStatus,
      qk.bundle("block-common", "status"),
      qk.bundle("block-common", "versions"),
      qk.downloadModules,
      qk.lookupModules,
      qk.presets,
      qk.providerStatus,
      qk.provider("hagezi", "status"),
      [...qk.provider("hagezi", "listing"), "prefix", "adblock/"],
      [...qk.provider("hagezi", "listing"), "q", "tif"],
      qk.provider("hagezi", "backtest"),
      qk.review,
      qk.feedStatus,
      qk.feedStatusRead,
      qk.feed("manual-block", "runs"),
      qk.feed("manual-block", "export-size"),
      qk.manualFile("manual-block"),
      qk.warninglists,
      ["extension"],
      ["devices"],
      ["lookup-modules"],
      ["lookup-status", "p1"],
      ["logs", {}],
      ["top", "domains", "24h", "all"],
      ["trial-results", "kids", "block-common", "24h", "all"],
    ];
    // Every event type but `restore` and `lagged` (they read everything), each as widely as core
    // sends it: lists that say they are truncated, data that can't be read.
    const frames: UiEvent[] = [
      truncatedAlertFrame(),
      alertFrame([{ id: 7 }]),
      { type: "edge_status", data: { edge: "e1", event: "hello" } },
      { type: "temp_allow", data: { edges: [], edges_truncated: true } },
      { type: "dnssec", data: null },
      { type: "dnssec_queued", data: {} },
      { type: "lanca", data: { event: "rotated", root: "SHA256:b", previous: "SHA256:a", current: "SHA256:b" } },
      { type: "lanca_served", data: {} },
      jobFrame("bundle_build", "block-common", "end", { dropped: 3 }),
      truncatedRunFrame(),
      feedRunFrame([{ feed: "manual-block", run: 4 }]),
      { type: "bundle_version", data: {} },
    ];
    const marked = new Set<string>();
    for (const frame of frames) {
      const qc = new QueryClient();
      for (const k of keys) qc.setQueryData(k, {});
      // An edge keeping a previous LAN CA root in use: its session changes read the settings too.
      qc.setQueryData(qk.settings, { lanca: { previous: [{ edges: [{ edge_id: "e1" }] }] } });
      applyEvent(qc, frame);
      for (const k of keys) if (qc.getQueryCache().find({ queryKey: k, exact: true })?.state.isInvalidated) marked.add(JSON.stringify(k));
    }
    // A closed editor's file is marked stale, never read; an open one's editor decides.
    const file = JSON.stringify(qk.manualFile("manual-block"));
    expect(marked.has(file)).toBe(true);
    expect(keys.filter((k) => keptByEvents(k)).map((k) => JSON.stringify(k))).toEqual(keys.map((k) => JSON.stringify(k)).filter((k) => marked.has(k) && k !== file));
    // Not a backtest (read only when Run asks), a manual feed's file or an alert's evidence (their pages decide).
    expect([qk.provider("hagezi", "backtest"), qk.manualFile("manual-block"), qk.alertEvidence(7)].map((k) => keptByEvents(k))).toEqual([false, false, false]);
  });
});

describe("U2: the restoring tab's wait for its restore's own event is bounded (Opus FO6-3)", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  /** The event stream alone (no page and its timers), and the listener events it gives. */
  function stream() {
    const qc = new QueryClient();
    const heard: UiEvent[] = [];
    function Stream() {
      useEventStream();
      return null;
    }
    function Listener() {
      useUiEvent((ev) => heard.push(ev));
      return null;
    }
    const n = sockets().length;
    const app = render(
      <QueryClientProvider client={qc}>
        <Stream />
      </QueryClientProvider>,
    );
    render(<Listener />);
    expect(sockets().length).toBe(n + 1);
    act(() => socket().open());
    return { qc, heard, app };
  }

  it("its event never comes on the socket open as the restore was sent (core subscribed it after the commit): the wait ends after RESTORE_EVENT_WAIT_MS with a resync, and a late event re-reads once more", () => {
    const { qc, heard } = stream();
    vi.useFakeTimers();
    act(() => resyncForRestore(qc, 4, restoreSent()));
    expect(beforeRestoreEvent(qc)).toBe(true);
    expect(heard.filter(isRestore)).toHaveLength(1);
    act(() => void vi.advanceTimersByTime(RESTORE_EVENT_WAIT_MS - 1));
    expect(beforeRestoreEvent(qc)).toBe(true);
    act(() => void vi.advanceTimersByTime(1));
    expect(beforeRestoreEvent(qc)).toBe(false);
    // The events skipped meanwhile came after the restore: listeners check again (an open editor reads its runs).
    expect(heard.map((e) => e.type)).toEqual(["resync", "resync"]);
    expect(isRestore(heard[1])).toBe(false);
    // The restore's event, should it still come: it re-reads as a restore, resetting what the events before it said.
    act(() => socket().emit({ type: "restore", data: { at: "2026-11-25T12:00:00.000000Z", generation: 4 } }));
    expect(heard.filter(isRestore)).toHaveLength(2);
    expect(beforeRestoreEvent(qc)).toBe(false);
  });

  it("its event coming in time ends it, and the timer with it: nothing more at RESTORE_EVENT_WAIT_MS", () => {
    const { qc, heard } = stream();
    vi.useFakeTimers();
    act(() => resyncForRestore(qc, 4, restoreSent()));
    act(() => socket().emit({ type: "restore", data: { at: "2026-11-25T12:00:00.000000Z", generation: 4 } }));
    expect(beforeRestoreEvent(qc)).toBe(false);
    act(() => void vi.advanceTimersByTime(RESTORE_EVENT_WAIT_MS));
    expect(heard.filter((e) => e.type === "resync")).toHaveLength(1);
  });

  it("the socket closes while it waits: the wait ends, and nothing comes at RESTORE_EVENT_WAIT_MS (the reopened socket re-reads)", () => {
    const { qc, heard } = stream();
    vi.useFakeTimers();
    act(() => resyncForRestore(qc, 4, restoreSent()));
    act(() => socket().onclose?.());
    expect(beforeRestoreEvent(qc)).toBe(false);
    // The page reconnects after its backoff; that socket isn't open yet.
    act(() => void vi.advanceTimersByTime(RESTORE_EVENT_WAIT_MS));
    expect(heard.map((e) => e.type)).toEqual(["resync"]);
  });

  it("a later restore's answer on the same socket waits anew: the earlier wait's time doesn't end it", () => {
    const { qc, heard } = stream();
    vi.useFakeTimers();
    act(() => resyncForRestore(qc, 4, restoreSent()));
    act(() => void vi.advanceTimersByTime(RESTORE_EVENT_WAIT_MS / 2));
    act(() => resyncForRestore(qc, 5, restoreSent()));
    act(() => void vi.advanceTimersByTime(RESTORE_EVENT_WAIT_MS / 2));
    expect(beforeRestoreEvent(qc)).toBe(true);
    expect(heard.map((e) => e.type)).toEqual(["resync", "resync"]);
    act(() => void vi.advanceTimersByTime(RESTORE_EVENT_WAIT_MS / 2));
    expect(beforeRestoreEvent(qc)).toBe(false);
    expect(heard.map((e) => e.type)).toEqual(["resync", "resync", "resync"]);
  });

  it("the stream ends (the app unmounts): the wait ends with it, and nothing comes at RESTORE_EVENT_WAIT_MS", () => {
    const { qc, heard, app } = stream();
    vi.useFakeTimers();
    act(() => resyncForRestore(qc, 4, restoreSent()));
    app.unmount();
    expect(beforeRestoreEvent(qc)).toBe(false);
    act(() => void vi.advanceTimersByTime(RESTORE_EVENT_WAIT_MS));
    expect(heard.map((e) => e.type)).toEqual(["resync"]);
  });
});

describe("V1: drafts survive tab switches, and a sheet asks before dropping one (Codex polish V1)", () => {
  it("an entity sheet with unsaved changes asks before Escape closes it: Keep editing keeps the draft, Discard closes; a clean one closes at once", async () => {
    const user = userEvent.setup();
    const { fixtures } = mockApi();
    const upstream = (fixtures["/upstreams"] as { items: { id: string }[] }).items.find((u) => u.id === "cf-doh");
    mockApi([{ method: "GET", path: "/upstreams/cf-doh", body: () => upstream }]);
    renderApp("/upstreams");
    const edit = await screen.findByRole("button", { name: "Edit cf-doh" }, T);
    await user.click(edit);
    const form = await screen.findByRole("form", { name: "Edit upstream" }, T);
    const name = within(form).getByLabelText("Name");
    await user.clear(name);
    await user.type(name, "Mine");
    await user.keyboard("{Escape}");
    const ask = await screen.findByRole("alertdialog", { name: "Discard your changes?" }, T);
    await user.click(within(ask).getByRole("button", { name: "Keep editing" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull(), T);
    expect(within(screen.getByRole("form", { name: "Edit upstream" })).getByLabelText("Name")).toHaveValue("Mine");
    await user.keyboard("{Escape}");
    await user.click(within(await screen.findByRole("alertdialog", { name: "Discard your changes?" }, T)).getByRole("button", { name: "Discard" }));
    await waitFor(() => expect(screen.queryByRole("form", { name: "Edit upstream" })).toBeNull(), T);
    // Clean: no question.
    await user.click(screen.getByRole("button", { name: "Edit cf-doh" }));
    expect(within(await screen.findByRole("form", { name: "Edit upstream" }, T)).getByLabelText("Name")).toHaveValue("Cloudflare DoH 1.1.1.1");
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("form", { name: "Edit upstream" })).toBeNull(), T);
    expect(screen.queryByRole("alertdialog")).toBeNull();
  });

  it("a settings tab with unsaved changes keeps them while another tab shows; a clean one isn't kept", async () => {
    const user = userEvent.setup();
    mockApi();
    renderApp("/settings?tab=retention");
    const input = await screen.findByLabelText("Metrics", undefined, T);
    await user.clear(input);
    await user.type(input, "6h");
    await user.click(screen.getByRole("tab", { name: "Alerts" }));
    await waitFor(() => expect(screen.getByRole("tab", { name: "Alerts" })).toHaveAttribute("aria-selected", "true"), T);
    // Kept, out of sight.
    expect(screen.getByLabelText("Metrics")).not.toBeVisible();
    await user.click(screen.getByRole("tab", { name: "Retention" }));
    expect(screen.getByLabelText("Metrics")).toBeVisible();
    expect(screen.getByLabelText("Metrics")).toHaveValue("6h");
    await user.click(screen.getByRole("button", { name: "Discard changes" }));
    await user.click(screen.getByRole("tab", { name: "Alerts" }));
    await waitFor(() => expect(screen.queryByLabelText("Metrics")).toBeNull(), T);
  });

  it("the clients page's sheet asks too", async () => {
    const user = userEvent.setup();
    mockApi();
    renderApp("/clients");
    await user.click(await screen.findByRole("button", { name: /New client/ }, T));
    const form = await screen.findByRole("form", { name: "New client" }, T);
    await user.type(within(form).getByLabelText("Name"), "kid-tablet");
    await user.keyboard("{Escape}");
    await user.click(within(await screen.findByRole("alertdialog", { name: "Discard your changes?" }, T)).getByRole("button", { name: "Keep editing" }));
    expect(within(screen.getByRole("form", { name: "New client" })).getByLabelText("Name")).toHaveValue("kid-tablet");
  });

  it("the LAN CA's zones and an edge's settings keep their drafts while another tab shows", async () => {
    const user = userEvent.setup();
    mockApi();
    const { unmount } = renderApp("/settings?tab=lanca");
    await user.type(await screen.findByLabelText("Zones", undefined, T), "lan.example{Enter}");
    await user.click(screen.getByRole("tab", { name: "Retention" }));
    await user.click(screen.getByRole("tab", { name: "LAN CA" }));
    expect(screen.getByText("lan.example")).toBeVisible();
    unmount();
    renderApp("/edges/e-cacc845b?tab=settings");
    const name = await screen.findByLabelText("Name", undefined, T);
    await user.clear(name);
    await user.type(name, "gw-renamed");
    await user.click(screen.getByRole("tab", { name: "Events" }));
    await user.click(screen.getByRole("tab", { name: "Settings" }));
    expect(screen.getByLabelText("Name")).toHaveValue("gw-renamed");
  });

  it("a manual feed's unsaved text stays while another tab shows", async () => {
    const user = userEvent.setup();
    mockApi();
    renderApp("/feeds/manual-block");
    await screen.findByTestId("code-editor", undefined, T);
    const view = () => EditorView.findFromDOM(screen.getByTestId("code-editor").querySelector(".cm-editor") as HTMLElement)!;
    act(() => view().dispatch({ changes: { from: view().state.doc.length, insert: "||draft.example^\n" } }));
    const text = view().state.doc.toString();
    await user.click(screen.getByRole("tab", { name: "Runs" }));
    await screen.findByRole("table", { name: /runs/i }, T);
    await user.click(screen.getByRole("tab", { name: "File" }));
    expect(view().state.doc.toString()).toBe(text);
    expect(screen.getByRole("button", { name: "Save" })).toBeEnabled();
  });
});

describe("V2: a provider whose status can't be read isn't shown as healthy (Codex polish V2)", () => {
  it("shows its health as unknown and the read's error with Retry; Retry shows the status", async () => {
    const user = userEvent.setup();
    let fail = true;
    const { fixtures } = mockApi();
    mockApi([{ method: "GET", path: "/feed-provider-status", body: () => (fail ? reply(500, { error: { code: "internal", message: "database is locked" } }) : fixtures["/feed-provider-status"]) }]);
    renderApp("/feed-providers");
    const table = await screen.findByRole("table", { name: "Feed providers" }, T);
    const error = await screen.findByText(/database is locked/, undefined, T);
    const row = within(table).getAllByRole("row")[1];
    expect(within(row).queryByText("ok")).toBeNull();
    expect(within(row).getByText("unknown")).toBeInTheDocument();
    fail = false;
    await user.click(within(error.closest("[role=alert]") as HTMLElement).getByRole("button", { name: /Retry/ }));
    await waitFor(() => expect(within(within(table).getAllByRole("row")[1]).getByText("ok")).toBeInTheDocument(), T);
    expect(screen.queryByText(/database is locked/)).toBeNull();
  });
});

describe("V3: invalid JSON text blocks the form's submission (Codex polish V3)", () => {
  function JsonForm({ onSubmit }: { onSubmit: (v: unknown) => void }) {
    const [value, setValue] = React.useState<unknown>({ a: 1 });
    return (
      <form
        aria-label="Config"
        onSubmit={(e) => {
          e.preventDefault();
          onSubmit(value);
        }}
      >
        <SchemaForm schema={{ description: "The module's config as JSON." }} value={value} onChange={setValue} idPrefix="json" />
        <button type="submit">Save</button>
      </form>
    );
  }

  it("sends nothing while the text doesn't parse, then the parsed value", async () => {
    const user = userEvent.setup();
    const sent: unknown[] = [];
    render(<JsonForm onSubmit={(v) => sent.push(v)} />);
    const text = screen.getByRole("textbox");
    fireEvent.change(text, { target: { value: '{"a": 2,' } });
    expect(screen.getByText(/^Not valid JSON/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(sent).toEqual([]);
    fireEvent.change(text, { target: { value: '{"a": 2}' } });
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(sent).toEqual([{ a: 2 }]);
  });
});

describe("V4: a failed refresh keeps what was loaded (Codex polish V4)", () => {
  it("a chart whose refresh fails keeps its lines and says the refresh failed, with Retry", async () => {
    const user = userEvent.setup();
    let fail = false;
    mockApi([
      {
        method: "GET",
        path: "/metrics",
        body: () => (fail ? reply(500, { error: { code: "internal", message: "metrics unreadable" } }) : { step_s: 60, series: [{ name: "queries", edge: null, labels: {}, points: [[1764000000, 5], [1764000060, 7]] }] }),
      },
    ]);
    const qc = makeQueryClient({ retry: false });
    render(
      <QueryClientProvider client={qc}>
        <TooltipProvider>
          <MetricPanel title="Queries" series={["queries"]} window="1h" edge="all" />
        </TooltipProvider>
      </QueryClientProvider>,
    );
    await screen.findByRole("img", { name: "Queries" }, T);
    fail = true;
    await act(() => qc.refetchQueries({ queryKey: ["metrics"] }));
    expect(await screen.findByText(/metrics unreadable/, undefined, T)).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "Queries" })).toBeInTheDocument();
    fail = false;
    await user.click(screen.getByRole("button", { name: /Retry/ }));
    await waitFor(() => expect(screen.queryByText(/metrics unreadable/)).toBeNull(), T);
    expect(screen.getByRole("img", { name: "Queries" })).toBeInTheDocument();
  });

  it("the change journal keeps its rows and the open diff when the next page fails; Retry loads it", async () => {
    const user = userEvent.setup();
    const { fixtures } = mockApi();
    const all = (fixtures["/config-changes"] as { items: { id: number }[] }).items;
    let fail = true;
    mockApi([
      {
        method: "GET",
        path: "/config-changes",
        body: (c: Call) => {
          if (!c.query.get("cursor")) return { items: all.slice(0, 2), next_cursor: "p2" };
          return fail ? reply(500, { error: { code: "internal", message: "journal unreadable" } }) : { items: all.slice(2, 4), next_cursor: null };
        },
      },
    ]);
    renderApp("/settings?tab=changes");
    const table = await screen.findByRole("table", { name: "Change journal" }, T);
    await user.click(within(table).getAllByRole("row")[1]);
    const diffs = () => within(screen.getByRole("table", { name: "Change journal" })).getAllByRole("row").length;
    const open = diffs();
    await user.click(screen.getByRole("button", { name: "Load more" }));
    expect(await screen.findByText(/journal unreadable/, undefined, T)).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Change journal" })).toBeInTheDocument();
    expect(diffs()).toBe(open);
    fail = false;
    await user.click(screen.getByRole("button", { name: /Retry/ }));
    await waitFor(() => expect(diffs()).toBe(open + 2), T);
    expect(screen.queryByText(/journal unreadable/)).toBeNull();
  });
});

describe("V5: a map's values are named by their key and field (Codex polish V5)", () => {
  it("each value control's name is its field's and its key", () => {
    const schema = {
      type: "object",
      properties: {
        headers: { type: "object", additionalProperties: { type: "string" } },
        thresholds: { type: "object", additionalProperties: { type: "integer" } },
      },
    };
    render(
      <TooltipProvider>
        <SchemaForm schema={schema} value={{ headers: { "X-Api-Key": "abc" }, thresholds: { edge_offline: 3 } }} onChange={() => {}} idPrefix="map" />
      </TooltipProvider>,
    );
    expect(screen.getByRole("textbox", { name: "Headers: X-Api-Key" })).toHaveValue("abc");
    expect(screen.getByRole("textbox", { name: "Thresholds: edge_offline" })).toHaveValue("3");
  });
});

describe("V6: ordered pickers are labelled groups with field-specific add controls (Codex polish V6)", () => {
  it("a profile's block bundles: a group named by its field, its add control naming the field too", async () => {
    const { fixtures } = mockApi();
    // No block bundle picked yet: block-common is offered.
    mockApi([{ method: "GET", path: "/profiles/default", body: () => ({ ...(fixtures["/profiles/default"] as object), block: [] }) }]);
    renderApp("/profiles/default");
    const group = await screen.findByRole("group", { name: "Block bundles (in order)" }, T);
    const add = within(group).getByRole("combobox", { name: "Block bundles (in order) Add a block bundle…" });
    // The field's label is the add control's (it focuses it).
    expect(screen.getByText("Block bundles (in order)").closest("label")).toHaveAttribute("for", add.id);
    expect(screen.getByRole("group", { name: "Allow bundles (in order)" })).toBeInTheDocument();
  });
});

describe("Core's polish: the temporary_allow setting, 408, the new alert kinds (polish-core-report A1, A2, C3)", () => {
  it("Settings → Alerts has the temporary_allow switch with its one-line explanation, and saves it", async () => {
    const user = userEvent.setup();
    const { fixtures } = mockApi();
    const { calls } = mockApi([{ method: "PUT", path: "/settings", body: () => fixtures["/settings"] }]);
    renderApp("/settings?tab=alerts");
    const toggle = await screen.findByRole("switch", { name: "Alert on temporary allows" }, T);
    expect(toggle).not.toBeChecked();
    expect(screen.getByText("Raises an info alert whenever an edge creates a temporary allow.")).toBeVisible();
    await user.click(toggle);
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(mutations(calls)).toHaveLength(1), T);
    expect((mutations(calls)[0].body as { alerts: { temporary_allow: unknown } }).alerts.temporary_allow).toBe(true);
  });

  it("a restore whose upload stalled (408 timeout) says nothing was changed and doesn't re-read as after a restore", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([{ method: "PUT", path: "/config/export", refuses: true, body: () => reply(408, { error: { code: "timeout", message: "the request body didn't arrive within 60 s" } }) }]);
    const { queryClient } = renderApp("/settings?tab=export");
    const doc = new File([JSON.stringify(W5["GET /config/export"])], "picket-config.json", { type: "application/json" });
    await user.upload(await screen.findByLabelText("File", undefined, T), doc);
    await user.click(await screen.findByRole("button", { name: /^Restore$/ }, T));
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    const reads = calls.filter((c) => c.method === "GET").length;
    await user.click(await screen.findByRole("button", { name: "Restore" }));
    expect(await screen.findByTestId("restore-error", undefined, T)).toHaveTextContent("The upload stalled before core had the whole document. Nothing was changed: try again.");
    await pause(300);
    expect(calls.filter((c) => c.method === "GET").length).toBe(reads);
  });

  it("a 405 or 408 without core's JSON error body still says what it is (unit)", () => {
    expect(toApiError(new Response(null, { status: 408 }), null).message).toBe("The request took too long to reach core; nothing was changed. Try again.");
    expect(toApiError(new Response(null, { status: 405 }), null).message).toBe("Core doesn't take this request here.");
    // Core's own body (C3, C5) is what shows.
    expect(toApiError(new Response(null, { status: 408 }), { error: { code: "timeout", message: "the request body didn't arrive within 30 s" } }).code).toBe("timeout");
  });

  /** An alert's page, its alert as core gives it (`GET alerts/{id}`) with these fields. */
  function alertPage(id: number, fields: Record<string, unknown>) {
    const base = W5["/alerts/{category_blocked}"] as { alert: Record<string, unknown> };
    const { calls } = mockApi([{ method: "GET", path: `/alerts/${id}`, body: { alert: { ...base.alert, id, feed: null, bundle: null, ...fields }, history: [] } }]);
    renderApp(`/alerts/${id}`);
    return calls;
  }

  it("a temporary_allow alert shows the allow (target, device, profile, expiry, how) and links the temporary allows; it keeps evidence like any security alert (core captures the device's queries under the target, core.md §9)", async () => {
    alertPage(301, {
      type: "security",
      severity: "info",
      kind: "temporary_allow",
      dedupe_key: "temporary_allow:e-1:tablet:ads.example",
      title: "Edge gw: tablet was allowed ads.example until 2026-11-25T13:00:00.000000Z",
      edge: "e-1",
      details: { edge: "e-1", allow_id: "a-7", device: "tablet", client: "192.0.2.10", kind: "dns", target: "ads.example", subdomains: true, profile: "kids", block_id: "b-3", expires_at: "2026-11-25T13:00:00.000000Z", via: "extension", created_at: "2026-11-25T12:00:00.000000Z" },
    });
    const allow = await screen.findByTestId("temporary-allow", undefined, T);
    expect(within(allow).getByText("ads.example and its subdomains")).toBeInTheDocument();
    expect(within(allow).getByText("tablet (192.0.2.10)")).toBeInTheDocument();
    expect(within(allow).getByText("kids")).toBeInTheDocument();
    expect(within(allow).getByText("extension")).toBeInTheDocument();
    expect(within(allow).getByText("Expires")).toBeInTheDocument();
    expect(within(allow).getByRole("link", { name: "Temporary allows" })).toHaveAttribute("href", "/temporary-allows");
    expect(await screen.findByText("Evidence", undefined, T)).toBeInTheDocument();
  });

  it("a bundle_cold_share alert shows the share against its limit and each deciding feed's share, linked", async () => {
    alertPage(302, {
      type: "operational",
      severity: "warning",
      kind: "bundle_cold_share",
      dedupe_key: "bundle_cold_share:block-common",
      title: "Bundle block-common answered 2.5 % of its blocks from its cold part over 24 h",
      edge: null,
      bundle: "block-common",
      details: { bundle: "block-common", window_h: 24, blocks: 400, cold_blocks: 10, share: 0.025, limit: 0.01, feeds: [{ feed: "f-big", cold_blocks: 8, share: 0.02 }, { feed: "f-small", cold_blocks: 2, share: 0.005 }], unattributed_cold_blocks: 1 },
    });
    const cold = await screen.findByTestId("cold-share", undefined, T);
    expect(cold).toHaveTextContent("10 of 400 blocks (2.5 %) over the last 24 h came from the cold part; the limit is 1.0 %.");
    const rows = within(within(cold).getByRole("table", { name: "Cold blocks per feed" })).getAllByRole("row").slice(1);
    expect(rows.map((r) => r.textContent)).toEqual(["f-big82.0 %", "f-small20.5 %"]);
    expect(within(rows[0]).getByRole("link", { name: "f-big" })).toHaveAttribute("href", "/feeds/f-big");
    expect(cold).toHaveTextContent("1 cold block has no deciding feed yet (attribution hasn't run or couldn't tell).");
  });
});
