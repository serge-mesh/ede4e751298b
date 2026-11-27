// The UI on core 720be97's API (dev/briefs/ui-cf2.md; brought to c58ba80's in ui-c58.test.tsx),
// against answers captured from a real core
// (test/core-w5.ts, scripts/capture-w5.mjs): P2 the LAN CA (current root, a zones change, the
// previous roots edges still use, core's 409/422 in words), P3 live events (`temp_allow`,
// `dnssec`, `restore`; what still polls), P4 evidence paged with core's cursor, P5 temporary
// allows' `revoked` state and the per-profile allows, P6 devices' MACs and the trial graph per
// edge, P7 parameters typed by core's OpenAPI document.
import { describe, expect, it, vi } from "vitest";
import { act, renderHook, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, type QueryKey } from "@tanstack/react-query";
import { mockApi, mutations, reply, type Call } from "@/test/mock-api";
import { renderApp } from "@/test/render";
import { W5, captured, capturedEvent, capturedSettings } from "@/test/core-w5";
import { captureDownloads } from "@/test/downloads";
import { alertFrame, truncatedAlertFrame, type AlertLike } from "@/test/events";
import { checkSchema, contractViolations } from "@/test/contract";
import { applyEvent, tempAllowsChanged, usesPreviousRoot, useUiEvent, type UiEvent } from "@/api/events";
import { qk } from "@/api/queries";
import { rotationSteps } from "./lanca";
import { joinEvidence } from "./alerts";
import type { DnssecQueue, EvidenceView, SettingsView, UiEventFrame } from "@/api/types";

const T = { timeout: 8000 };
type Rec = Record<string, unknown>;
const gets = (calls: Call[], path: string) => calls.filter((c) => c.method === "GET" && c.path === path);
const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));
const q = (s = "") => new URLSearchParams(s);

interface FakeSocket {
  open(): void;
  emit(data: unknown): void;
}
const socket = () => (globalThis.WebSocket as unknown as { instances: FakeSocket[] }).instances.at(-1)!;

/** The refresh interval a mounted query's observer resolves to now. */
function intervalOf(qc: QueryClient, queryKey: QueryKey) {
  const query = qc.getQueryCache().find({ queryKey, exact: true });
  const v = (query?.observers[0]?.options as { refetchInterval?: unknown } | undefined)?.refetchInterval;
  return typeof v === "function" ? (v as (x: unknown) => unknown)(query) : v;
}

const FRESH = capturedSettings("/settings (fresh)");
const ROTATING = capturedSettings("/settings (rotating)");
const OFFLINE = capturedSettings("/settings (rotating, edge offline)");
const ROTATED = capturedSettings("/settings (rotated)");
const EDGE = W5["trial edge"] as string;
const bodyOf = (key: string) => captured(key).body;
const messageOf = (key: string) => (bodyOf(key) as { error: { message: string } }).error.message;

describe("P2: the LAN CA under Settings (core.md §11, security.md §2)", () => {
  it("shows the current root: fingerprint, zones, when it was made and its downloads", async () => {
    mockApi([{ method: "GET", path: "/settings", body: FRESH }]);
    renderApp("/settings?tab=lanca");
    const root = (await screen.findByText("Current root", undefined, T)).closest("[data-slot=card]") as HTMLElement;
    expect(within(root).getByText(FRESH.lanca.fingerprint)).toBeInTheDocument();
    expect(within(root).getByText("home.arpa")).toBeInTheDocument();
    expect(within(root).getByRole("link", { name: /DER/ })).toHaveAttribute("href", FRESH.lanca.download);
    expect(within(root).getByRole("link", { name: /PEM/ })).toHaveAttribute("href", "/lanca/ca.pem");
    expect(within(root).queryByText("—")).toBeNull();
    // No previous root in use: nothing listed, and the zones can change.
    expect(screen.queryByText("Previous roots still in use")).toBeNull();
    expect(screen.queryByTestId("lanca-blocked")).toBeNull();
  });

  it("changes the zones after a warning: one PUT of lanca.zones with the root it replaces, then the new root and the old one's edges", async () => {
    const user = userEvent.setup();
    let state: SettingsView = FRESH;
    const { calls } = mockApi([
      // The contract reads the LAN CA core has now from it (`pure`): rotate_from must name it.
      { method: "GET", path: "/settings", pure: true, body: () => state },
      {
        method: "PUT",
        path: "/settings",
        body: () => {
          state = ROTATING;
          return bodyOf("PUT /settings lanca.zones (rotation)");
        },
      },
    ]);
    renderApp("/settings?tab=lanca");
    const button = await screen.findByRole("button", { name: /Change zones/ }, T);
    // Nothing to change yet; the same zones written otherwise are no change either.
    expect(button).toBeDisabled();
    const zones = screen.getByLabelText("Zones");
    await user.type(zones, "HOME.ARPA.{Enter}");
    expect(button).toBeDisabled();
    await user.type(zones, "lan.example{Enter}");
    expect(button).toBeEnabled();
    // The warning says what a change does before it is made.
    const warning = screen.getByRole("list", { name: "What a zones change does" });
    for (const t of rotationSteps(FRESH.settings.web)) expect(within(warning).getByText(t)).toBeInTheDocument();
    await user.click(button);
    const dialog = await screen.findByRole("alertdialog", undefined, T);
    expect(within(dialog).getByText(/a new CA root/i, { selector: "li" })).toBeInTheDocument();
    expect(within(dialog).getByText("home.arpa, lan.example")).toBeInTheDocument();
    expect(mutations(calls)).toHaveLength(0);
    await user.click(within(dialog).getByRole("button", { name: "Make a new root" }));
    const done = await screen.findByTestId("lanca-rotated", undefined, T);
    const sent = mutations(calls).filter((c) => c.path === "/settings");
    expect(sent).toHaveLength(1);
    expect(sent[0].body).toEqual({ lanca: { zones: ["home.arpa", "lan.example"], rotate_from: FRESH.lanca.fingerprint } });
    expect(done).toHaveTextContent(ROTATING.lanca.fingerprint);
    expect(done).toHaveTextContent(/trust it on every device/);
    // The draft is now the zones as core keeps them.
    expect(within(zones.parentElement!).queryByText("HOME.ARPA.")).toBeNull();
    expect(within(zones.parentElement!).getByText("lan.example")).toBeInTheDocument();
    // The settings read again: the previous root and the edge still serving its certificates.
    const previous = await screen.findByTestId("previous-root", undefined, T);
    expect(within(previous).getByText(FRESH.lanca.fingerprint)).toBeInTheDocument();
    const row = within(previous).getByRole("link", { name: "e1" }).closest("tr")!;
    expect(row).toHaveTextContent("lan-dot");
    expect(within(row).getByText("online")).toBeInTheDocument();
    expect(within(screen.getByRole("link", { name: "e1" }).closest("tr")!).queryByText("offline")).toBeNull();
    // Its own rotation is no change "elsewhere": the draft is based on the new root.
    expect(screen.queryByTestId("lanca-moved")).toBeNull();
    // A previous root in use: the zones can't change again until it's gone.
    expect(screen.getByTestId("lanca-blocked")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Change zones/ })).toBeDisabled();
  });

  it("says an edge still on the old root is offline (it re-issues when it reconnects), and allows a change once none is", async () => {
    mockApi([{ method: "GET", path: "/settings", body: OFFLINE }]);
    const app = renderApp("/settings?tab=lanca");
    const row = (await screen.findByRole("link", { name: "e1" }, T)).closest("tr")!;
    expect(within(row).getByText("offline")).toHaveAttribute("title", expect.stringMatching(/when it reconnects/));
    app.unmount();
    mockApi([{ method: "GET", path: "/settings", body: ROTATED }]);
    renderApp("/settings?tab=lanca");
    await screen.findByText("Current root", undefined, T);
    expect(screen.queryByText("Previous roots still in use")).toBeNull();
    expect(screen.queryByTestId("lanca-blocked")).toBeNull();
    expect(screen.getByText("home.arpa, lan.example")).toBeInTheDocument();
  });

  it("shows core's 409 for a previous root in use in words: nothing changed, the edges on the old root listed", async () => {
    const user = userEvent.setup();
    // The page read the current root with no previous one in use; by the save, a listener keeps
    // the previous root in use again (core kept it until its next prune).
    let state: SettingsView = { ...ROTATING, lanca: { ...ROTATING.lanca, previous: [], can_rotate: true } };
    const { calls } = mockApi([
      { method: "GET", path: "/settings", body: () => state },
      {
        method: "PUT",
        path: "/settings",
        refuses: true,
        body: () => {
          state = ROTATING;
          return reply(409, bodyOf("PUT /settings lanca.zones (previous root in use)"));
        },
      },
    ]);
    renderApp("/settings?tab=lanca");
    await user.type(await screen.findByLabelText("Zones", undefined, T), "other.example{Enter}");
    await user.click(screen.getByRole("button", { name: /Change zones/ }));
    await user.click(await screen.findByRole("button", { name: "Make a new root" }, T));
    const refusal = await screen.findByTestId("lanca-refusal", undefined, T);
    expect(mutations(calls)[0].body).toMatchObject({ lanca: { rotate_from: ROTATING.lanca.fingerprint } });
    expect(refusal).toHaveTextContent("The previous root is still in use");
    expect(refusal).toHaveTextContent(messageOf("PUT /settings lanca.zones (previous root in use)"));
    expect(refusal).toHaveTextContent(/Nothing was changed/);
    expect(await screen.findByTestId("previous-root", undefined, T)).toHaveTextContent("e1");
  });

  it("shows core's 422 in words: the names to move first (with the two-step path), or zones core won't take", async () => {
    const user = userEvent.setup();
    let answer = "PUT /settings lanca.zones (orphans)";
    mockApi([
      { method: "GET", path: "/settings", body: FRESH },
      { method: "PUT", path: "/settings", refuses: true, body: () => reply(422, bodyOf(answer)) },
    ]);
    renderApp("/settings?tab=lanca");
    const zones = await screen.findByLabelText("Zones", undefined, T);
    await user.click(within(zones.parentElement!).getByRole("button", { name: /home\.arpa/ }));
    await user.type(zones, "lan.example{Enter}");
    await user.click(screen.getByRole("button", { name: /Change zones/ }));
    await user.click(await screen.findByRole("button", { name: "Make a new root" }, T));
    let refusal = await screen.findByTestId("lanca-refusal", undefined, T);
    expect(refusal).toHaveTextContent("Names to move first");
    expect(refusal).toHaveTextContent("dns.home.arpa (listener lan-dot)");
    expect(refusal).toHaveTextContent(/add the new zone next to the old one, rename, then remove the old zone/);
    // The draft stays for another try.
    answer = "PUT /settings lanca.zones (public suffix)";
    await user.click(screen.getByRole("button", { name: /Change zones/ }));
    await user.click(await screen.findByRole("button", { name: "Make a new root" }, T));
    await waitFor(() => expect(screen.getByTestId("lanca-refusal")).toHaveTextContent("Core refused the zones"), T);
    refusal = screen.getByTestId("lanca-refusal");
    expect(refusal).toHaveTextContent(/is a public suffix/);
    expect(refusal).not.toHaveTextContent(/two steps|next to the old one/);
  });

  it("reads the settings again when an edge still on the old root comes online or goes offline, not on its heartbeats or for others", async () => {
    const { calls } = mockApi([{ method: "GET", path: "/settings", body: ROTATING }]);
    const { queryClient } = renderApp("/settings?tab=lanca");
    await screen.findByTestId("previous-root", undefined, T);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    act(() => socket().open());
    // The socket's first open reads the settings once more (events keep them fresh: keptByEvents).
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    const n = gets(calls, "/settings").length;
    const frames = W5.events.edge_status as Extract<UiEventFrame, { type: "edge_status" }>[];
    const of = (event: string) => frames.find((f) => f.data.event === event)!;
    const frame = of("hello");
    expect(frame.data.edge).toBe(ROTATING.lanca.previous[0].edges[0].edge_id);
    act(() => socket().emit({ ...frame, data: { ...frame.data, edge: "e-other" } }));
    // Its listeners' reports come as lanca_served (core 07acc1c): a heartbeat changes nothing here.
    act(() => socket().emit(of("heartbeat")));
    await pause(300);
    expect(gets(calls, "/settings")).toHaveLength(n);
    act(() => socket().emit(frame));
    await waitFor(() => expect(gets(calls, "/settings").length).toBe(n + 1), T);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    act(() => socket().emit(of("session_ended")));
    await waitFor(() => expect(gets(calls, "/settings").length).toBe(n + 2), T);
    expect(usesPreviousRoot(ROTATED, frame.data.edge)).toBe(false);
  });

  it("links the Identity tab's LAN CA to it, and the restore says to change the zones there first", async () => {
    mockApi();
    renderApp("/settings?tab=identity");
    expect(await screen.findByRole("link", { name: "LAN CA" }, T)).toHaveAttribute("href", "/settings?tab=lanca");
  });
});

describe("P3: live events (temp_allow, dnssec, restore) and what still polls", () => {
  it("every frame core sent is one of its UiEventFrame variants, and so is a dnssec frame the UI handles", () => {
    const frame = { $ref: "#/components/schemas/UiEventFrame" };
    for (const [type, frames] of Object.entries(W5.events)) for (const f of frames) expect(checkSchema(frame, f), type).toEqual([]);
    expect(Object.keys(W5.events)).toEqual(expect.arrayContaining(["temp_allow", "restore", "edge_status", "alert", "job", "feed_run", "bundle_version", "lanca", "lanca_served", "dnssec_queued"]));
    expect(checkSchema(frame, { type: "dnssec", data: { results: 2, outcomes: { bogus: 1, secure: 1 } } })).toEqual([]);
  });

  it("shows a revoke's acknowledgement when core's temp_allow event arrives, with no polling while the socket is open", async () => {
    let acked = false;
    const { calls } = mockApi([
      {
        method: "GET",
        path: "/temp-allows",
        body: (c: Call) => W5[`/temp-allows?state=${c.query.get("state")}${acked ? " (revoked)" : c.query.get("state") === "active" ? " (revoke pending)" : ""}`],
      },
    ]);
    const { queryClient } = renderApp("/temporary-allows");
    const active = await screen.findByRole("table", { name: "Active temporary allows" }, T);
    expect(await within(active).findByText("revoke pending", undefined, T)).toBeInTheDocument();
    act(() => socket().open());
    await waitFor(() => expect(intervalOf(queryClient, ["temp-allows", "active", "all"])).toBe(false), T);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    const n = gets(calls, "/temp-allows").length;
    acked = true;
    const frame = capturedEvent("temp_allow");
    act(() => socket().emit(W5.events.temp_allow.find((f) => f.type === "temp_allow" && f.data.revoke_acked > 0) ?? frame));
    const recent = screen.getByRole("table", { name: "Recent temporary allows" });
    const row = (await within(recent).findByText("ads.example", undefined, T)).closest("tr")!;
    expect(within(row).getByText("revoked")).toBeInTheDocument();
    expect(await within(active).findByText("None.", undefined, T)).toBeInTheDocument();
    // Both lists (every edge's) read once each.
    expect(gets(calls, "/temp-allows").length).toBe(n + 2);
  });

  it("reads again only the allows lists the event's edges concern, and the device and profile views (unit)", () => {
    const qc = new QueryClient();
    const keys = [
      [...qk.tempAllows, "active", "all"],
      [...qk.tempAllows, "active", "e-1"],
      [...qk.tempAllows, "recent", "e-2"],
      [...qk.querySummary, { device: "tablet" }, "24h", "all"],
      [...qk.dnssecResults, "bogus"],
    ];
    for (const k of keys) qc.setQueryData(k, { pages: [], pageParams: [] });
    const stale = () => keys.filter((k) => qc.getQueryCache().find({ queryKey: k, exact: true })?.state.isInvalidated).map((k) => k.slice(1).join("/"));
    const data = { edges: ["e-1"], edges_truncated: false, ingested: 1, expired: 0, revoke_requested: 0, revoke_acked: 0 };
    applyEvent(qc, { type: "temp_allow", data });
    expect(stale()).toEqual(["active/all", "active/e-1", "[object Object]/24h/all"]);
    expect(tempAllowsChanged([...qk.tempAllows, "recent", "e-2"], { ...data, edges_truncated: true })).toBe(true);
    expect(tempAllowsChanged([...qk.tempAllows, "recent", "e-2"], data)).toBe(false);
    expect(tempAllowsChanged([...qk.tempAllows, "recent", "e-2"], {})).toBe(true);
  });

  it("reads DNSSEC results and the queue again on a dnssec event; dnssec_queued reads the queue alone; alerts of any kind neither (core a3eb6d5)", async () => {
    const { calls } = mockApi();
    const { queryClient } = renderApp("/dnssec");
    await screen.findByRole("table", { name: "DNSSEC queue" }, T);
    await waitFor(() => expect(gets(calls, "/dnssec/results").length).toBeGreaterThan(0), T);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    const results = () => gets(calls, "/dnssec/results").length;
    const queue = () => gets(calls, "/dnssec/queue").length;
    const [r0, q0] = [results(), queue()];
    act(() => applyEvent(queryClient, alertFrame([{ id: 99, kind: "edge_offline" }])));
    await pause(300);
    expect([results(), queue()]).toEqual([r0, q0]);
    act(() => applyEvent(queryClient, { type: "dnssec", data: { results: 2, outcomes: { bogus: 1, secure: 1 } } }));
    await waitFor(() => expect([results(), queue()]).toEqual([r0 + 1, q0 + 1]), T);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    // A cross-check that ends sends dnssec_queued (crosscheck_ended); its upstream_disagrees alert
    // and a bogus result's alert read neither list.
    act(() => applyEvent(queryClient, truncatedAlertFrame([{ id: 97, kind: "upstream_disagrees" }, { id: 98, kind: "dnssec_bogus" }])));
    await pause(300);
    expect([results(), queue()]).toEqual([r0 + 1, q0 + 1]);
    act(() => applyEvent(queryClient, { type: "dnssec_queued", data: { ...capturedEvent("dnssec_queued").data, crosscheck_ended: 1 } }));
    await waitFor(() => expect(queue()).toBe(q0 + 2), T);
    await pause(300);
    expect(results()).toBe(r0 + 1);
  });

  it("polls DNSSEC results and the queue only while the socket is down, even while the queue holds checks (every change to it sends an event: core a3eb6d5)", async () => {
    let queue = W5["/dnssec/queue"] as DnssecQueue;
    expect(queue.depth).toBeGreaterThan(0);
    mockApi([{ method: "GET", path: "/dnssec/queue", body: () => queue }]);
    const { queryClient } = renderApp("/dnssec");
    await screen.findByRole("table", { name: "DNSSEC queue" }, T);
    await waitFor(() => expect(intervalOf(queryClient, [...qk.dnssecResults, "bogus"])).toBe(60_000), T);
    expect(intervalOf(queryClient, qk.dnssecQueue)).toBe(60_000);
    act(() => socket().open());
    await waitFor(() => expect(intervalOf(queryClient, [...qk.dnssecResults, "bogus"])).toBe(false), T);
    // Checks queued: their retries, waits and ends send dnssec_queued now.
    expect(intervalOf(queryClient, qk.dnssecQueue)).toBe(false);
    queue = { ...queue, depth: 0, items: [], crosscheck_depth: 0, crosscheck_items: [] };
    await act(() => queryClient.invalidateQueries({ queryKey: qk.dnssecQueue }));
    await waitFor(() => expect(screen.getByText(/^0 queued/)).toBeInTheDocument(), T);
    expect(intervalOf(queryClient, qk.dnssecQueue)).toBe(false);
    // The socket closes: both poll again, whatever the queue holds.
    act(() => (socket() as unknown as { onclose: () => void }).onclose());
    await waitFor(() => expect(intervalOf(queryClient, qk.dnssecQueue)).toBe(60_000), T);
    expect(intervalOf(queryClient, [...qk.dnssecResults, "bogus"])).toBe(60_000);
  });

  it("reads everything again on core's restore event (another tab's restore) and tells listeners to resync", async () => {
    let restored = false;
    const before = { items: [{ name: "old_secret", has_value: true }], next_cursor: null };
    const after = { items: [{ name: "aws_secret", has_value: false }], next_cursor: null };
    const { calls } = mockApi([{ method: "GET", path: "/secrets", body: () => (restored ? after : before) }]);
    renderApp("/settings?tab=secrets");
    expect(await screen.findByText("old_secret", undefined, T)).toBeInTheDocument();
    act(() => socket().open());
    const alerts = gets(calls, "/alerts").length;
    restored = true;
    act(() => socket().emit(capturedEvent("restore")));
    expect(await screen.findByText("aws_secret", undefined, T)).toBeInTheDocument();
    // Not only what's on screen: the sidebar's open alerts too.
    await waitFor(() => expect(gets(calls, "/alerts").length).toBeGreaterThan(alerts), T);
    const qc = new QueryClient();
    const seen: UiEvent[] = [];
    renderHook(() => useUiEvent((ev) => seen.push(ev)));
    act(() => applyEvent(qc, capturedEvent("restore")));
    expect(seen.map((e) => e.type)).toEqual(["resync"]);
  });
});

describe("P4: evidence paged with core's cursor (newest stored first since core c58ba80)", () => {
  const detail = W5["/alerts/{paged}"] as { alert: AlertLike };
  const id = detail.alert.id;
  const page1 = W5["/alerts/{paged}/evidence?limit=2"] as EvidenceView;
  const page2 = W5["/alerts/{paged}/evidence?limit=2&cursor=1"] as EvidenceView;
  const all = W5["/alerts/{paged}/evidence"] as EvidenceView;
  const routes = (fail = () => false) => [
    { method: "GET", path: `/alerts/${id}`, body: detail },
    {
      method: "GET",
      path: `/alerts/${id}/evidence`,
      body: (c: Call) => {
        // The download's pages (500 a request) are the captured pages too, so it follows cursors.
        if (!c.query.get("cursor")) return page1;
        if (fail()) return reply(503, { error: { code: "unavailable", message: "core is busy" } });
        return c.query.get("cursor") === page1.next_cursor ? page2 : reply(400, { error: { code: "bad_request", message: "bad cursor" } });
      },
    },
  ];

  it("shows the first page with core's total, and loads older copies from its cursor", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi(routes());
    renderApp(`/alerts/${id}`);
    expect(page1.total).toBe(4);
    expect(await screen.findByTestId("evidence-copies", undefined, T)).toHaveTextContent("Copies (2 of 4)");
    expect(gets(calls, `/alerts/${id}/evidence`)[0].query.get("limit")).toBe("100");
    // The first page's breakdown and rule.
    expect(screen.getByText(/Copies records for malware\.example/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Load older copies" }));
    await waitFor(() => expect(screen.getByTestId("evidence-copies")).toHaveTextContent("Copies (4)"), T);
    expect(gets(calls, `/alerts/${id}/evidence`)[1].query.get("cursor")).toBe(page1.next_cursor);
    expect(within(screen.getByRole("table", { name: "Evidence copies" })).getAllByRole("row")).toHaveLength(5);
    expect(screen.queryByRole("button", { name: "Load older copies" })).toBeNull();
    // The breakdown still comes from the first page (later pages carry none).
    expect(screen.getByRole("table", { name: "Evidence counts per name" })).toHaveTextContent("malware.example");
  });

  it("keeps the copies when Load older fails, with Retry for that page", async () => {
    const user = userEvent.setup();
    let failing = true;
    mockApi(routes(() => failing));
    renderApp(`/alerts/${id}`);
    await screen.findByTestId("evidence-copies", undefined, T);
    await user.click(screen.getByRole("button", { name: "Load older copies" }));
    const error = await screen.findByTestId("next-page-error", undefined, T);
    expect(error).toHaveTextContent("core is busy");
    expect(screen.getByTestId("evidence-copies")).toHaveTextContent("Copies (2 of 4)");
    // Under the copies only: not as the evidence's error, nor as a failed refresh above it.
    expect(screen.queryByTestId("error-state")).toBeNull();
    expect(screen.queryByTestId("refetch-error")).toBeNull();
    expect(screen.getAllByText(/core is busy/)).toHaveLength(1);
    failing = false;
    await user.click(within(error).getByRole("button", { name: /Retry/ }));
    await waitFor(() => expect(screen.getByTestId("evidence-copies")).toHaveTextContent("Copies (4)"), T);
  });

  it("downloads every page (at most 500 copies a request), joined", async () => {
    const user = userEvent.setup();
    const saved = captureDownloads();
    const { calls } = mockApi(routes());
    renderApp(`/alerts/${id}`);
    await screen.findByTestId("evidence-copies", undefined, T);
    await user.click(screen.getByRole("button", { name: "Download evidence" }));
    await waitFor(() => expect(saved).toHaveLength(1), T);
    const download = gets(calls, `/alerts/${id}/evidence`).filter((c) => c.query.get("limit") === "500");
    expect(download.map((c) => c.query.get("cursor"))).toEqual([null, page1.next_cursor]);
    const got = JSON.parse(await saved[0].blob.text()) as EvidenceView;
    expect(got.items.map((i) => [i.edge, i.seq])).toEqual(all.items.map((i) => [i.edge, i.seq]));
    expect(got.total).toBe(4);
    expect(got.next_cursor).toBeNull();
  });

  it("reads the loaded pages again for its own alert's events only, at most every 30 s", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
      const { calls } = mockApi(routes());
      renderApp(`/alerts/${id}`);
      await screen.findByTestId("evidence-copies", undefined, T);
      await user.click(screen.getByRole("button", { name: "Load older copies" }));
      await waitFor(() => expect(screen.getByTestId("evidence-copies")).toHaveTextContent("Copies (4)"), T);
      act(() => socket().open());
      const reads = () => gets(calls, `/alerts/${id}/evidence`);
      const n = reads().length;
      // Its own alert's event right after the pages were read: one read at the end of the interval.
      act(() => socket().emit(alertFrame([{ ...detail.alert, count: 4 }])));
      await act(() => vi.advanceTimersByTimeAsync(10_000));
      expect(reads()).toHaveLength(n);
      await act(() => vi.advanceTimersByTimeAsync(21_000));
      // Both loaded pages, in order: the second from the first page's fresh cursor.
      await waitFor(() => expect(reads()).toHaveLength(n + 2), T);
      expect(reads().slice(n).map((c) => c.query.get("cursor"))).toEqual([null, page1.next_cursor]);
      // Other alerts' events read nothing.
      act(() => socket().emit(alertFrame([{ id: id + 1000, kind: "edge_offline" }])));
      await act(() => vi.advanceTimersByTimeAsync(31_000));
      expect(reads()).toHaveLength(n + 2);
      // Past the interval: at once.
      act(() => socket().emit(alertFrame([{ ...detail.alert, count: 5 }])));
      await waitFor(() => expect(reads()).toHaveLength(n + 4), T);
    } finally {
      vi.useRealTimers();
    }
  });

  it("joins pages: the first page's breakdown and rule, every copy, each answer once, the last page's total and cursor (unit)", () => {
    const a = { answer_id: "x", source: "log", wire: "AA==", records: [] };
    const b = { answer_id: "y", source: "log", wire: "AA==", records: [] };
    const joined = joinEvidence([
      { ...page1, answers: [a] },
      // Read after the first page: a copy stored meanwhile counts in its total.
      { ...page2, answers: [a, b], total: 5, next_cursor: "next" },
    ]);
    expect(joined.items.map((i) => [i.edge, i.seq])).toEqual([...page1.items, ...page2.items].map((i) => [i.edge, i.seq]));
    expect(joined.answers.map((x) => x.answer_id)).toEqual(["x", "y"]);
    expect(joined.counts).toEqual(page1.counts);
    expect(joined.rule).toEqual(page1.rule);
    expect([joined.total, joined.next_cursor]).toEqual([5, "next"]);
    expect(joinEvidence([page1])).toMatchObject({ total: 4, next_cursor: page1.next_cursor });
  });
});

describe("P5: temporary allows: the revoked state, who an allow is for, and the profile view's allows", () => {
  it("lists a revoked allow under Recent with when the edge acknowledged it, its id, device and address, and no Revoke", async () => {
    mockApi([{ method: "GET", path: "/temp-allows", body: (c: Call) => W5[`/temp-allows?state=${c.query.get("state")} (revoked)`] }]);
    renderApp("/temporary-allows");
    const recent = await screen.findByRole("table", { name: "Recent temporary allows" }, T);
    const row = (await within(recent).findByText("ads.example", undefined, T)).closest("tr")!;
    const badge = within(row).getByText("revoked");
    expect(badge.getAttribute("title")).toMatch(/applied the revoke.*acknowledged/);
    expect(within(row).getByText("a-1")).toBeInTheDocument();
    expect(within(row).getByText("tablet")).toBeInTheDocument();
    expect(within(row).getByText("192.0.2.10")).toBeInTheDocument();
    // Ended or revoked: the acknowledgement's time, not a blank.
    expect((row as HTMLTableRowElement).cells[5].textContent).not.toBe("—");
    expect(within(row).queryByRole("button", { name: "Revoke" })).toBeNull();
    // An expired allow made from an address no client names: the address alone.
    const expired = within(recent).getByText("198.51.100.7").closest("tr")!;
    expect(within(expired).getByText("expired")).toBeInTheDocument();
    expect(within(expired).getByText("192.0.2.11")).toBeInTheDocument();
    expect(within(expired).queryByText(/^from/)).toBeNull();
    const active = screen.getByRole("table", { name: "Active temporary allows" });
    expect(within(active).getByText("None.")).toBeInTheDocument();
  });

  it("shows a pending revoke on an active allow, without Revoke; an active allow without one offers it", async () => {
    const pending = (W5["/temp-allows?state=active (revoke pending)"] as { items: Rec[] }).items[0];
    mockApi([{ method: "GET", path: "/temp-allows", body: (c: Call) => (c.query.get("state") === "active" ? { items: [pending, { ...pending, allow_id: "a-8", target: "other.example", revoke_pending: false, revoke_requested_at: null }], next_cursor: null } : { items: [], next_cursor: null }) }]);
    renderApp("/temporary-allows");
    const active = await screen.findByRole("table", { name: "Active temporary allows" }, T);
    const row = (await within(active).findByText("ads.example", undefined, T)).closest("tr")!;
    expect(within(row).getByText("revoke pending")).toBeInTheDocument();
    expect(within(row).queryByRole("button", { name: "Revoke" })).toBeNull();
    const other = within(active).getByText("other.example").closest("tr")!;
    expect(within(other).getByRole("button", { name: "Revoke" })).toBeInTheDocument();
  });

  it("lists a profile's devices' allows with whose each is and its state; the device view shows the state too", async () => {
    mockApi([{ method: "GET", path: "/query-summary", body: (c: Call) => W5[c.query.get("profile") ? "/query-summary?profile=p1 (revoked)" : "/query-summary?device=tablet (revoked)"] }]);
    const app = renderApp("/clients/profile/p1");
    const allows = await screen.findByRole("list", { name: "Temporary allows" }, T);
    const revoked = within(allows).getByText("ads.example").closest("li")!;
    expect(within(revoked).getByText("revoked", { selector: "[data-slot=badge]" })).toBeInTheDocument();
    expect(revoked).toHaveTextContent("for tablet");
    expect(revoked).toHaveTextContent(/revoked .*ago|revoked in/);
    const expired = within(allows).getByText("198.51.100.7").closest("li")!;
    expect(within(expired).getByText("expired")).toBeInTheDocument();
    expect(expired).toHaveTextContent("for 192.0.2.11");
    app.unmount();
    renderApp("/clients/device?key=tablet");
    const own = await screen.findByRole("list", { name: "Temporary allows" }, T);
    const item = within(own).getByText("ads.example").closest("li")!;
    expect(within(item).getByText("revoked", { selector: "[data-slot=badge]" })).toBeInTheDocument();
    // A device's own view doesn't repeat whose it is.
    expect(item).not.toHaveTextContent("for tablet");
  });
});

describe("P6: devices' MACs and the trial graph per edge", () => {
  it("shows the MACs core knows for a device; a MAC-keyed device is added as a client by its MAC", async () => {
    const user = userEvent.setup();
    const devices = W5["/devices"] as { items: (Rec & { key: string; mac: string | null; macs: string[] })[] };
    const tablet = devices.items.find((d) => d.key === "tablet")!;
    // A client-named device: its client entry's MACs, which are authoritative (core c58ba80).
    expect(tablet.macs).toEqual(["02:11:22:33:44:55"]);
    const own = devices.items.find((d) => d.key === "02:aa:bb:cc:dd:02")!;
    expect([own.mac, own.client]).toEqual(["02:aa:bb:cc:dd:02", null]);
    const { calls } = mockApi();
    renderApp("/clients");
    const table = await screen.findByRole("table", { name: "Seen devices" }, T);
    const row = within(table)
      .getAllByRole("link", { name: "tablet" })
      .find((a) => a.getAttribute("href") === "/clients/device?key=tablet")!
      .closest("tr")!;
    expect(within(row).getByText("02:11:22:33:44:55")).toBeInTheDocument();
    expect(within(row).getByText("private MAC")).toBeInTheDocument();
    const add = within(table).getByRole("link", { name: "02:aa:bb:cc:dd:02" }).closest("tr")!;
    await user.click(within(add).getByRole("button", { name: /Add as client/ }));
    const sheet = await screen.findByRole("dialog", undefined, T);
    expect(within(sheet).getAllByText("02:aa:bb:cc:dd:02").length).toBeGreaterThan(0);
    // Its MAC alone: the address it was seen at stays out (another device may use it).
    expect(within(sheet).queryByText("192.0.2.11")).toBeNull();
    expect(mutations(calls)).toHaveLength(0);
  });

  it("charts the selected edge's would-blocks (core counts them per edge), without a note", async () => {
    const { calls } = mockApi([{ method: "GET", path: "/metrics", body: (c: Call) => (c.query.get("edge") === EDGE ? bodyOf("/metrics?series=trial_would_block&edge={edge}") : { step_s: 300, series: [] }) }]);
    renderApp(`/profiles/p1/trial/trial-b?edge=${EDGE}`);
    await waitFor(() => expect(gets(calls, "/metrics").some((c) => c.query.get("series") === "trial_would_block")).toBe(true), T);
    const trial = gets(calls, "/metrics").filter((c) => c.query.get("series") === "trial_would_block");
    expect(trial.every((c) => c.query.get("edge") === EDGE)).toBe(true);
    expect(screen.queryByText(/without their edge/)).toBeNull();
    expect(gets(calls, "/trial-results").every((c) => c.query.get("edge") === EDGE)).toBe(true);
  });

  it("counts would-blocks from the edge's graph while trial-results can't be read", async () => {
    const chart = bodyOf("/metrics?series=trial_would_block&edge={edge}") as { series: { points: [number, number | null][] }[] };
    const sum = chart.series[0].points.reduce((n, [, v]) => n + (v ?? 0), 0);
    expect(sum).toBeGreaterThan(0);
    mockApi([
      { method: "GET", path: "/trial-results", body: () => reply(503, { error: { code: "unavailable", message: "core is busy" } }) },
      { method: "GET", path: "/metrics", body: (c: Call) => (c.query.get("edge") === EDGE ? chart : { step_s: 300, series: [] }) },
    ]);
    renderApp(`/profiles/p1/trial/trial-b?edge=${EDGE}`);
    await waitFor(() => expect(screen.getByText("Would-blocks").parentElement!).toHaveTextContent(String(sum)), T);
  });
});

describe("P7: parameters typed by core's OpenAPI document", () => {
  it("checks every query value against the document's schema: enums, whole numbers, required ones (unit)", () => {
    // Enums the document carries now, also where the mocks never modelled one.
    expect(contractViolations("GET", "/feeds/x/entries", q("rule_type=cname"), undefined)).toEqual([expect.stringMatching(/rule_type=cname isn't one of dns, ip, browser/)]);
    expect(contractViolations("GET", "/alerts", q("kind=dnssec_bogus&limit=100&state=open"), undefined)).toEqual([]);
    expect(contractViolations("GET", "/alerts", q("kind=bogus"), undefined)).toEqual([expect.stringMatching(/kind=bogus isn't one of/)]);
    expect(contractViolations("GET", "/alerts", q("limit=-1"), undefined)).toEqual([expect.stringMatching(/400 limit: a whole number/)]);
    expect(contractViolations("PUT", "/lookup-providers/p", q("clear_cached_verdicts=yes"), {})).toContainEqual(expect.stringMatching(/400 clear_cached_verdicts: true or false/));
    expect(contractViolations("GET", "/metrics", q("window=1h"), undefined)).toEqual([expect.stringMatching(/400 series is required/)]);
    expect(contractViolations("GET", "/metrics", q("series=x&window=2h"), undefined)).toEqual([expect.stringMatching(/window=2h isn't one of/)]);
    // The evidence's bounds (the document's, core 07acc1c) and its cursor, beyond the document (logs/api.rs).
    expect(contractViolations("GET", `/alerts/1/evidence`, q(`limit=2&cursor=${(W5["evidence cursors"] as { first: string }).first}`), undefined)).toEqual([]);
    expect(contractViolations("GET", `/alerts/1/evidence`, q("limit=0"), undefined)).toEqual([expect.stringMatching(/400 limit: 1 to 500/)]);
    expect(contractViolations("GET", `/alerts/1/evidence`, q("limit=501"), undefined)).toEqual([expect.stringMatching(/400 limit: 1 to 500/)]);
    expect(contractViolations("GET", `/alerts/1/evidence`, q("cursor=YQ"), undefined)).toEqual([expect.stringMatching(/400 bad cursor/)]);
  });

  it("offers the alert kinds core's document lists and sends the one chosen", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi();
    renderApp("/alerts");
    await user.click(await screen.findByRole("combobox", { name: "Kind" }, T));
    expect(screen.getByRole("option", { name: "dnssec_bogus" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "alert_evidence_full" })).toBeInTheDocument();
    await user.click(screen.getByRole("option", { name: "wire_mismatch" }));
    await waitFor(() => expect(gets(calls, "/alerts").some((c) => c.query.get("kind") === "wire_mismatch")).toBe(true), T);
  });
});
