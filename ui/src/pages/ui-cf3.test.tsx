// The UI on core 07acc1c's API (dev/briefs/ui-cf3.md), against answers captured from a real core
// at 07acc1c (test/core-w5.ts, scripts/capture-w5.mjs): P2 PUT settings' two 409s
// (`lanca_root_changed`, `conflict`), each with its words and action; P3 the typed `lanca` event
// naming the previous root; P4 the `lanca_served` and `dnssec_queued` events; P5 a restore's
// generation; P6 every `limit`, the backtest's `days` and `k` within core's bounds (400 outside);
// P7 devices' MACs as core currently knows them; P8 decimal scores; P9 the contract the mocks check.
import { describe, expect, it } from "vitest";
import { act, fireEvent, renderHook, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient } from "@tanstack/react-query";
import { mockApi, mutations, reply, takeViolations, type Call } from "@/test/mock-api";
import { renderApp } from "@/test/render";
import { W5, captured, capturedEvent, capturedSettings } from "@/test/core-w5";
import { alertFrame, feedRunFrame, truncatedAlertFrame, truncatedRunFrame } from "@/test/events";
import { answerViolations, contractViolations, eventViolations, refusalViolations } from "@/test/contract";
import { applyEvent, lancaEventOf, resyncForRestore, useUiEvent } from "@/api/events";
import { LANCA_ROOT_CHANGED, StaleRoot, qk } from "@/api/queries";
import { ApiError } from "@/api/errors";
import { queryRange, rangeProblem, rangeText } from "@/lib/openapi";
import { finishedRotation, replacedRoot, zonesRefusal } from "./lanca";
import { EVIDENCE_PAGE, EVIDENCE_PAGE_MAX } from "./alerts";
import { BACKTEST_DAYS, BACKTEST_K } from "./feed-provider-detail";
import type { SeenDevice, SettingsView, UiEventFrame } from "@/api/types";

const T = { timeout: 8000 };
type Rec = Record<string, unknown>;
const gets = (calls: Call[], path: string) => calls.filter((c) => c.method === "GET" && c.path === path);
const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

interface FakeSocket {
  open(): void;
  emit(data: unknown): void;
}
const socket = () => (globalThis.WebSocket as unknown as { instances: FakeSocket[] }).instances.at(-1)!;

const FRESH = capturedSettings("/settings (fresh)");
const ROTATING = capturedSettings("/settings (rotating)");
const ROTATED = capturedSettings("/settings (rotated)");
const bodyOf = (key: string) => captured(key).body;
const messageOf = (key: string) => (bodyOf(key) as { error: { message: string } }).error.message;
const lancaEvents = W5.events.lanca as Extract<UiEventFrame, { type: "lanca" }>[];
const lancaEvent = (event: string) => lancaEvents.find((f) => f.data.event === event)!;
/** The keys of `keys` a query client marks stale. */
const staleOf = (qc: QueryClient, keys: (readonly unknown[])[]) => keys.filter((k) => qc.getQueryCache().find({ queryKey: k, exact: true })?.state.isInvalidated).map((k) => k.join("/"));

describe("P2: PUT settings' two 409s, each with its words and action (core 07acc1c)", () => {
  it("captured: a replaced root is `lanca_root_changed`, a previous root in use `conflict`", () => {
    expect(captured("PUT /settings lanca.zones (replaced root)")).toMatchObject({ status: 409, body: { error: { code: LANCA_ROOT_CHANGED } } });
    expect(captured("PUT /settings lanca.zones (stale rotate_from)")).toMatchObject({ status: 409, body: { error: { code: LANCA_ROOT_CHANGED } } });
    expect(captured("PUT /settings lanca.zones (previous root in use)")).toMatchObject({ status: 409, body: { error: { code: "conflict" } } });
    const err = (key: string) => {
      const b = bodyOf(key) as { error: { code: string; message: string } };
      return new ApiError(captured(key).status, b.error.code, b.error.message);
    };
    // Told apart by the code alone, not by the root core has now.
    expect(zonesRefusal(err("PUT /settings lanca.zones (replaced root)")).kind).toBe("stale");
    expect(zonesRefusal(new StaleRoot(err("PUT /settings lanca.zones (replaced root)"), null)).kind).toBe("stale");
    expect(zonesRefusal(err("PUT /settings lanca.zones (previous root in use)")).kind).toBe("in-use");
    expect(zonesRefusal(new ApiError(409, "busy", "something else")).kind).toBe("other");
  });

  it("lanca_root_changed: names the root core has now, once, and Reload settings puts the draft on it to decide again", async () => {
    const user = userEvent.setup();
    let state: SettingsView = FRESH;
    // After core's refusal: the read that tells the root core has now answers, the reads after it
    // wait until released (the page names the root from that first read at once).
    let afterRefusal = 0;
    let release: (() => void) | null = null;
    const { calls } = mockApi([
      {
        method: "GET",
        path: "/settings",
        body: () => (afterRefusal > 0 && afterRefusal++ > 1 && !release ? new Promise<SettingsView>((r) => (release = () => r(state))) : state),
      },
      {
        method: "PUT",
        path: "/settings",
        refuses: true,
        body: () => {
          // Another tab's rotation committed between this page's read and its save.
          state = ROTATING;
          afterRefusal = 1;
          return reply(409, bodyOf("PUT /settings lanca.zones (replaced root)"));
        },
      },
    ]);
    renderApp("/settings?tab=lanca");
    const zones = await screen.findByLabelText("Zones", undefined, T);
    await user.type(zones, "other.example{Enter}");
    await user.click(screen.getByRole("button", { name: /Change zones/ }));
    await user.click(await screen.findByRole("button", { name: "Make a new root" }, T));
    const refusal = await screen.findByTestId("lanca-refusal", undefined, T);
    expect(refusal).toHaveTextContent("The LAN CA root changed since you started editing");
    expect(refusal).toHaveTextContent(messageOf("PUT /settings lanca.zones (replaced root)"));
    await waitFor(() => expect(refusal).toHaveTextContent(`now ${ROTATING.lanca.fingerprint} for home.arpa, lan.example`), T);
    // Named from the read right after the refusal, while the next one is still out.
    expect(release).not.toBeNull();
    await act(async () => release!());
    expect(screen.queryByTestId("lanca-moved")).toBeNull();
    expect(screen.getByRole("button", { name: /Change zones/ })).toBeDisabled();
    const reads = gets(calls, "/settings").length;
    await user.click(within(refusal).getByRole("button", { name: "Reload settings" }));
    await waitFor(() => expect(screen.queryByTestId("lanca-refusal")).toBeNull(), T);
    expect(gets(calls, "/settings").length).toBeGreaterThan(reads);
    // The draft is core's zones now, from the root core has: nothing to send until the admin decides.
    expect(within(zones.parentElement!).queryByText("other.example")).toBeNull();
    expect(within(zones.parentElement!).getByText("lan.example")).toBeInTheDocument();
    expect(screen.queryByTestId("lanca-moved")).toBeNull();
    expect(screen.getByRole("button", { name: /Change zones/ })).toBeDisabled();
    expect(mutations(calls)).toHaveLength(1);
  });

  it("conflict: says to wait while a previous root is in use, and that the wait is over once settings read after it say can_rotate", async () => {
    const user = userEvent.setup();
    let state: SettingsView = ROTATED;
    let held: ((v: SettingsView) => void) | null = null;
    let hold = false;
    const { calls } = mockApi([
      { method: "GET", path: "/settings", body: () => (hold ? new Promise<SettingsView>((r) => (held = r)) : state) },
      { method: "PUT", path: "/settings", refuses: true, body: () => reply(409, bodyOf("PUT /settings lanca.zones (previous root in use)")) },
    ]);
    const { queryClient } = renderApp("/settings?tab=lanca");
    await user.type(await screen.findByLabelText("Zones", undefined, T), "other.example{Enter}");
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    act(() => socket().open());
    // The settings read after core's answer is held: the page still has can_rotate true from before.
    hold = true;
    await user.click(screen.getByRole("button", { name: /Change zones/ }));
    await user.click(await screen.findByRole("button", { name: "Make a new root" }, T));
    const refusal = await screen.findByTestId("lanca-refusal", undefined, T);
    expect(refusal).toHaveTextContent("The previous root is still in use");
    expect(refusal).toHaveTextContent(messageOf("PUT /settings lanca.zones (previous root in use)"));
    expect(refusal).toHaveTextContent(/Wait until every edge listed above reports/);
    await waitFor(() => expect(held).not.toBeNull(), T);
    hold = false;
    await act(async () => held!(ROTATING));
    await waitFor(() => expect(screen.getByTestId("previous-root")).toBeInTheDocument(), T);
    expect(screen.getByTestId("lanca-refusal")).toHaveTextContent("The previous root is still in use");
    // The refusal covers what the blocked notice would say.
    expect(screen.queryByTestId("lanca-blocked")).toBeNull();
    expect(screen.getByRole("button", { name: /Change zones/ })).toBeDisabled();
    // The edge reports the current root; core drops the previous one.
    state = ROTATED;
    act(() => socket().emit(lancaEvent("previous_dropped")));
    await waitFor(() => expect(screen.getByTestId("lanca-refusal")).toHaveTextContent("The previous root is no longer in use"), T);
    expect(screen.getByTestId("lanca-refusal")).toHaveTextContent(/change the zones again when ready/);
    expect(screen.getByRole("button", { name: /Change zones/ })).toBeEnabled();
    expect(mutations(calls)).toHaveLength(1);
  });
});

describe("P3: the lanca event names the previous root (LancaEventKind, `previous`)", () => {
  it("captured: rotated names the new root and the one it replaced, previous_dropped the root dropped", () => {
    const rotated = lancaEvent("rotated").data;
    const dropped = lancaEvent("previous_dropped").data;
    expect([rotated.root, rotated.previous, rotated.current]).toEqual([ROTATED.lanca.fingerprint, FRESH.lanca.fingerprint, ROTATED.lanca.fingerprint]);
    expect([dropped.root, dropped.previous, dropped.current]).toEqual([FRESH.lanca.fingerprint, FRESH.lanca.fingerprint, ROTATED.lanca.fingerprint]);
    expect(lancaEventOf(rotated)).toEqual(rotated);
    expect(lancaEventOf({ ...rotated, event: "rotate" })).toBeNull();
    expect(lancaEventOf({ event: "rotated", root: rotated.root, current: rotated.current })).toBeNull();
    expect(lancaEventOf(null)).toBeNull();
    expect(replacedRoot(rotated, ROTATED.lanca.fingerprint)).toBe(FRESH.lanca.fingerprint);
    expect(replacedRoot(rotated, FRESH.lanca.fingerprint)).toBeNull();
    expect(replacedRoot(dropped, ROTATED.lanca.fingerprint)).toBeNull();
    expect(finishedRotation(dropped, ROTATED.lanca)).toBe(FRESH.lanca.fingerprint);
    // Not while the settings still list the dropped root, nor for another current root.
    expect(finishedRotation(dropped, ROTATING.lanca)).toBeNull();
    expect(finishedRotation(dropped, FRESH.lanca)).toBeNull();
    expect(finishedRotation(rotated, ROTATED.lanca)).toBeNull();
    expect(finishedRotation(undefined, ROTATED.lanca)).toBeNull();
  });

  it("a dirty draft's notice names the root another tab's rotation replaced", async () => {
    const user = userEvent.setup();
    let state: SettingsView = FRESH;
    mockApi([{ method: "GET", path: "/settings", pure: true, body: () => state }]);
    renderApp("/settings?tab=lanca");
    await user.type(await screen.findByLabelText("Zones", undefined, T), "other.example{Enter}");
    act(() => socket().open());
    state = ROTATING;
    act(() => socket().emit(lancaEvent("rotated")));
    const moved = await screen.findByTestId("lanca-moved", undefined, T);
    expect(moved).toHaveTextContent(`It is now ${ROTATING.lanca.fingerprint} for home.arpa, lan.example, replacing root ${FRESH.lanca.fingerprint}.`);
  });

  it("this tab's rotation names the root it replaced; previous_dropped says the rotation finished, naming the root dropped", async () => {
    const user = userEvent.setup();
    let state: SettingsView = FRESH;
    mockApi([
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
    const { queryClient } = renderApp("/settings?tab=lanca");
    await user.type(await screen.findByLabelText("Zones", undefined, T), "lan.example{Enter}");
    await user.click(screen.getByRole("button", { name: /Change zones/ }));
    await user.click(await screen.findByRole("button", { name: "Make a new root" }, T));
    const done = await screen.findByTestId("lanca-rotated", undefined, T);
    expect(done).toHaveTextContent(`replacing root ${FRESH.lanca.fingerprint}`);
    await waitFor(() => expect(screen.getByTestId("previous-root")).toBeInTheDocument(), T);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    act(() => socket().open());
    // The event comes first; the settings read it causes still lists the root until it lands.
    state = ROTATED;
    act(() => socket().emit(lancaEvent("previous_dropped")));
    const finished = await screen.findByTestId("lanca-finished", undefined, T);
    expect(finished).toHaveTextContent(`Core no longer trusts the previous root ${FRESH.lanca.fingerprint}`);
    expect(screen.queryByTestId("previous-root")).toBeNull();
  });
});

describe("P4: lanca_served and dnssec_queued (coalesced)", () => {
  it("lanca_served reads the LAN CA view again, so an edge's progress shows without polling; nothing else", async () => {
    const prev = ROTATING.lanca.previous[0];
    const two = { ...ROTATING, lanca: { ...ROTATING.lanca, previous: [{ ...prev, edges: prev.edges.map((e) => ({ ...e, listeners: [...e.listeners, "lan-doh"] })) }] } };
    let state: SettingsView = two;
    const { calls } = mockApi([{ method: "GET", path: "/settings", body: () => state }]);
    const { queryClient } = renderApp("/settings?tab=lanca");
    const previous = await screen.findByTestId("previous-root", undefined, T);
    expect(within(previous).getByText("lan-dot, lan-doh")).toBeInTheDocument();
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    act(() => socket().open());
    // The socket's first open reads the settings once more (events keep them fresh: keptByEvents).
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    const n = gets(calls, "/settings").length;
    // The edge's lan-doh listener now serves a certificate from the current root.
    state = ROTATING;
    const frame = capturedEvent("lanca_served");
    expect(frame.data).toEqual({ edges: [prev.edges[0].edge_id], edges_truncated: false, reports: 1 });
    act(() => socket().emit(frame));
    await waitFor(() => expect(within(screen.getByTestId("previous-root")).getByText("lan-dot")).toBeInTheDocument(), T);
    expect(gets(calls, "/settings")).toHaveLength(n + 1);
    // No timer reads the settings while a rotation is in progress (the clock is synchronised).
    const settings = queryClient.getQueryCache().find({ queryKey: qk.settings, exact: true })!;
    const interval = (settings.observers[0].options as { refetchInterval?: unknown }).refetchInterval;
    expect(typeof interval === "function" ? (interval as (q: unknown) => unknown)(settings) : interval).toBe(false);
    const qc = new QueryClient();
    const keys = [qk.settings, qk.identity, qk.edges, qk.dnssecQueue, ["alerts"]];
    for (const k of keys) qc.setQueryData(k, {});
    applyEvent(qc, frame);
    expect(staleOf(qc, keys)).toEqual(["settings"]);
  });

  it("dnssec_queued reads the DNSSEC queue again, not the results", async () => {
    const { calls } = mockApi();
    const { queryClient } = renderApp("/dnssec");
    await screen.findByRole("table", { name: "DNSSEC queue" }, T);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    act(() => socket().open());
    // The socket's first open reads both once more (events keep them fresh: api/events.ts keptByEvents).
    await waitFor(() => expect(gets(calls, "/dnssec/queue").length).toBeGreaterThan(1), T);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    const [r0, q0] = [gets(calls, "/dnssec/results").length, gets(calls, "/dnssec/queue").length];
    const frame = capturedEvent("dnssec_queued");
    // Core a3eb6d5 counts every change to the queue: here a check queued, then waiting for an
    // edge DoH listener (the capture's core has none).
    expect(frame.data).toEqual({ validation: 1, crosscheck: 0, joined: 0, retried: 0, waiting: 1, crosscheck_retried: 0, crosscheck_ended: 0, dropped: 0, stamped: 0 });
    act(() => socket().emit(frame));
    await waitFor(() => expect(gets(calls, "/dnssec/queue")).toHaveLength(q0 + 1), T);
    await pause(300);
    expect(gets(calls, "/dnssec/results")).toHaveLength(r0);
    const qc = new QueryClient();
    const keys = [qk.dnssecQueue, [...qk.dnssecResults, "all"], qk.settings];
    for (const k of keys) qc.setQueryData(k, {});
    applyEvent(qc, frame);
    expect(staleOf(qc, keys)).toEqual(["dnssec-queue"]);
  });
});

describe("P5: the restoring tab knows its own restore event by the generation", () => {
  it("captured: the restore's answer and its event carry the same generation", () => {
    expect((bodyOf("PUT /config/export") as { generation: number }).generation).toBe(capturedEvent("restore").data.generation);
  });

  it("re-reads once per restore generation: the answer and then its event, or the event first; another restore again (unit)", () => {
    const qc = new QueryClient();
    const heard: string[] = [];
    renderHook(() => useUiEvent((ev) => heard.push(ev.type)));
    resyncForRestore(qc, 1);
    resyncForRestore(qc, 1);
    expect(heard).toEqual(["resync"]);
    applyEvent(qc, { type: "restore", data: { at: "2026-11-24T00:00:00Z", generation: 1 } });
    expect(heard).toHaveLength(1);
    applyEvent(qc, { type: "restore", data: { at: "2026-11-24T00:00:00Z", generation: 2 } });
    resyncForRestore(qc, 2);
    expect(heard).toHaveLength(2);
    // Another page (query client) keeps its own; a generation that isn't a number re-reads.
    resyncForRestore(new QueryClient(), 1);
    expect(heard).toHaveLength(3);
    resyncForRestore(qc, undefined);
    resyncForRestore(qc, "1");
    resyncForRestore(qc, "1");
    resyncForRestore(qc, 1.5);
    resyncForRestore(qc, 1.5);
    expect(heard).toHaveLength(8);
  });

  it("forgets those generations when the event socket closes and when it opens again (core may have restarted, counting again)", async () => {
    mockApi();
    const { queryClient } = renderApp("/settings?tab=lanca");
    await screen.findByLabelText("Zones", undefined, T);
    const heard: string[] = [];
    renderHook(() => useUiEvent((e) => e.type === "resync" && heard.push(e.type)));
    act(() => socket().open());
    act(() => resyncForRestore(queryClient, 1));
    expect(heard).toHaveLength(1);
    const first = socket() as FakeSocket & { onclose: () => void };
    act(() => first.onclose());
    // A restore's answer while the socket is down: core restarted and counts from 1 again.
    act(() => resyncForRestore(queryClient, 1));
    expect(heard).toHaveLength(2);
    // The reconnect re-reads everything; core's next restore of generation 1 is another one.
    await waitFor(() => expect(socket()).not.toBe(first), T);
    act(() => socket().open());
    expect(heard).toHaveLength(3);
    act(() => socket().emit({ type: "restore", data: { at: "2026-11-24T00:00:00Z", generation: 1 } }));
    expect(heard).toHaveLength(4);
  });

  it("the restoring tab re-reads everything once, whichever of core's answer and its event comes first", async () => {
    const user = userEvent.setup();
    const done = bodyOf("PUT /config/export") as { generation: number };
    const ev = capturedEvent("restore");
    let release: ((v: unknown) => void) | null = null;
    let holdAnswer = false;
    mockApi([
      {
        method: "PUT",
        path: "/config/export",
        body: () => (holdAnswer ? new Promise((r) => (release = () => r({ ...done, generation: done.generation + 1 }))) : done),
      },
    ]);
    renderApp("/settings?tab=export");
    const heard: string[] = [];
    // The re-reads (`resync`), not the raw `restore` frames listeners also get.
    renderHook(() => useUiEvent((e) => e.type === "resync" && heard.push(e.type)));
    await user.upload(await screen.findByLabelText("File", undefined, T), new File([JSON.stringify(W5["GET /config/export"])], "picket-config.json", { type: "application/json" }));
    await screen.findByTestId("export-head", undefined, T);
    act(() => socket().open());
    const restore = async () => {
      await user.click(screen.getByRole("button", { name: /^Restore$/ }));
      await user.click(await screen.findByRole("button", { name: "Restore" }, T));
    };
    // The answer first, then its event.
    await restore();
    await screen.findByTestId("restore-result", undefined, T);
    expect(heard).toEqual(["resync"]);
    act(() => socket().emit(ev));
    await pause(100);
    expect(heard).toEqual(["resync"]);
    // The next restore's event first, then its answer.
    holdAnswer = true;
    await restore();
    await waitFor(() => expect(release).not.toBeNull(), T);
    act(() => socket().emit({ ...ev, data: { ...ev.data, generation: done.generation + 1 } }));
    expect(heard).toEqual(["resync", "resync"]);
    await act(async () => release!(null));
    await waitFor(() => expect(screen.getAllByText(/^Restored/).length).toBeGreaterThan(1), T);
    await pause(100);
    expect(heard).toEqual(["resync", "resync"]);
  });
});

describe("P6: limits, days and k within core's bounds (400 outside since core 07acc1c)", () => {
  const limits = W5.limits as Record<string, { status: number; body: unknown }>;

  it("the contract refuses what the captured core refused, and passes what it answered", () => {
    expect(Object.keys(limits).length).toBeGreaterThan(15);
    for (const [url, got] of Object.entries(limits)) {
      const u = new URL(url, "https://core");
      const found = contractViolations("GET", u.pathname, u.searchParams, undefined);
      if (got.status === 200) expect(found, url).toEqual([]);
      else {
        expect(got.status, url).toBe(400);
        const name = [...u.searchParams.keys()].find((k) => ["limit", "days", "k"].includes(k))!;
        const r = queryRange(`/api/ui/v1${u.pathname.replace(/^\/feed-providers\/[^/]+/, "/feed-providers/{id}").replace(/^\/alerts\/\d+/, "/alerts/{id}").replace(/^\/feeds\/[^/]+/, "/feeds/{id}").replace(/^\/bundles\/[^/]+/, "/bundles/{id}")}`, name);
        expect(found, url).toEqual([expect.stringMatching(new RegExp(`: 400 ${name}: ${rangeText(r).replace(/\./g, "\\.")}$`))]);
        // Core says the same range in its own words.
        expect((got.body as { error: { message: string } }).error.message, url).toBe(`${name}: ${rangeText(r)}`);
      }
    }
    expect(contractViolations("GET", "/feed-providers/x/backtest", new URLSearchParams("k=0x10"), undefined)).toEqual([expect.stringMatching(/400 k: a number/)]);
    expect(contractViolations("GET", "/feed-providers/x/backtest", new URLSearchParams("days=7.5"), undefined)).toEqual([expect.stringMatching(/400 days: a whole number/)]);
  });

  it("reads core's bounds from its document; the limits the UI sends are inside them (unit)", () => {
    expect(queryRange("/api/ui/v1/top", "limit")).toEqual({ min: 1, max: 100, integer: true });
    expect(queryRange("/api/ui/v1/logs", "limit")).toEqual({ min: 1, max: 500, integer: true });
    expect(BACKTEST_DAYS).toEqual({ min: 1, max: 60, integer: true });
    expect(BACKTEST_K).toEqual({ min: 0.1, max: 50, integer: false });
    expect(() => queryRange("/api/ui/v1/logs", "nope")).toThrow(/no bounds/);
    const evidence = queryRange("/api/ui/v1/alerts/{id}/evidence", "limit");
    expect(EVIDENCE_PAGE_MAX).toBe(evidence.max);
    expect(EVIDENCE_PAGE).toBeGreaterThanOrEqual(evidence.min);
    expect(rangeProblem("61", BACKTEST_DAYS)).toBe("A whole number from 1 to 60.");
    expect(rangeProblem("7.5", BACKTEST_DAYS)).toBe("A whole number from 1 to 60.");
    expect(rangeProblem("", BACKTEST_DAYS)).toBe("Enter a whole number from 1 to 60.");
    expect(rangeProblem("60", BACKTEST_DAYS)).toBeNull();
    expect(rangeProblem("1", BACKTEST_DAYS)).toBeNull();
    expect(rangeProblem("0", BACKTEST_DAYS)).toBe("A whole number from 1 to 60.");
    expect(rangeProblem("", BACKTEST_K, true)).toBeNull();
    expect(rangeProblem("0.05", BACKTEST_K, true)).toBe("A number from 0.1 to 50.");
    expect(rangeProblem("50.5", BACKTEST_K, true)).toBe("A number from 0.1 to 50.");
    expect(rangeProblem("0.1", BACKTEST_K, true)).toBeNull();
    expect(rangeProblem("abc", BACKTEST_K, true)).toBe("A number from 0.1 to 50.");
  });

  it("the backtest refuses days and k outside core's range in the form, with the range, and sends what is inside", async () => {
    const user = userEvent.setup();
    const asked = limits["/feed-providers/hagezi/backtest?days=60&k=0.1"];
    expect(asked.status).toBe(200);
    const { calls, fixtures } = mockApi([
      { method: "GET", path: "/feed-providers/hagezi/backtest", body: (c: Call) => (c.query.has("days") ? asked.body : fixtures["/feed-providers/hagezi/backtest"]) },
    ]);
    renderApp("/feed-providers/hagezi?tab=backtest");
    const table = await screen.findByRole("table", { name: "Backtest" }, T);
    expect(within(table).getAllByRole("row")).toHaveLength(5);
    const sent = () => gets(calls, "/feed-providers/hagezi/backtest");
    // Core's defaults first (7 days, each of 1, 2, 3 and 5).
    expect(Object.fromEntries(sent()[0].query)).toEqual({});
    const days = screen.getByLabelText("Days");
    const k = screen.getByLabelText("k");
    const run = screen.getByRole("button", { name: "Run" });
    expect(screen.getByText("1 to 60: the history replayed.")).toBeInTheDocument();
    expect(screen.getByText("0.1 to 50; blank for each of 1, 2, 3 and 5.")).toBeInTheDocument();
    await user.clear(days);
    await user.type(days, "61");
    expect(screen.getByText("A whole number from 1 to 60.")).toBeInTheDocument();
    expect(days).toHaveAttribute("aria-invalid", "true");
    expect(run).toBeDisabled();
    await user.clear(days);
    await user.type(days, "60");
    await user.type(k, "0.05");
    expect(screen.getByText("A number from 0.1 to 50.")).toBeInTheDocument();
    expect(k).toHaveAttribute("aria-invalid", "true");
    expect(run).toBeDisabled();
    // Enter in the form sends nothing either, nor does a submit however it comes.
    await user.type(k, "{Enter}");
    fireEvent.submit(screen.getByRole("form", { name: "Backtest settings" }));
    await pause(100);
    expect(sent()).toHaveLength(1);
    await user.clear(k);
    await user.type(k, "0.1");
    expect(run).toBeEnabled();
    await user.click(run);
    await waitFor(() => expect(sent()).toHaveLength(2), T);
    expect(Object.fromEntries(sent()[1].query)).toEqual({ days: "60", k: "0.1" });
    await waitFor(() => expect(within(screen.getByRole("table", { name: "Backtest" })).getAllByRole("row")).toHaveLength(2), T);
    expect(within(screen.getByRole("table", { name: "Backtest" })).getByText("0.1")).toBeInTheDocument();
    // k left blank again: core's own set of k, for the days asked.
    await user.clear(k);
    await user.clear(days);
    await user.type(days, "30");
    await user.click(run);
    await waitFor(() => expect(sent()).toHaveLength(3), T);
    expect(Object.fromEntries(sent()[2].query)).toEqual({ days: "30" });
  });
});

describe("P7: devices' MACs as core currently knows them (nothing inferred)", () => {
  const devices = (W5["/devices"] as { items: SeenDevice[] }).items;

  it("captured: a device keyed by a client name no entry has, or whose entry lists no MACs, has no MAC", () => {
    const laptop = devices.find((d) => d.key === "laptop")!;
    const phone = devices.find((d) => d.key === "phone")!;
    expect([laptop.mac, laptop.macs, laptop.client]).toEqual([null, [], null]);
    expect([phone.mac, phone.macs, phone.client]).toEqual([null, [], "phone"]);
    const tablet = devices.find((d) => d.key === "tablet")!;
    expect([tablet.mac, tablet.macs]).toEqual(["02:11:22:33:44:55", ["02:11:22:33:44:55"]]);
  });

  it("shows no MAC for them; adds a former client's device under its name by its addresses, never offers one a client names", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi();
    renderApp("/clients");
    const table = await screen.findByRole("table", { name: "Seen devices" }, T);
    const row = (name: string) => within(table).getByRole("link", { name }).closest("tr")!;
    const phone = row("phone");
    expect(within(phone).getByText("client")).toBeInTheDocument();
    expect(within(phone).getByText("—")).toBeInTheDocument();
    expect(within(phone).queryByRole("button", { name: /Add as client/ })).toBeNull();
    const laptop = row("laptop");
    expect(within(laptop).getByText("—")).toBeInTheDocument();
    expect(within(laptop).queryByText("seen at its address")).toBeNull();
    await user.click(within(laptop).getByRole("button", { name: /Add as client/ }));
    const sheet = await screen.findByRole("dialog", undefined, T);
    expect(within(sheet).getByText("New client")).toBeInTheDocument();
    expect(within(sheet).getByDisplayValue("laptop")).toBeInTheDocument();
    expect(within(sheet).getAllByText("192.0.2.12").length).toBeGreaterThan(0);
    expect(mutations(calls)).toHaveLength(0);
  });
});

describe("P8: decimal scores", () => {
  it("shows a lookup's score in the query log as core sends it (0.97)", async () => {
    const user = userEvent.setup();
    const rec = W5["/logs/{seq 18}"] as Rec & { id: string; lookups: { score: number }[] };
    expect(rec.lookups[0].score).toBe(0.97);
    mockApi([
      { method: "GET", path: "/logs", body: { items: [rec], next_cursor: null } },
      { method: "GET", path: `/logs/${rec.id}`, body: rec },
    ]);
    renderApp("/query-log");
    const table = await screen.findByRole("table", { name: "Query log" }, T);
    await user.click(await within(table).findByText("lookup-block.example", undefined, T));
    const sheet = await screen.findByRole("dialog", undefined, T);
    expect(await within(sheet).findByText("score 0.97", undefined, T)).toBeInTheDocument();
  });
});

describe("P9: the contract models core 07acc1c (unit)", () => {
  it("a mock must answer the 409 code core gives for the request's state", async () => {
    const at = (s: SettingsView) => (p: string) => (p === "/settings" ? s : undefined);
    const body = { lanca: { zones: ["home.arpa", "x.example"], rotate_from: FRESH.lanca.fingerprint } };
    const predicted = contractViolations("PUT", "/settings", new URLSearchParams(), body, at(ROTATING));
    expect(predicted).toEqual([expect.stringMatching(/409 lanca_root_changed: /)]);
    const conflict = bodyOf("PUT /settings lanca.zones (previous root in use)");
    const changed = bodyOf("PUT /settings lanca.zones (replaced root)");
    expect(refusalViolations("PUT", "/settings", 409, conflict, predicted)).toEqual([expect.stringMatching(/answers this request 409 lanca_root_changed, not "conflict"/)]);
    expect(refusalViolations("PUT", "/settings", 409, changed, predicted)).toEqual([]);
    const inUse = contractViolations("PUT", "/settings", new URLSearchParams(), { lanca: { zones: ["home.arpa"], rotate_from: ROTATING.lanca.fingerprint } }, at(ROTATING));
    expect(refusalViolations("PUT", "/settings", 409, changed, inUse)).toEqual([expect.stringMatching(/answers this request 409 conflict/)]);
    expect(refusalViolations("PUT", "/settings", 409, conflict, inUse)).toEqual([]);
    // Through the mock core.
    mockApi([
      { method: "GET", path: "/settings", pure: true, body: () => ROTATING },
      { method: "PUT", path: "/settings", refuses: true, body: () => reply(409, conflict) },
    ]);
    await fetch("/api/ui/v1/settings", { method: "PUT", headers: { "content-type": "application/json", "x-picket-ui": "1" }, body: JSON.stringify(body) });
    expect(takeViolations()).toEqual([expect.stringMatching(/answers this request 409 lanca_root_changed/)]);
  });

  it("checks the event frames a test emits for the new and changed events, and a restore's answer", () => {
    for (const t of ["lanca", "lanca_served", "dnssec_queued", "restore", "alert", "feed_run"]) for (const f of W5.events[t]) expect(eventViolations(f), t).toEqual([]);
    const rotated = lancaEvent("rotated");
    const { previous: _drop, ...noPrevious } = rotated.data;
    expect(eventViolations({ ...rotated, data: noPrevious })).toEqual([expect.stringMatching(/matches no variant/)]);
    expect(eventViolations({ ...rotated, data: { ...rotated.data, event: "rotate" } })).toEqual([expect.stringMatching(/matches no variant/)]);
    expect(eventViolations({ type: "lanca_served", data: { edges: ["e"], reports: 1 } })).toEqual([expect.stringMatching(/matches no variant/)]);
    expect(eventViolations({ type: "dnssec_queued", data: { validation: "1", crosscheck: 0 } })).toEqual([expect.stringMatching(/matches no variant/)]);
    expect(eventViolations({ type: "restore", data: { at: "2026-11-24T00:00:00Z" } })).toEqual([expect.stringMatching(/matches no variant/)]);
    // Core a3eb6d5's coalesced alert and feed_run: a frame of one alert or one run, as core sent them before, is refused.
    expect(eventViolations({ type: "alert", data: { id: 1, kind: "x", state: "open", count: 1 } })).toEqual([expect.stringMatching(/matches no variant/)]);
    expect(eventViolations({ type: "feed_run", data: { feed: "f", run: 1, kind: "download", status: "applied", version: null, saved_at: null, source_run: null } })).toEqual([expect.stringMatching(/matches no variant/)]);
    expect(eventViolations(truncatedAlertFrame([{ id: 1 }, { id: 2, deleted: true }]))).toEqual([]);
    expect(eventViolations(truncatedRunFrame([{ feed: "f", run: 1 }]))).toEqual([]);
    expect(eventViolations(alertFrame([{ id: 1 }, { id: 2, deleted: true }]))).toEqual([]);
    expect(eventViolations(feedRunFrame([{ feed: "f", run: 1 }]))).toEqual([]);
    // Partial frames of other types stay the tests' own.
    expect(eventViolations({ type: "edge_status", data: { edge: "e1" } })).toEqual([]);
    // The fake socket notes a frame core wouldn't send.
    (globalThis.WebSocket as unknown as { new (url: string): FakeSocket }).prototype.emit.call({ onmessage: null }, { ...rotated, data: noPrevious });
    expect(takeViolations()).toEqual([expect.stringMatching(/event lanca: matches no variant/)]);
    const restored = bodyOf("PUT /config/export") as Rec;
    expect(answerViolations("PUT", "/config/export", 200, restored)).toEqual([]);
    const { generation: _gen, ...old } = restored;
    expect(answerViolations("PUT", "/config/export", 200, old)).toEqual([expect.stringMatching(/answer\.generation: required/)]);
    expect(answerViolations("PUT", "/config/export", 409, { error: { code: "busy", message: "" } })).toEqual([]);
  });
});
