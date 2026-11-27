// Review fixes for the UI at b3c771a (dev/briefs/fix-b3c-ui.md; reviews dev/briefs/r07/ui-opus.md
// and ui-codex.md, Codex's repro tests reused): U1 this tab's own rotation, whose event and
// settings read come before core's answer, isn't "a root changed since you started editing"; U2
// Reload settings that can't read them keeps the refusal; U3 a Backtest `k` or Days the browser
// can't read as a number is refused in the form; U4 the "rotation finished" notice lives with the
// LAN CA tab, and a `conflict` refusal's stale words go once the wait is over; U5 an event during a
// first read in flight reads again after it; U6 Run always asks core.
import { describe, expect, it } from "vitest";
import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryObserver } from "@tanstack/react-query";
import { mockApi, mutations, reply, type Call } from "@/test/mock-api";
import { renderApp } from "@/test/render";
import { W5, captured, capturedEvent, capturedSettings } from "@/test/core-w5";
import { alertFrame, feedRunFrame, jobFrame, truncatedAlertFrame, type AlertLike } from "@/test/events";
import { applyEvent } from "@/api/events";
import { qk } from "@/api/queries";
import type { SettingsView, UiEventFrame } from "@/api/types";

const T = { timeout: 8000 };
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
const lancaEvent = (event: string) => (W5.events.lanca as Extract<UiEventFrame, { type: "lanca" }>[]).find((f) => f.data.event === event)!;
const settingsNow = (qc: QueryClient) => qc.getQueryData<SettingsView>(qk.settings);

describe("U1: this tab's rotation, its event and settings read first, then core's answer", () => {
  it("never says the root changed since editing while its own rotation is out", async () => {
    const user = userEvent.setup();
    let state: SettingsView = FRESH;
    let answer: (() => void) | null = null;
    mockApi([
      { method: "GET", path: "/settings", pure: true, body: () => state },
      {
        method: "PUT",
        path: "/settings",
        body: () =>
          new Promise((r) => {
            // Core committed; its answer is still on the way.
            state = ROTATING;
            answer = () => r(bodyOf("PUT /settings lanca.zones (rotation)"));
          }),
      },
    ]);
    const { queryClient } = renderApp("/settings?tab=lanca");
    await user.type(await screen.findByLabelText("Zones", undefined, T), "lan.example{Enter}");
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    act(() => socket().open());
    await user.click(screen.getByRole("button", { name: /Change zones/ }));
    await user.click(await screen.findByRole("button", { name: "Make a new root" }, T));
    await waitFor(() => expect(answer).not.toBeNull(), T);
    // Core sends its `lanca rotated` event before the answer; the settings read it causes lands first.
    act(() => socket().emit(lancaEvent("rotated")));
    await waitFor(() => expect(settingsNow(queryClient)?.lanca.fingerprint).toBe(ROTATING.lanca.fingerprint), T);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    await pause(50);
    // Answered before the check, so a failure here can't hold the settings' write queue for later tests.
    const movedWhileOut = screen.queryByTestId("lanca-moved")?.textContent ?? null;
    await act(async () => answer!());
    expect(movedWhileOut).toBeNull();
    const done = await screen.findByTestId("lanca-rotated", undefined, T);
    expect(done).toHaveTextContent(`replacing root ${FRESH.lanca.fingerprint}`);
    expect(screen.queryByTestId("lanca-moved")).toBeNull();
  });
});

describe("U2: Reload settings after a replaced root, when the settings can't be read", () => {
  it("keeps the refusal and says the reload failed; the draft stays off the replaced root; a later reload that reads them rebases", async () => {
    const user = userEvent.setup();
    let failing = false;
    let state: SettingsView = FRESH;
    const { calls } = mockApi([
      { method: "GET", path: "/settings", body: () => (failing ? Promise.reject(new TypeError("Failed to fetch")) : state) },
      {
        method: "PUT",
        path: "/settings",
        refuses: true,
        body: () => {
          // Another tab's rotation committed; core can't be reached right after.
          state = ROTATING;
          failing = true;
          return reply(409, bodyOf("PUT /settings lanca.zones (replaced root)"));
        },
      },
    ]);
    const { queryClient } = renderApp("/settings?tab=lanca");
    const zones = await screen.findByLabelText("Zones", undefined, T);
    await user.type(zones, "other.example{Enter}");
    await user.click(screen.getByRole("button", { name: /Change zones/ }));
    await user.click(await screen.findByRole("button", { name: "Make a new root" }, T));
    const refusal = await screen.findByTestId("lanca-refusal", undefined, T);
    expect(refusal).toHaveTextContent("The LAN CA root changed since you started editing");
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    // The page still has the replaced root (nothing newer could be read).
    expect(settingsNow(queryClient)?.lanca.fingerprint).toBe(FRESH.lanca.fingerprint);
    const reads = gets(calls, "/settings").length;
    await user.click(within(refusal).getByRole("button", { name: "Reload settings" }));
    await waitFor(() => expect(gets(calls, "/settings").length).toBeGreaterThan(reads), T);
    await waitFor(() => expect(within(screen.getByTestId("lanca-refusal")).getByRole("button", { name: "Reload settings" })).toBeEnabled(), T);
    expect(screen.getByTestId("lanca-refusal")).toHaveTextContent("The LAN CA root changed since you started editing");
    expect(screen.getByTestId("lanca-refusal")).toHaveTextContent(/Couldn't read the settings: .*Try Reload settings again/);
    // The draft is the admin's still, and no change can go out from the replaced root.
    expect(within(zones.parentElement!).getByText("other.example")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Change zones/ })).toBeDisabled();
    expect(screen.getByRole("button", { name: /Change zones/ })).toHaveAttribute("title", "Reload the settings first.");
    expect(mutations(calls)).toHaveLength(1);
    // Core is back: Reload settings puts the draft on the root core has now.
    failing = false;
    await user.click(within(screen.getByTestId("lanca-refusal")).getByRole("button", { name: "Reload settings" }));
    await waitFor(() => expect(screen.queryByTestId("lanca-refusal")).toBeNull(), T);
    expect(within(zones.parentElement!).queryByText("other.example")).toBeNull();
    expect(within(zones.parentElement!).getByText("lan.example")).toBeInTheDocument();
    expect(screen.queryByTestId("lanca-moved")).toBeNull();
  });
});

describe("U3: a Backtest field the browser can't read as a number (validity.badInput)", () => {
  /**
   * jsdom doesn't model badInput (its number input reads "1e" or "-" as "" with badInput false),
   * so the field's validity is stubbed as a browser sets it, while the typed text is one.
   */
  const stubBadInput = (input: HTMLElement) => {
    const state = { bad: false };
    Object.defineProperty(input, "validity", { configurable: true, get: () => ({ valid: !state.bad, badInput: state.bad }) });
    return state;
  };

  it("refuses k and Days in the form with the range, sends nothing, and takes them again once readable", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi();
    renderApp("/feed-providers/hagezi?tab=backtest");
    await screen.findByRole("table", { name: "Backtest" }, T);
    const sent = () => gets(calls, "/feed-providers/hagezi/backtest");
    const k = screen.getByLabelText("k");
    const days = screen.getByLabelText("Days");
    const run = screen.getByRole("button", { name: "Run" });
    const kBad = stubBadInput(k);
    // "1e": the value reads "" (blank: each of 1, 2, 3 and 5) while the field shows "1e".
    await user.type(k, "1");
    kBad.bad = true;
    await user.type(k, "e");
    expect(screen.getByText("A number from 0.1 to 50.")).toBeInTheDocument();
    expect(k).toHaveAttribute("aria-invalid", "true");
    expect(run).toBeDisabled();
    fireEvent.submit(screen.getByRole("form", { name: "Backtest settings" }));
    await pause(100);
    expect(sent()).toHaveLength(1);
    // Cleared: blank again, core's own set of k.
    kBad.bad = false;
    await user.clear(k);
    expect(screen.getByText("0.1 to 50; blank for each of 1, 2, 3 and 5.")).toBeInTheDocument();
    expect(run).toBeEnabled();
    // "-" alone: the value stays "", so only the input event says so (no change event).
    kBad.bad = true;
    await user.type(k, "-");
    expect(screen.getByText("A number from 0.1 to 50.")).toBeInTheDocument();
    expect(run).toBeDisabled();
    kBad.bad = false;
    await user.clear(k);
    expect(run).toBeEnabled();
    // Days the same, in its own words: not "Enter a number" while the field shows one.
    const daysBad = stubBadInput(days);
    await user.clear(days);
    expect(screen.getByText("Enter a whole number from 1 to 60.")).toBeInTheDocument();
    daysBad.bad = true;
    await user.type(days, "-");
    expect(screen.getByText("A whole number from 1 to 60.")).toBeInTheDocument();
    expect(days).toHaveAttribute("aria-invalid", "true");
    expect(run).toBeDisabled();
    daysBad.bad = false;
    await user.clear(days);
    await user.type(days, "30");
    expect(run).toBeEnabled();
    await user.click(run);
    await waitFor(() => expect(sent()).toHaveLength(2), T);
    expect(Object.fromEntries(sent()[1].query)).toEqual({ days: "30" });
  });
});

describe("U4: the LAN CA notices end when they no longer apply", () => {
  it("'The rotation finished' doesn't outlive the LAN CA tab: leaving it and coming back shows none", async () => {
    let state: SettingsView = ROTATING;
    mockApi([{ method: "GET", path: "/settings", pure: true, body: () => state }]);
    const { queryClient, router } = renderApp("/settings?tab=lanca");
    await screen.findByTestId("previous-root", undefined, T);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    act(() => socket().open());
    state = ROTATED;
    act(() => socket().emit(lancaEvent("previous_dropped")));
    expect(await screen.findByTestId("lanca-finished", undefined, T)).toHaveTextContent(FRESH.lanca.fingerprint);
    await act(() => router.navigate({ to: "/settings", search: { tab: "retention" } as never }));
    await waitFor(() => expect(screen.queryByLabelText("Zones")).toBeNull(), T);
    await act(() => router.navigate({ to: "/settings", search: { tab: "lanca" } as never }));
    await screen.findByLabelText("Zones", undefined, T);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    expect(screen.queryByTestId("lanca-finished")).toBeNull();
    expect(screen.queryByTestId("previous-root")).toBeNull();
  });

  it("a later rotation ends it", async () => {
    let state: SettingsView = ROTATING;
    mockApi([{ method: "GET", path: "/settings", pure: true, body: () => state }]);
    const { queryClient } = renderApp("/settings?tab=lanca");
    await screen.findByTestId("previous-root", undefined, T);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    act(() => socket().open());
    state = ROTATED;
    act(() => socket().emit(lancaEvent("previous_dropped")));
    await screen.findByTestId("lanca-finished", undefined, T);
    // Another tab's rotation; its event comes before the settings read it causes lands.
    act(() => socket().emit({ type: "lanca", data: { event: "rotated", root: "SHA256:later", previous: ROTATED.lanca.fingerprint, current: "SHA256:later" } }));
    await waitFor(() => expect(screen.queryByTestId("lanca-finished")).toBeNull(), T);
  });

  it("a conflict refusal whose wait is over no longer shows core's 'still in use' words", async () => {
    const user = userEvent.setup();
    let state: SettingsView = ROTATED;
    let held: ((v: SettingsView) => void) | null = null;
    let hold = false;
    mockApi([
      { method: "GET", path: "/settings", body: () => (hold ? new Promise<SettingsView>((r) => (held = r)) : state) },
      { method: "PUT", path: "/settings", refuses: true, body: () => reply(409, bodyOf("PUT /settings lanca.zones (previous root in use)")) },
    ]);
    const { queryClient } = renderApp("/settings?tab=lanca");
    await user.type(await screen.findByLabelText("Zones", undefined, T), "other.example{Enter}");
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    act(() => socket().open());
    hold = true;
    await user.click(screen.getByRole("button", { name: /Change zones/ }));
    await user.click(await screen.findByRole("button", { name: "Make a new root" }, T));
    const words = messageOf("PUT /settings lanca.zones (previous root in use)");
    expect(await screen.findByTestId("lanca-refusal", undefined, T)).toHaveTextContent(words);
    await waitFor(() => expect(held).not.toBeNull(), T);
    hold = false;
    await act(async () => held!(ROTATING));
    await waitFor(() => expect(screen.getByTestId("previous-root")).toBeInTheDocument(), T);
    expect(screen.getByTestId("lanca-refusal")).toHaveTextContent(words);
    state = ROTATED;
    act(() => socket().emit(lancaEvent("previous_dropped")));
    await waitFor(() => expect(screen.getByTestId("lanca-refusal")).toHaveTextContent("The previous root is no longer in use"), T);
    expect(screen.getByTestId("lanca-refusal")).not.toHaveTextContent(words);
    expect(screen.getByTestId("lanca-refusal")).toHaveTextContent(/Nothing was changed then/);
  });
});

describe("U5: an event during a first read in flight reads again after it", () => {
  it("a final lanca_served and previous_dropped during the first settings read aren't undone by that read's older answer (Codex)", async () => {
    let release: ((s: SettingsView) => void) | undefined;
    let n = 0;
    const { calls } = mockApi([{ method: "GET", path: "/settings", body: () => (++n === 1 ? new Promise<SettingsView>((r) => (release = r)) : ROTATED) }]);
    const { queryClient } = renderApp("/settings?tab=lanca");
    await waitFor(() => expect(release).toBeDefined(), T);
    act(() => socket().open());
    // The read's answer was made while a root was still in use; the final edge report and the
    // drop arrive while it is out.
    act(() => {
      socket().emit(capturedEvent("lanca_served"));
      socket().emit(lancaEvent("previous_dropped"));
    });
    await act(async () => release!(ROTATING));
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    await pause(100);
    expect(gets(calls, "/settings").length).toBeGreaterThan(1);
    expect(settingsNow(queryClient)?.lanca.can_rotate).toBe(true);
    expect(screen.queryByTestId("previous-root")).toBeNull();
  });

  it("an alert's own event during its first evidence read reads the evidence again after it", async () => {
    const detail = W5["/alerts/{paged}"] as { alert: AlertLike };
    const id = detail.alert.id;
    const page1 = W5["/alerts/{paged}/evidence?limit=2"];
    let release: (() => void) | undefined;
    const { calls } = mockApi([
      { method: "GET", path: `/alerts/${id}`, body: detail },
      { method: "GET", path: `/alerts/${id}/evidence`, body: () => (release ? page1 : new Promise((r) => (release = () => r(page1)))) },
    ]);
    const { queryClient } = renderApp(`/alerts/${id}`);
    await waitFor(() => expect(release).toBeDefined(), T);
    act(() => socket().open());
    // A raise adds copies after the read was answered.
    act(() => socket().emit(alertFrame([{ ...detail.alert, count: 5 }])));
    await act(async () => release!());
    await screen.findByTestId("evidence-copies", undefined, T);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    await pause(100);
    expect(gets(calls, `/alerts/${id}/evidence`)).toHaveLength(2);
  });

  it("every event's reads: a first read in flight lands, then one more read follows it (unit; fix-95e V1: never cancelled)", async () => {
    // Each event type and a query it reads again, from a first read in flight.
    const frames: [UiEventFrame | { type: string; data: unknown }, readonly unknown[]][] = [
      [alertFrame([{ id: 1, kind: "dnssec_bogus" }]), ["alerts", "list"]],
      [truncatedAlertFrame(), qk.config("feeds")],
      [{ type: "edge_status", data: { edge: "e1", event: "heartbeat" } }, qk.edges],
      [capturedEvent("dnssec_queued"), qk.dnssecQueue],
      [{ type: "dnssec", data: { outcomes: { bogus: 1 } } }, qk.dnssecQueue],
      [capturedEvent("lanca_served"), qk.settings],
      [lancaEvent("rotated"), qk.identity],
      [{ type: "temp_allow", data: { edges: ["e1"], edges_truncated: false } }, [...qk.tempAllows, "active", "e1"]],
      [feedRunFrame([{ feed: "f1", run: 1 }]), qk.config("feeds")],
      [feedRunFrame([{ feed: "f1", run: 1 }]), qk.provider("hagezi", "status")], // not a backtest: only Run reads it (final check GC1)
      [{ type: "bundle_version", data: {} }, qk.warninglists],
      [jobFrame("feed_ingest", "f1", "end", { dropped: 1 }), ["feeds", "f1", "runs"]],
    ];
    for (const [frame, key] of frames) {
      const qc = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 60_000 } } });
      const answers: ((v: string) => void)[] = [];
      // An active first read: an observer, its read out, no data yet.
      const observer = new QueryObserver(qc, { queryKey: key, queryFn: () => new Promise<string>((r) => answers.push(r)) });
      const stop = observer.subscribe(() => {});
      await waitFor(() => expect(answers).toHaveLength(1));
      applyEvent(qc, frame as UiEventFrame);
      applyEvent(qc, frame as UiEventFrame);
      await pause(10);
      const what = `${frame.type} → ${key.join("/")}`;
      expect(answers.length, `${what}: not cancelled`).toBe(1);
      // The read's answer lands; its invalidation isn't cleared with nothing read after it.
      answers[0]("before");
      await waitFor(() => expect(qc.getQueryData(key)).toBe("before"));
      await waitFor(() => expect(answers.length, `${what}: one read after`).toBe(2));
      answers[1]("after");
      await waitFor(() => expect(qc.getQueryData(key)).toBe("after"));
      await pause(10);
      expect(answers.length, `${what}: one read after, for both events`).toBe(2);
      expect(qc.getQueryState(key)?.isInvalidated).toBe(false);
      stop();
    }
  });

  it("an inactive query's read in flight (a fetchQuery's) isn't cancelled: its caller gets it, and the query is then marked stale, unread (unit; fix-95e V1)", async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const answers: ((v: string) => void)[] = [];
    const read = qc.fetchQuery({ queryKey: qk.settings, queryFn: () => new Promise<string>((r) => answers.push(r)) });
    await waitFor(() => expect(answers).toHaveLength(1));
    applyEvent(qc, capturedEvent("lanca_served"));
    await pause(20);
    expect(answers).toHaveLength(1);
    answers[0]("before");
    await expect(read).resolves.toBe("before");
    // Stale once it lands, so whoever reads it next reads core again; nobody shows it now.
    await waitFor(() => expect(qc.getQueryState(qk.settings)?.isInvalidated).toBe(true));
    await pause(20);
    expect(answers).toHaveLength(1);
    expect(qc.getQueryState(qk.settings)?.fetchStatus).toBe("idle");
    // Nothing in flight: only marked stale, nothing read (nobody shows it).
    applyEvent(qc, capturedEvent("lanca_served"));
    await pause(20);
    expect(answers).toHaveLength(1);
    expect(qc.getQueryState(qk.settings)?.isInvalidated).toBe(true);
  });
});

describe("U6: Run always asks core", () => {
  it("a second Run with the same Days and k reads again, fresh or stale, and so does a Run back to values read before", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi();
    const { queryClient } = renderApp("/feed-providers/hagezi?tab=backtest");
    await screen.findByRole("table", { name: "Backtest" }, T);
    const sent = () => gets(calls, "/feed-providers/hagezi/backtest");
    const run = screen.getByRole("button", { name: "Run" });
    const k = screen.getByLabelText("k");
    await user.click(run);
    await waitFor(() => expect(sent()).toHaveLength(2), T);
    // At once, with the answer still fresh.
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    await user.click(run);
    await waitFor(() => expect(sent()).toHaveLength(3), T);
    expect(Object.fromEntries(sent()[2].query)).toEqual({ days: "7" });
    // Older than the 15 s the UI keeps an answer fresh, without a focus or another refetch (Codex).
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    const key = [...qk.provider("hagezi", "backtest"), 7, null];
    act(() => queryClient.setQueryData(key, queryClient.getQueryData(key), { updatedAt: Date.now() - 60_000 }));
    await user.click(run);
    await waitFor(() => expect(sent()).toHaveLength(4), T);
    // k 1, then 2, then 1 again: the third Run reads k 1 again, not the answer kept for it.
    await user.type(k, "1");
    await user.click(run);
    await waitFor(() => expect(sent()).toHaveLength(5), T);
    await user.clear(k);
    await user.type(k, "2");
    await user.click(run);
    await waitFor(() => expect(sent()).toHaveLength(6), T);
    await user.clear(k);
    await user.type(k, "1");
    await user.click(run);
    await waitFor(() => expect(sent()).toHaveLength(7), T);
    expect(sent().map((c) => c.query.get("k"))).toEqual([null, null, null, null, "1", "2", "1"]);
  });
});
