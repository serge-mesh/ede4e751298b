// Review fixes on the UI for core c58ba80 (dev/briefs/fix-c58-ui.md), against answers captured
// from a real core at c58ba80 (test/core-w5.ts): V1 a rotation whose answer is lost is judged by
// the root core has afterwards, and a 200 that changed nothing says so; V2 the LAN CA view reads
// the settings again while core's clock isn't synchronised; V3 a `dnssec` event reads only the
// results lists its outcomes concern, the newest page alone past one page, throttled; V4 an
// evidence copy stays open by its record, not its row; V5 a whole-evidence download checks it
// read one run of copies; V6 what a rotation does to this browser and the devices; V7 "several
// edges" for every kind raised from records, and the allows' states in the device views.
import { describe, expect, it, vi } from "vitest";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, type QueryKey } from "@tanstack/react-query";
import { mockApi, mutations, reply, type Call } from "@/test/mock-api";
import { renderApp } from "@/test/render";
import { W5, captured, capturedSettings } from "@/test/core-w5";
import { captureDownloads } from "@/test/downloads";
import { applyEvent, dnssecResultsChanged } from "@/api/events";
import { PAGED_EVENT_GAP_MS, qk } from "@/api/queries";
import { ApiError } from "@/api/errors";
import { CLOCK_POLL_MS, answerLost, clockPoll, rotationSteps, zonesRefusal } from "./lanca";
import { copyKeys, fetchAllEvidence, seenOnSeveralEdges } from "./alerts";
import type { Alert, EvidenceView, SettingsView, UiEventFrame } from "@/api/types";

const T = { timeout: 8000 };
type Rec = Record<string, unknown>;
const gets = (calls: Call[], path: string) => calls.filter((c) => c.method === "GET" && c.path === path);
const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

interface FakeSocket {
  open(): void;
  emit(data: unknown): void;
}
const socket = () => (globalThis.WebSocket as unknown as { instances: FakeSocket[] }).instances.at(-1)!;

/** The refresh intervals a mounted query's observers resolve to now (several views may share the settings). */
function intervalsOf(qc: QueryClient, queryKey: QueryKey) {
  const query = qc.getQueryCache().find({ queryKey, exact: true });
  return (query?.observers ?? []).map((o) => {
    const v = (o.options as { refetchInterval?: unknown }).refetchInterval;
    return typeof v === "function" ? (v as (x: unknown) => unknown)(query) : v;
  });
}
const polls = (qc: QueryClient, queryKey: QueryKey) => intervalsOf(qc, queryKey).filter((v) => typeof v === "number" && v > 0);

const FRESH = capturedSettings("/settings (fresh)");
const ROTATING = capturedSettings("/settings (rotating)");
const UNSYNCED = capturedSettings("/settings (clock not synchronised)");
const bodyOf = (key: string) => captured(key).body;
const lancaEvent = (event: string) => (W5.events.lanca as Extract<UiEventFrame, { type: "lanca" }>[]).find((f) => f.data.event === event)!;
const withWeb = (s: SettingsView, web: Rec): SettingsView => ({ ...s, settings: { ...s.settings, web: { ...s.settings.web, ...web } } as SettingsView["settings"] });

/** Opens Settings → LAN CA, adds `lan.example` and confirms the change. */
async function rotate(user: ReturnType<typeof userEvent.setup>) {
  const zones = await screen.findByLabelText("Zones", undefined, T);
  await user.type(zones, "lan.example{Enter}");
  await user.click(screen.getByRole("button", { name: /Change zones/ }));
  await user.click(await screen.findByRole("button", { name: "Make a new root" }, T));
  return zones;
}

describe("V1: a rotation whose answer is lost is judged by the root core has afterwards", () => {
  // Core committed, then the answer was lost: the connection dropped, a proxy timed out or
  // answered 502, or core failed after its commit (500).
  const lost: [string, () => unknown][] = [
    ["the connection dropped", () => Promise.reject(new TypeError("Failed to fetch"))],
    ["a proxy timed out (504, not core's error)", () => reply(504, "Gateway Timeout")],
    ["core failed after its commit (500)", () => reply(500, { error: { code: "internal", message: "internal error" } })],
    ["a proxy's 503 without core's error", () => reply(503, "Service Unavailable")],
  ];
  for (const [what, answer] of lost) {
    it(`shows the new root and the re-trust instruction when ${what}`, async () => {
      const user = userEvent.setup();
      let state: SettingsView = FRESH;
      const { calls } = mockApi([
        { method: "GET", path: "/settings", pure: true, body: () => state },
        {
          method: "PUT",
          path: "/settings",
          refuses: true,
          body: () => {
            state = ROTATING;
            return answer();
          },
        },
      ]);
      renderApp("/settings?tab=lanca");
      await rotate(user);
      const done = await screen.findByTestId("lanca-rotated", undefined, T);
      expect(done).toHaveTextContent(ROTATING.lanca.fingerprint);
      expect(done).toHaveTextContent(/this browser/);
      expect(screen.queryByTestId("lanca-refusal")).toBeNull();
      expect(screen.queryByTestId("lanca-unknown")).toBeNull();
      expect(screen.queryByTestId("lanca-moved")).toBeNull();
      expect(mutations(calls)).toHaveLength(1);
    });
  }

  it("says the outcome isn't known while the root is unchanged, and shows the new root when core's event comes", async () => {
    const user = userEvent.setup();
    let state: SettingsView = FRESH;
    const { calls } = mockApi([
      { method: "GET", path: "/settings", pure: true, body: () => state },
      { method: "PUT", path: "/settings", refuses: true, body: () => Promise.reject(new TypeError("Failed to fetch")) },
    ]);
    renderApp("/settings?tab=lanca");
    act(() => socket().open());
    await rotate(user);
    const unknown = await screen.findByTestId("lanca-unknown", undefined, T);
    expect(unknown).toHaveTextContent(/answer was lost/);
    expect(unknown).toHaveTextContent(FRESH.lanca.fingerprint);
    expect(screen.queryByTestId("lanca-refusal")).toBeNull();
    expect(screen.queryByTestId("lanca-rotated")).toBeNull();
    // The rotation core was still making lands: its own, not "changed since you started editing".
    state = ROTATING;
    act(() => socket().emit(lancaEvent("rotated")));
    const done = await screen.findByTestId("lanca-rotated", undefined, T);
    expect(done).toHaveTextContent(ROTATING.lanca.fingerprint);
    expect(screen.queryByTestId("lanca-unknown")).toBeNull();
    expect(screen.queryByTestId("lanca-moved")).toBeNull();
    expect(mutations(calls)).toHaveLength(1);
  });

  it("a root that changes to other zones after the outcome was left unknown is another change's", async () => {
    const user = userEvent.setup();
    let state: SettingsView = FRESH;
    mockApi([
      { method: "GET", path: "/settings", pure: true, body: () => state },
      { method: "PUT", path: "/settings", refuses: true, body: () => reply(502, "Bad Gateway") },
    ]);
    renderApp("/settings?tab=lanca");
    act(() => socket().open());
    await rotate(user);
    expect(await screen.findByTestId("lanca-unknown", undefined, T)).toHaveTextContent(/Core still names root/);
    state = { ...ROTATING, lanca: { ...ROTATING.lanca, zones: ["home.arpa", "other.example"] } };
    act(() => socket().emit(lancaEvent("rotated")));
    await waitFor(() => expect(screen.getByTestId("lanca-unknown")).toHaveTextContent(/other zones/), T);
    expect(screen.getByTestId("lanca-unknown")).not.toHaveTextContent(/Core still names root/);
    expect(screen.getByTestId("lanca-moved")).toHaveTextContent(ROTATING.lanca.fingerprint);
    expect(screen.queryByTestId("lanca-rotated")).toBeNull();
  });

  it("an answer lost while the root went to other zones (another change): no 'rotated', the draft against the root core has", async () => {
    const user = userEvent.setup();
    let state: SettingsView = FRESH;
    const other = { ...ROTATING, lanca: { ...ROTATING.lanca, zones: ["home.arpa", "other.example"] } };
    mockApi([
      { method: "GET", path: "/settings", pure: true, body: () => state },
      {
        method: "PUT",
        path: "/settings",
        refuses: true,
        body: () => {
          state = other;
          return reply(502, "Bad Gateway");
        },
      },
    ]);
    renderApp("/settings?tab=lanca");
    await rotate(user);
    const unknown = await screen.findByTestId("lanca-unknown", undefined, T);
    expect(unknown).toHaveTextContent(/other zones/);
    const moved = await screen.findByTestId("lanca-moved", undefined, T);
    expect(moved).toHaveTextContent(ROTATING.lanca.fingerprint);
    expect(screen.queryByTestId("lanca-rotated")).toBeNull();
    await user.click(within(moved).getByRole("button", { name: "Reload" }));
    expect(screen.queryByTestId("lanca-unknown")).toBeNull();
    expect(screen.queryByTestId("lanca-moved")).toBeNull();
  });

  const atOnce: [string, () => unknown][] = [
    ["the connection dropped", () => Promise.reject(new TypeError("Failed to fetch"))],
    ["a 2xx came without the settings view", () => ({})],
  ];
  for (const [what, answer] of atOnce) {
    it(`shows the new root at once from the settings read right after, when ${what}`, async () => {
      const user = userEvent.setup();
      let after = -1;
      const { calls } = mockApi([
        {
          method: "GET",
          path: "/settings",
          refuses: true,
          // The read right after the lost answer has the new root; any later read is held.
          body: () => (after < 0 ? FRESH : after++ === 0 ? ROTATING : new Promise(() => {})),
        },
        {
          method: "PUT",
          path: "/settings",
          refuses: true,
          body: () => {
            after = 0;
            return answer();
          },
        },
      ]);
      renderApp("/settings?tab=lanca");
      const zones = await screen.findByLabelText("Zones", undefined, T);
      await user.type(zones, "Lan.Example.{Enter}");
      await user.click(screen.getByRole("button", { name: /Change zones/ }));
      await user.click(await screen.findByRole("button", { name: "Make a new root" }, T));
      expect(await screen.findByTestId("lanca-rotated", undefined, T)).toHaveTextContent(ROTATING.lanca.fingerprint);
      await waitFor(() => expect(after).toBeGreaterThan(1), T);
      const root = screen.getByText("Current root").closest("[data-slot=card]") as HTMLElement;
      expect(within(root).getByText(ROTATING.lanca.fingerprint)).toBeInTheDocument();
      expect(screen.queryByTestId("lanca-moved")).toBeNull();
      expect(screen.queryByTestId("lanca-unknown")).toBeNull();
      // The draft is the zones as core keeps them.
      expect(within(zones.parentElement!).getByText("lan.example")).toBeInTheDocument();
      expect(within(zones.parentElement!).queryByText("Lan.Example.")).toBeNull();
      expect(mutations(calls)[0].body).toEqual({ lanca: { zones: ["home.arpa", "lan.example"], rotate_from: FRESH.lanca.fingerprint } });
    });
  }

  it("with core's own web certificate file, a lost answer and a new root say nothing about this browser", async () => {
    const user = userEvent.setup();
    let state: SettingsView = withWeb(FRESH, { tls: "file", http_port: 8080 });
    let broken = false;
    mockApi([
      { method: "GET", path: "/settings", refuses: true, body: () => (broken ? Promise.reject(new TypeError("Failed to fetch")) : state) },
      {
        method: "PUT",
        path: "/settings",
        refuses: true,
        body: () => {
          broken = true;
          return Promise.reject(new TypeError("Failed to fetch"));
        },
      },
    ]);
    const app = renderApp("/settings?tab=lanca");
    await rotate(user);
    const unknown = await screen.findByTestId("lanca-unknown", undefined, T);
    expect(unknown).toHaveTextContent(/can't be read/);
    expect(unknown).not.toHaveTextContent(/this browser/);
    app.unmount();
    broken = false;
    mockApi([
      { method: "GET", path: "/settings", pure: true, body: () => state },
      {
        method: "PUT",
        path: "/settings",
        refuses: true,
        body: () => (state = withWeb(ROTATING, { tls: "file", http_port: 8080 })),
      },
    ]);
    renderApp("/settings?tab=lanca");
    await rotate(user);
    const done = await screen.findByTestId("lanca-rotated", undefined, T);
    expect(done).toHaveTextContent(/as soon as its edge re-issues/);
    expect(done).not.toHaveTextContent(/this browser/);
  });

  it("an answer lost and the settings unreadable: says so, and how this browser gets the new root over the plain-HTTP port", async () => {
    const user = userEvent.setup();
    let broken = false;
    const start = withWeb(FRESH, { http_port: 8080 });
    mockApi([
      { method: "GET", path: "/settings", refuses: true, body: () => (broken ? Promise.reject(new TypeError("Failed to fetch")) : start) },
      {
        method: "PUT",
        path: "/settings",
        refuses: true,
        body: () => {
          broken = true;
          return Promise.reject(new TypeError("Failed to fetch"));
        },
      },
    ]);
    const { queryClient } = renderApp("/settings?tab=lanca");
    await rotate(user);
    const unknown = await screen.findByTestId("lanca-unknown", undefined, T);
    expect(unknown).toHaveTextContent(/can't be read/);
    expect(unknown).toHaveTextContent(/this browser/);
    const link = within(unknown).getByRole("link", { name: /plain-HTTP port 8080/ });
    expect(link).toHaveAttribute("href", `http://${window.location.hostname}:8080${FRESH.lanca.download}`);
    expect(screen.queryByTestId("lanca-refusal")).toBeNull();
    // Readable again, still the old root: not made (yet).
    broken = false;
    await act(() => queryClient.invalidateQueries({ queryKey: qk.settings }));
    await waitFor(() => expect(screen.getByTestId("lanca-unknown")).toHaveTextContent(`Core still names root ${FRESH.lanca.fingerprint}`), T);
    expect(screen.getByTestId("lanca-unknown")).not.toHaveTextContent(/can't be read/);
  });

  it("a 200 that kept the root says nothing changed, not 'a new root'", async () => {
    const user = userEvent.setup();
    mockApi([
      { method: "GET", path: "/settings", body: FRESH },
      // Core took the zones as the ones it has (its normal form): same root.
      { method: "PUT", path: "/settings", refuses: true, body: FRESH },
    ]);
    renderApp("/settings?tab=lanca");
    await rotate(user);
    const kept = await screen.findByTestId("lanca-kept", undefined, T);
    expect(kept).toHaveTextContent(FRESH.lanca.fingerprint);
    expect(kept).toHaveTextContent(/Nothing changed/);
    expect(screen.queryByTestId("lanca-rotated")).toBeNull();
    // The draft is the zones as core has them: nothing left to change.
    const zones = screen.getByLabelText("Zones");
    expect(within(zones.parentElement!).queryByText("lan.example")).toBeNull();
    expect(screen.getByRole("button", { name: /Change zones/ })).toBeDisabled();
  });

  it("a 503 is the clock only when core's error code says so (unit)", () => {
    const clock = bodyOf("PUT /settings lanca.zones (clock not synchronised)") as { error: { code: string; message: string } };
    expect(clock.error.code).toBe("unavailable");
    expect(zonesRefusal(new ApiError(503, clock.error.code, clock.error.message)).kind).toBe("clock");
    expect(zonesRefusal(new ApiError(503, "http_503", "Core is busy or unavailable; try again.")).kind).not.toBe("clock");
    expect(answerLost(new ApiError(503, "unavailable", clock.error.message))).toBe(false);
    expect(answerLost(new ApiError(503, "http_503", "x"))).toBe(true);
    expect(answerLost(new ApiError(0, "network", "x"))).toBe(true);
    expect(answerLost(new ApiError(500, "internal", "x"))).toBe(true);
    expect(answerLost(new ApiError(504, "http_504", "x"))).toBe(true);
    expect(answerLost(new ApiError(409, "conflict", "x"))).toBe(false);
    expect(answerLost(new ApiError(422, "invalid", "x"))).toBe(false);
    expect(answerLost(new ApiError(429, "too_many_requests", "x"))).toBe(false);
    expect(answerLost(new Error("x"))).toBe(false);
  });
});

describe("V2: the LAN CA view reads the settings again while core's clock isn't synchronised", () => {
  it("polls while clock_synced is false and stops once it is; the change is offered then", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
      let state: SettingsView = UNSYNCED;
      const { calls } = mockApi([{ method: "GET", path: "/settings", body: () => state }]);
      const { queryClient } = renderApp("/settings?tab=lanca");
      await screen.findByTestId("lanca-clock", undefined, T);
      await user.type(screen.getByLabelText("Zones"), "lan.example{Enter}");
      expect(screen.getByRole("button", { name: /Change zones/ })).toBeDisabled();
      expect(polls(queryClient, qk.settings)).toEqual([CLOCK_POLL_MS]);
      const n = gets(calls, "/settings").length;
      await act(() => vi.advanceTimersByTimeAsync(CLOCK_POLL_MS + 100));
      await waitFor(() => expect(gets(calls, "/settings").length).toBe(n + 1), T);
      expect(screen.getByTestId("lanca-clock")).toBeInTheDocument();
      state = { ...UNSYNCED, lanca: { ...UNSYNCED.lanca, clock_synced: true } };
      await act(() => vi.advanceTimersByTimeAsync(CLOCK_POLL_MS + 100));
      await waitFor(() => expect(screen.queryByTestId("lanca-clock")).toBeNull(), T);
      expect(screen.getByRole("button", { name: /Change zones/ })).toBeEnabled();
      expect(polls(queryClient, qk.settings)).toEqual([]);
      const m = gets(calls, "/settings").length;
      await act(() => vi.advanceTimersByTimeAsync(3 * CLOCK_POLL_MS));
      expect(gets(calls, "/settings").length).toBe(m);
    } finally {
      vi.useRealTimers();
    }
  });

  it("polls only for a view read that says the clock isn't synchronised (unit)", () => {
    expect(clockPoll(UNSYNCED)).toBe(CLOCK_POLL_MS);
    expect(clockPoll(FRESH)).toBe(false);
    // Nothing read yet (or no LAN CA view): no polling of its own.
    expect(clockPoll(undefined)).toBe(false);
    expect(clockPoll({ ...FRESH, lanca: undefined } as unknown as SettingsView)).toBe(false);
  });

  it("doesn't poll a synchronised core's settings", async () => {
    mockApi([{ method: "GET", path: "/settings", body: FRESH }]);
    const { queryClient } = renderApp("/settings?tab=lanca");
    await screen.findByLabelText("Zones", undefined, T);
    expect(intervalsOf(queryClient, qk.settings).length).toBeGreaterThan(0);
    expect(polls(queryClient, qk.settings)).toEqual([]);
  });
});

describe("V3: a dnssec event reads only the results lists it concerns, the newest page alone past one page", () => {
  const row = (id: number, outcome = "bogus") => ({ id, name: `n${id}.example.`, qtype: "A", outcome, group: "default", at: "2026-11-24T00:00:00Z", edges: [], clients: [], groups: [] });
  /** Results newest first, 100 a page; `newest` is the id of the newest; `delay` holds each page back. */
  function results() {
    const s = { newest: 1000, delay: 0 };
    const route = {
      method: "GET",
      path: "/dnssec/results",
      body: async (c: Call) => {
        if (s.delay) await pause(s.delay);
        const top = c.query.get("cursor") ? Number(c.query.get("cursor")) : s.newest + 1;
        const items = Array.from({ length: 100 }, (_, i) => row(top - 1 - i, c.query.get("outcome") ?? "bogus"));
        return { items, next_cursor: String(top - 100) };
      },
    };
    return { s, route };
  }
  async function loadPages(calls: Call[], qc: QueryClient, n: number) {
    const user = userEvent.setup();
    await waitFor(() => expect(gets(calls, "/dnssec/results").length).toBeGreaterThan(0), T);
    await waitFor(() => expect(qc.isFetching()).toBe(0), T);
    for (let i = 1; i < n; i++) {
      await user.click(await screen.findByRole("button", { name: "Load older results" }, T));
      await waitFor(() => expect(qc.isFetching()).toBe(0), T);
    }
  }

  it("reads the newest page alone for a list with three pages loaded, and joins it to them", async () => {
    const { s, route } = results();
    const { calls } = mockApi([route]);
    const { queryClient } = renderApp("/dnssec");
    await loadPages(calls, queryClient, 3);
    expect(screen.getByText("n701.example.")).toBeInTheDocument();
    const n = gets(calls, "/dnssec/results").length;
    s.newest = 1002;
    act(() => applyEvent(queryClient, { type: "dnssec", data: { results: 2, outcomes: { bogus: 2 } } }));
    expect(await screen.findByText("n1002.example.", undefined, T)).toBeInTheDocument();
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    expect(gets(calls, "/dnssec/results").slice(n).map((c) => c.query.get("cursor"))).toEqual([null]);
    // The older pages stay as loaded.
    expect(screen.getByText("n701.example.")).toBeInTheDocument();
  });

  it("reads nothing for outcomes the list doesn't show; every outcome's list reads", async () => {
    const user = userEvent.setup();
    const { route } = results();
    const { calls } = mockApi([route]);
    const { queryClient } = renderApp("/dnssec");
    await loadPages(calls, queryClient, 1);
    const n = gets(calls, "/dnssec/results").length;
    act(() => applyEvent(queryClient, { type: "dnssec", data: { results: 3, outcomes: { secure: 2, insecure: 1 } } }));
    await pause(300);
    expect(gets(calls, "/dnssec/results").length).toBe(n);
    await user.click(screen.getByRole("combobox", { name: "Outcome" }));
    await user.click(await screen.findByRole("option", { name: "Every outcome" }, T));
    await waitFor(() => expect(gets(calls, "/dnssec/results").at(-1)!.query.get("outcome")).toBeNull(), T);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    const m = gets(calls, "/dnssec/results").length;
    act(() => applyEvent(queryClient, { type: "dnssec", data: { results: 1, outcomes: { secure: 1 } } }));
    await waitFor(() => expect(gets(calls, "/dnssec/results").length).toBe(m + 1), T);
  });

  it("under an event a second and slow pages, reads don't cancel each other: the list updates during the burst, throttled", async () => {
    const { s, route } = results();
    const { calls } = mockApi([route]);
    const { queryClient } = renderApp("/dnssec");
    await loadPages(calls, queryClient, 3);
    s.delay = 150;
    const n = gets(calls, "/dnssec/results").length;
    const t0 = Date.now();
    for (let i = 0; i < 8; i++) {
      s.newest++;
      act(() => applyEvent(queryClient, { type: "dnssec", data: { results: 1, outcomes: { bogus: 1 } } }));
      await pause(400);
    }
    // Seen while the events still come (3.2 s of them).
    expect(screen.getAllByText(/^n100[4-8]\.example\.$/).length).toBeGreaterThan(0);
    const reads = gets(calls, "/dnssec/results").length - n;
    expect(reads).toBeGreaterThanOrEqual(2);
    // One read per gap at most (3.2 s of events: 2 reads, or more should the host stall).
    expect(reads).toBeLessThanOrEqual(Math.ceil((Date.now() - t0) / PAGED_EVENT_GAP_MS) + 1);
    // The last event's results show once the throttle lets the trailing read through.
    expect(await screen.findByText("n1008.example.", undefined, T)).toBeInTheDocument();
  }, 30_000);

  it("an event while older results are loading waits for them, and doesn't cancel the load", async () => {
    const user = userEvent.setup();
    const { s, route } = results();
    let release: (() => void) | null = null;
    const held = {
      ...route,
      body: async (c: Call) => {
        if (c.query.get("cursor")) await new Promise<void>((ok) => (release = ok));
        return route.body(c);
      },
    };
    const { calls } = mockApi([held]);
    const { queryClient } = renderApp("/dnssec");
    await loadPages(calls, queryClient, 1);
    await user.click(screen.getByRole("button", { name: "Load older results" }));
    await waitFor(() => expect(release).not.toBeNull(), T);
    s.newest = 1001;
    act(() => applyEvent(queryClient, { type: "dnssec", data: { results: 1, outcomes: { bogus: 1 } } }));
    await pause(100);
    act(() => release!());
    expect(await screen.findByText("n801.example.", undefined, T)).toBeInTheDocument();
    expect(await screen.findByText("n1001.example.", undefined, T)).toBeInTheDocument();
    expect(screen.getByText("n801.example.")).toBeInTheDocument();
  });

  it("a newest-page read dropped because the list changed meanwhile is made again", async () => {
    const user = userEvent.setup();
    const { s, route } = results();
    let hold = false;
    let release: (() => void) | null = null;
    const held = {
      ...route,
      body: async (c: Call) => {
        if (hold && !c.query.get("cursor")) {
          hold = false;
          await new Promise<void>((ok) => (release = ok));
        }
        return route.body(c);
      },
    };
    const { calls } = mockApi([held]);
    const { queryClient } = renderApp("/dnssec");
    await loadPages(calls, queryClient, 2);
    hold = true;
    s.newest = 1001;
    act(() => applyEvent(queryClient, { type: "dnssec", data: { results: 1, outcomes: { bogus: 1 } } }));
    await waitFor(() => expect(release).not.toBeNull(), T);
    // A third page lands while the newest page is out: that read no longer fits the list.
    await user.click(screen.getByRole("button", { name: "Load older results" }));
    expect(await screen.findByText("n701.example.", undefined, T)).toBeInTheDocument();
    act(() => release!());
    expect(await screen.findByText("n1001.example.", undefined, T)).toBeInTheDocument();
    expect(screen.getByText("n701.example.")).toBeInTheDocument();
  });

  it("events while a read is due add none: one read per gap, then quiet", async () => {
    const { s, route } = results();
    const { calls } = mockApi([route]);
    const { queryClient } = renderApp("/dnssec");
    await loadPages(calls, queryClient, 3);
    const n = gets(calls, "/dnssec/results").length;
    const reads = () => gets(calls, "/dnssec/results").length - n;
    const event = () => {
      s.newest++;
      act(() => applyEvent(queryClient, { type: "dnssec", data: { results: 1, outcomes: { bogus: 1 } } }));
    };
    // The throttle's clock stands still (its timers stay real): every later event falls within the
    // first read's gap, however slowly a loaded host renders that read.
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      event();
      await screen.findByText("n1001.example.", undefined, T);
      expect(reads()).toBe(1);
      for (let i = 0; i < 3; i++) {
        event();
        await pause(50);
      }
      expect(await screen.findByText("n1004.example.", undefined, { timeout: PAGED_EVENT_GAP_MS + T.timeout })).toBeInTheDocument();
      expect(reads()).toBe(2);
      await pause(PAGED_EVENT_GAP_MS + 500);
      expect(reads()).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  }, 30_000);

  it("a list with one page loaded reads it again whole: rows pushed past the page leave", async () => {
    const { s, route } = results();
    const { calls } = mockApi([route]);
    const { queryClient } = renderApp("/dnssec");
    await loadPages(calls, queryClient, 1);
    expect(screen.getByText("n901.example.")).toBeInTheDocument();
    s.newest = 1002;
    act(() => applyEvent(queryClient, { type: "dnssec", data: { results: 2, outcomes: { bogus: 2 } } }));
    expect(await screen.findByText("n1002.example.", undefined, T)).toBeInTheDocument();
    expect(screen.queryByText("n901.example.")).toBeNull();
    expect(within(screen.getByRole("list", { name: "DNSSEC results" })).getAllByRole("listitem")).toHaveLength(100);
  });

  it("knows which lists an event concerns (unit)", () => {
    const ev = { results: 3, outcomes: { bogus: 1, secure: 2 } };
    expect(dnssecResultsChanged([...qk.dnssecResults, "all"], ev)).toBe(true);
    expect(dnssecResultsChanged([...qk.dnssecResults, "bogus"], ev)).toBe(true);
    expect(dnssecResultsChanged([...qk.dnssecResults, "secure"], ev)).toBe(true);
    expect(dnssecResultsChanged([...qk.dnssecResults, "insecure"], ev)).toBe(false);
    expect(dnssecResultsChanged([...qk.dnssecResults, "indeterminate"], { results: 1, outcomes: { indeterminate: 0 } })).toBe(false);
    // Data it can't read: every list.
    expect(dnssecResultsChanged([...qk.dnssecResults, "insecure"], {})).toBe(true);
    expect(dnssecResultsChanged([...qk.dnssecResults, "insecure"], { outcomes: null as unknown as Record<string, number> })).toBe(true);
    const qc = new QueryClient();
    const keys = [[...qk.dnssecResults, "all"], [...qk.dnssecResults, "bogus"], [...qk.dnssecResults, "secure"], qk.dnssecQueue];
    for (const k of keys) qc.setQueryData(k, { pages: [], pageParams: [] });
    applyEvent(qc, { type: "dnssec", data: { results: 1, outcomes: { secure: 1 } } });
    const stale = keys.filter((k) => qc.getQueryCache().find({ queryKey: k, exact: true })?.state.isInvalidated).map((k) => k.join("/"));
    expect(stale).toEqual(["dnssec-results/all", "dnssec-results/secure", "dnssec-queue"]);
  });
});

describe("V4: an open evidence copy stays with its record when newer copies come first", () => {
  it("keeps the selected record open, and its reply's wire, when a newer copy shifts the rows", async () => {
    const user = userEvent.setup();
    const saved = captureDownloads();
    const detail = W5["/alerts/{paged}"] as { alert: { id: number } };
    const id = detail.alert.id;
    const shape = W5["/alerts/{paged}/evidence?limit=2"] as EvidenceView;
    const selected = { ...shape.items[0], qname: "selected.malware.example", edge: "edge/one", seq: 500, response: "AQ==" };
    const newer = { ...selected, qname: "newer.malware.example", seq: 501, id: `${selected.id}-501`, response: "Ag==" };
    let page: EvidenceView = { ...shape, items: [selected], total: 1, next_cursor: null };
    mockApi([
      { method: "GET", path: `/alerts/${id}`, body: detail },
      { method: "GET", path: `/alerts/${id}/evidence`, body: () => page },
    ]);
    const app = renderApp(`/alerts/${id}`);
    const table = await screen.findByRole("table", { name: "Evidence copies" }, T);
    await user.click(within(table).getByText(selected.qname));
    await screen.findByRole("button", { name: "Download the reply's wire" }, T);
    page = { ...page, items: [newer, selected], total: 2 };
    await act(() => app.queryClient.invalidateQueries({ queryKey: qk.alertEvidence(id) }));
    await waitFor(() => expect(within(table).getAllByRole("row")).toHaveLength(4), T);
    const rows = within(table).getAllByRole("row");
    // Header, newer, selected, then the selected one's detail.
    expect(rows[1]).toHaveTextContent(newer.qname);
    expect(rows[2]).toHaveTextContent(selected.qname);
    expect(rows[3]).toHaveTextContent(/"seq": 500/);
    expect(rows[3]).not.toHaveTextContent(/"seq": 501/);
    await user.click(within(rows[3]).getByRole("button", { name: "Download the reply's wire" }));
    expect(saved).toHaveLength(1);
    expect(new Uint8Array(await saved[0].blob.arrayBuffer())).toEqual(new Uint8Array([1]));
    expect(saved[0].name).toBe(`alert-${id}-reply-edge_one-500.bin`);
    // Its row closes it; the newer one opens its own.
    await user.click(within(table).getByText(selected.qname));
    expect(within(table).getAllByRole("row")).toHaveLength(3);
    await user.click(within(table).getByText(newer.qname));
    const open = within(table).getAllByRole("row");
    expect(open[2]).toHaveTextContent(/"seq": 501/);
    expect(open[3]).toHaveTextContent(selected.qname);
  });

  it("names copies by core's record (edge, boot, seq), each once (unit)", () => {
    const shape = (W5["/alerts/{paged}/evidence"] as EvidenceView).items;
    const keys = copyKeys(shape);
    expect(new Set(keys).size).toBe(shape.length);
    expect(copyKeys([shape[1], shape[0]])).toEqual([keys[1], keys[0]]);
    // A record twice (never from core: its copies are unique per record) still gets two keys.
    expect(new Set(copyKeys([shape[0], shape[0]])).size).toBe(2);
  });
});

describe("V5: a whole-evidence download checks it read one run of copies", () => {
  const shape = W5["/alerts/{paged}/evidence?limit=2"] as EvidenceView;
  const copy = (seq: number) => ({ ...shape.items[0], seq, id: `r-${seq}` });
  const later = shape.next_cursor!;

  it("retries a bounded number of times when the pages' total and copies differ, then says so", async () => {
    const first = { ...shape, items: Array.from({ length: 500 }, (_, i) => copy(1000 - i)), total: 501, next_cursor: later };
    const { calls } = mockApi([
      { method: "GET", path: "/alerts/123/evidence", body: (c: Call) => (c.query.has("cursor") ? { ...shape, items: [copy(500)], next_cursor: null, total: 502 } : first) },
    ]);
    const got = await fetchAllEvidence(123);
    expect(got.consistent).toBe(false);
    expect(got.evidence.items).toHaveLength(501);
    expect(got.evidence.total).toBe(502);
    expect(gets(calls, "/alerts/123/evidence").length).toBeLessThanOrEqual(9);
  });

  it("a read that copies came into is read again, and the next consistent read is the download", async () => {
    let arrivals = 1;
    const head = () => [copy(2000 + arrivals), ...Array.from({ length: 499 }, (_, i) => copy(1000 - i))];
    mockApi([
      {
        method: "GET",
        path: "/alerts/123/evidence",
        body: (c: Call) => {
          if (c.query.has("cursor")) {
            const v = { ...shape, items: [copy(400)], next_cursor: null, total: 501 };
            // One more copy stored while the first read paged: the head moved.
            if (arrivals === 1) arrivals = 2;
            return v;
          }
          return { ...shape, items: head().slice(0, Number(c.query.get("limit") ?? 100)), total: 501, next_cursor: later };
        },
      },
    ]);
    const got = await fetchAllEvidence(123);
    expect(got.consistent).toBe(true);
    expect(got.evidence.items[0].seq).toBe(2002);
    expect(got.evidence.items).toHaveLength(501);
  });

  it("a run is one count: pages agreeing on a total they don't hold, or a head whose total moved, are read again", async () => {
    // Totals agree, a copy is missing (core never answers so, but a copy it couldn't parse).
    mockApi([
      { method: "GET", path: "/alerts/123/evidence", body: (c: Call) => (c.query.has("cursor") ? { ...shape, items: [], next_cursor: null, total: 3 } : { ...shape, items: [copy(9), copy(8)], total: 3, next_cursor: later }) },
    ]);
    expect((await fetchAllEvidence(123)).consistent).toBe(false);
    // Every page agrees, but the newest copy's total moved by the end.
    const { calls } = mockApi([
      {
        method: "GET",
        path: "/alerts/124/evidence",
        body: (c: Call) => (c.query.has("cursor") ? { ...shape, items: [copy(7)], next_cursor: null, total: 3 } : { ...shape, items: [copy(9), copy(8)], total: c.query.get("limit") === "1" ? 4 : 3, next_cursor: later }),
      },
    ]);
    expect((await fetchAllEvidence(124)).consistent).toBe(false);
    expect(gets(calls, "/alerts/124/evidence").filter((c) => c.query.get("limit") === "1")).toHaveLength(3);
  });

  it("one page is one snapshot: read once, nothing more", async () => {
    const { calls } = mockApi([{ method: "GET", path: "/alerts/125/evidence", body: { ...shape, items: [copy(9), copy(8)], total: 2, next_cursor: null } }]);
    const got = await fetchAllEvidence(125);
    expect(got.consistent).toBe(true);
    expect(gets(calls, "/alerts/125/evidence").map((c) => c.query.get("limit"))).toEqual(["500"]);
  });

  it("saves what it read and warns when the evidence kept changing", async () => {
    const user = userEvent.setup();
    const saved = captureDownloads();
    const detail = W5["/alerts/{paged}"] as { alert: { id: number } };
    const id = detail.alert.id;
    const first = { ...shape, items: [copy(9), copy(8)], total: 3, next_cursor: later };
    mockApi([
      { method: "GET", path: `/alerts/${id}`, body: detail },
      { method: "GET", path: `/alerts/${id}/evidence`, body: (c: Call) => (c.query.has("cursor") ? { ...shape, items: [copy(7)], next_cursor: null, total: 4 } : first) },
    ]);
    renderApp(`/alerts/${id}`);
    await screen.findByTestId("evidence-copies", undefined, T);
    await user.click(screen.getByRole("button", { name: "Download evidence" }));
    await waitFor(() => expect(saved).toHaveLength(1), T);
    expect(await screen.findByText(/changed while it downloaded/, undefined, T)).toHaveTextContent("3 of 4 copies");
  });
});

describe("V6: what a rotation does to this browser and the devices", () => {
  it("says this browser loses the page on its next connection, and that devices fail as soon as their edge re-issues", () => {
    const steps = rotationSteps(FRESH.settings.web).join(" ");
    expect(FRESH.settings.web?.tls).toBe("managed");
    expect(steps).toMatch(/this browser/);
    expect(steps).toMatch(/next connection/);
    expect(steps).toMatch(/as soon as/);
    expect(steps).not.toMatch(/until then/i);
    expect(rotationSteps(withWeb(FRESH, { http_port: 8080 }).settings.web).join(" ")).toMatch(/plain-HTTP port 8080/);
    expect(rotationSteps(FRESH.settings.web).join(" ")).not.toMatch(/plain-HTTP/);
    // Core's web certificate from a file, or plain HTTP: this page isn't affected.
    expect(rotationSteps(withWeb(FRESH, { tls: "file" }).settings.web).join(" ")).not.toMatch(/this browser loses/);
    expect(rotationSteps(withWeb(FRESH, { tls: "off" }).settings.web).join(" ")).not.toMatch(/this browser loses/);
    // Left out, web.tls is managed (core's default).
    expect(rotationSteps(undefined).join(" ")).toMatch(/this browser loses this page on its next connection/);
    expect(rotationSteps({ http_port: null }).join(" ")).toMatch(/this browser loses/);
  });

  it("the confirmation and the warning list the steps for core's own web settings", async () => {
    const user = userEvent.setup();
    const start = withWeb(FRESH, { http_port: 8080 });
    mockApi([{ method: "GET", path: "/settings", body: start }]);
    renderApp("/settings?tab=lanca");
    const warning = await screen.findByRole("list", { name: "What a zones change does" }, T);
    for (const t of rotationSteps(start.settings.web)) expect(within(warning).getByText(t)).toBeInTheDocument();
    await user.type(screen.getByLabelText("Zones"), "lan.example{Enter}");
    await user.click(screen.getByRole("button", { name: /Change zones/ }));
    const dialog = await screen.findByRole("alertdialog", undefined, T);
    expect(dialog).toHaveTextContent(/this browser loses this page on its next connection/);
  });

  it("the done alert says to install the root on this browser now, with the plain-HTTP link when set", async () => {
    const user = userEvent.setup();
    let state: SettingsView = withWeb(FRESH, { http_port: 8080 });
    mockApi([
      { method: "GET", path: "/settings", pure: true, body: () => state },
      {
        method: "PUT",
        path: "/settings",
        refuses: true,
        body: () => {
          state = withWeb(ROTATING, { http_port: 8080 });
          return state;
        },
      },
    ]);
    renderApp("/settings?tab=lanca");
    await rotate(user);
    const done = await screen.findByTestId("lanca-rotated", undefined, T);
    expect(done).toHaveTextContent(/trust it on every device/);
    expect(done).toHaveTextContent(/this browser now/);
    expect(done).toHaveTextContent(/as soon as its edge re-issues/);
    expect(within(done).getByRole("link", { name: /plain-HTTP port 8080/ })).toHaveAttribute("href", `http://${window.location.hostname}:8080${ROTATING.lanca.download}`);
  });
});

describe("V7: 'several edges' for every kind raised from records; allows' states as of the edges' reports", () => {
  const paged = (W5["/alerts/{paged}"] as { alert: Alert }).alert;
  it("says 'several edges' for dnssec_bogus, upstream_disagrees and category_answered alerts that name none (unit)", () => {
    const of = (kind: string, details: Rec, edge: string | null = null) => ({ ...paged, kind, edge, details });
    expect(seenOnSeveralEdges(of("dnssec_bogus", { zone: "example.", edges: ["e1", "e2"] }))).toBe(true);
    expect(seenOnSeveralEdges(of("upstream_disagrees", { name: "x.example.", edges: ["e2"] }))).toBe(true);
    expect(seenOnSeveralEdges(of("category_answered", { source: "feed", edge: "e1" }))).toBe(true);
    // A lookup provider's category_answered names no edge in its details; every raise has one.
    expect(seenOnSeveralEdges(of("category_answered", { by: "provider", provider: "q9" }))).toBe(true);
    // No record's edge at all: not several.
    expect(seenOnSeveralEdges(of("dnssec_bogus", { zone: "example.", edges: [] }))).toBe(false);
    expect(seenOnSeveralEdges(of("upstream_disagrees", { edges: "e1" }))).toBe(false);
    expect(seenOnSeveralEdges(of("dnssec_bogus", { zone: "example.", edges: ["e1", "e2"] }, "e1"))).toBe(false);
    expect(seenOnSeveralEdges(of("edge_offline", { edges: ["e1", "e2"] }))).toBe(false);
    // Kinds are core's strings, not the table's own properties.
    expect(seenOnSeveralEdges(of("toString", { edge: "e1" }))).toBe(false);
    expect(seenOnSeveralEdges(of("constructor", { edge: "e1" }))).toBe(false);
  });

  it("the device and profile views say an allow's state is as of the edge's last report", async () => {
    mockApi([{ method: "GET", path: "/query-summary", body: (c: Call) => W5[c.query.get("profile") ? "/query-summary?profile=p1 (revoked)" : "/query-summary?device=tablet (revoked)"] }]);
    const app = renderApp("/clients/profile/p1");
    const allows = await screen.findByRole("list", { name: "Temporary allows" }, T);
    const card = allows.closest("[data-slot=card]") as HTMLElement;
    expect(card).toHaveTextContent(/as of each edge's last report/);
    expect(within(card).getByRole("link", { name: "Temporary allows" })).toHaveAttribute("href", "/temporary-allows");
    app.unmount();
    renderApp("/clients/device?key=tablet");
    const own = await screen.findByRole("list", { name: "Temporary allows" }, T);
    expect(own.closest("[data-slot=card]")).toHaveTextContent(/as of each edge's last report/);
  });
});
