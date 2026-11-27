// The last final check of the UI on wave 5 (dev/briefs/fix-final2-ui.md): a paged list past its
// first page still shows new rows (G1), and a restore or reconnect replaces reads still in flight,
// first reads included (G2).
import { describe, expect, it, vi } from "vitest";
import type * as React from "react";
import { act, renderHook, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { focusManager, QueryClient, QueryClientProvider, QueryObserver, type InfiniteData } from "@tanstack/react-query";
import { mockApi, reply, type Call } from "@/test/mock-api";
import { renderApp } from "@/test/render";
import { W5 } from "@/test/core-w5";
import { applyEvent, invalidateAll, resync } from "@/api/events";
import { downloadCap, qk, usePagedList, withHead } from "@/api/queries";
import { DEFAULT_DOWNLOAD_MIB } from "@/lib/import-file";

const T = { timeout: 8000 };
type Rec = Record<string, unknown>;
const gets = (calls: Call[], path: string) => calls.filter((c) => c.method === "GET" && c.path === path);
const coreError = (status: number, code: string, message: string) => reply(status, { error: { code, message } });
const file = (content: string, name = "picket-config-2026-11-24.json") => new File([content], name, { type: "application/json" });

/** A response the test holds back and sends when it chooses. */
function held<V>() {
  let send!: (v: V) => void;
  const promise = new Promise<V>((resolve) => {
    send = resolve;
  });
  return { promise, send };
}

/** The window losing and regaining focus. */
function refocus() {
  act(() => {
    focusManager.setFocused(false);
    focusManager.setFocused(true);
  });
  focusManager.setFocused(undefined);
}

// ---------------------------------------------------------------------------------------------
// G1

type P = { items: { id: string }[]; next_cursor: string | null };
const page = (ids: string[], next: string | null): P => ({ items: ids.map((id) => ({ id })), next_cursor: next });
const data = (...pages: P[]): InfiniteData<P, string | undefined> => ({ pages, pageParams: pages.map((_, i) => (i === 0 ? undefined : `c${i}`)) });
const rows = (d: InfiniteData<P, string | undefined>) => d.pages.flatMap((p) => p.items.map((r) => r.id));
const byId = (r: { id: string }) => r.id;

describe("G1: joining a fresh first page to the loaded pages (withHead)", () => {
  it("puts new rows first and keeps the rows they pushed out of the first page, then the older pages", () => {
    const d = withHead(data(page(["5", "4", "3"], "c1"), page(["2", "1"], "c2")), page(["7", "6", "5"], "x"), byId);
    expect(rows(d)).toEqual(["7", "6", "5", "4", "3", "2", "1"]);
    // The first page continues where the loaded first page did; the next pages stay as loaded.
    expect(d.pages.map((p) => p.next_cursor)).toEqual(["c1", "c2"]);
    expect(d.pageParams).toEqual([undefined, "c1"]);
  });

  it("drops a row the fresh page no longer has above its last row, and keeps changes to the rows it has", () => {
    const d = withHead(
      data(page(["5", "4", "3"], "c1"), page(["2", "1"], null)),
      { items: [{ id: "6" }, { id: "5", state: "x" } as never, { id: "3" }], next_cursor: "x" },
      byId,
    );
    expect(rows(d)).toEqual(["6", "5", "3", "2", "1"]);
    expect(d.pages[0].items[1]).toEqual({ id: "5", state: "x" });
  });

  it("joins at the last shared row in an older page: rows that left the list there are dropped, none twice", () => {
    // 5, 4 and 3 left the list (e.g. allows that ended); the fresh page reaches into page 2.
    const d = withHead(data(page(["5", "4", "3"], "c1"), page(["2", "1", "0"], "c2"), page(["-1"], null)), page(["6", "2", "1"], "x"), byId);
    expect(rows(d)).toEqual(["6", "2", "1", "0", "-1"]);
    expect(d.pages).toHaveLength(2);
    expect(d.pages[0].next_cursor).toBe("c2");
    expect(d.pageParams).toEqual([undefined, "c2"]);
    // Joined in the last page with rows after the shared one: Load more goes on after those.
    const e = withHead(data(page(["4", "3"], "c1"), page(["2", "1"], "c2")), page(["5", "4", "2"], "after-2"), byId);
    expect(rows(e)).toEqual(["5", "4", "2", "1"]);
    expect(e.pages.map((p) => p.next_cursor)).toEqual(["c2"]);
  });

  it("goes on from the fresh page's cursor when it reaches the last loaded row (Load more reads nothing twice)", () => {
    const d = withHead(data(page(["4", "3"], "c1"), page(["2"], null)), page(["5", "4", "2"], "after-2"), byId);
    expect(rows(d)).toEqual(["5", "4", "2"]);
    expect(d.pages).toHaveLength(1);
    expect(d.pages[0].next_cursor).toBe("after-2");
  });

  it("takes a fresh page with nothing after it as the whole list", () => {
    const d = withHead(data(page(["4", "3"], "c1"), page(["2", "1"], null)), page(["5", "3"], null), byId);
    expect(rows(d)).toEqual(["5", "3"]);
    expect(d.pages[0].next_cursor).toBeNull();
  });

  it("starts again from a fresh page that shares no row with the loaded ones (more new rows than a page)", () => {
    const d = withHead(data(page(["4", "3"], "c1"), page(["2", "1"], null)), page(["9", "8"], "after-8"), byId);
    expect(rows(d)).toEqual(["9", "8"]);
    expect(d.pages[0].next_cursor).toBe("after-8");
    expect(d.pageParams).toEqual([undefined]);
  });
});

describe("G1: a paged list past its first page still shows new rows, reading only its first page", () => {
  const allow = (W5["/temp-allows?state=active"] as { items: Rec[] }).items[0];
  const cursor = (W5["/temp-allows?limit=1"] as { next_cursor: string }).next_cursor;
  const second = { ...allow, allow_id: "a-9", target: "second.example", created_at: "2026-11-24T01:00:00.000000Z" };
  const added = { ...allow, allow_id: "a-10", target: "new.example", created_at: "2026-11-24T02:30:00.000000Z" };

  /** Temporary allows: two pages of active ones; `state.first` decides the first page. */
  function allowsCore(state: { first: () => unknown }) {
    return mockApi([
      {
        method: "GET",
        path: "/temp-allows",
        body: (c: Call) => (c.query.get("state") === "recent" ? { items: [], next_cursor: null } : c.query.get("cursor") ? { items: [second], next_cursor: null } : state.first()),
      },
    ]);
  }
  const active = (calls: Call[]) => gets(calls, "/temp-allows").filter((c) => c.query.get("state") === "active");

  it("polls the first page of temporary allows with two pages loaded: a new allow from the extension shows, the older page stays", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
      let withNew = false;
      const { calls } = allowsCore({ first: () => ({ items: withNew ? [added, allow] : [allow], next_cursor: cursor }) });
      const { queryClient } = renderApp("/temporary-allows");
      const table = await screen.findByRole("table", { name: "Active temporary allows" }, T);
      await within(table).findByText("ads.example", undefined, T);
      await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
      // One page: TanStack's poll reads it, once.
      let n = active(calls).length;
      await act(() => vi.advanceTimersByTimeAsync(61_000));
      await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
      expect(active(calls).slice(n).map((c) => c.query.get("cursor"))).toEqual([null]);
      await user.click(screen.getAllByRole("button", { name: "Load more" })[0]);
      expect(await within(table).findByText("second.example", undefined, T)).toBeInTheDocument();
      // Out of view, nothing is polled.
      n = active(calls).length;
      act(() => focusManager.setFocused(false));
      await act(() => vi.advanceTimersByTimeAsync(61_000));
      expect(active(calls)).toHaveLength(n);
      // Back in view with stale rows: the focus reads the first page.
      act(() => focusManager.setFocused(undefined));
      await waitFor(() => expect(active(calls).slice(n).map((c) => c.query.get("cursor"))).toEqual([null]), T);
      await act(() => vi.advanceTimersByTimeAsync(50));
      n = active(calls).length;
      withNew = true;
      await act(() => vi.advanceTimersByTimeAsync(61_000));
      expect(await within(table).findByText("new.example", undefined, T)).toBeInTheDocument();
      expect(within(table).getByText("ads.example")).toBeInTheDocument();
      expect(within(table).getByText("second.example")).toBeInTheDocument();
      // One request per poll: the first page.
      expect(active(calls).slice(n).map((c) => c.query.get("cursor"))).toEqual([null]);
      expect(within(table).getAllByRole("row")).toHaveLength(4);
    } finally {
      vi.useRealTimers();
    }
  });

  it("refreshes the first page on focus with two pages loaded (when stale), not every page", async () => {
    const user = userEvent.setup();
    let withNew = false;
    const { calls } = allowsCore({ first: () => ({ items: withNew ? [added, allow] : [allow], next_cursor: cursor }) });
    const { queryClient } = renderApp("/temporary-allows");
    const table = await screen.findByRole("table", { name: "Active temporary allows" }, T);
    await within(table).findByText("ads.example", undefined, T);
    await user.click(screen.getAllByRole("button", { name: "Load more" })[0]);
    await within(table).findByText("second.example", undefined, T);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    // Fresh: the focus reads nothing.
    let n = active(calls).length;
    refocus();
    await new Promise((r) => setTimeout(r, 200));
    expect(active(calls)).toHaveLength(n);
    // Stale: leaving reads nothing, coming back reads the first page only.
    act(() => void queryClient.invalidateQueries({ queryKey: qk.tempAllows, refetchType: "none" }));
    withNew = true;
    n = active(calls).length;
    act(() => focusManager.setFocused(false));
    await new Promise((r) => setTimeout(r, 200));
    expect(active(calls)).toHaveLength(n);
    act(() => focusManager.setFocused(true));
    focusManager.setFocused(undefined);
    expect(await within(table).findByText("new.example", undefined, T)).toBeInTheDocument();
    expect(within(table).getByText("second.example")).toBeInTheDocument();
    expect(active(calls).slice(n).map((c) => c.query.get("cursor"))).toEqual([null]);
  });

  it("drops a first-page read that a refetch overtook: an allow that ended doesn't come back", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
      let hold: ReturnType<typeof held<unknown>> | null = null;
      let ended = false;
      const now = () => ({ items: ended ? [added] : [added, allow], next_cursor: cursor });
      const { calls } = allowsCore({
        first: () => {
          if (!hold) return now();
          const h = hold;
          hold = null;
          return h.promise;
        },
      });
      const { queryClient } = renderApp("/temporary-allows");
      const table = await screen.findByRole("table", { name: "Active temporary allows" }, T);
      await within(table).findByText("ads.example", undefined, T);
      await user.click(screen.getAllByRole("button", { name: "Load more" })[0]);
      await within(table).findByText("second.example", undefined, T);
      const late = held<unknown>();
      hold = late;
      const n = active(calls).length;
      await act(() => vi.advanceTimersByTimeAsync(61_000));
      await waitFor(() => expect(active(calls).length).toBe(n + 1), T);
      // The allow ends; an event reads every loaded page again while the poll's read is out.
      ended = true;
      act(() => void queryClient.invalidateQueries({ queryKey: qk.tempAllows }));
      await waitFor(() => expect(within(table).queryByText("ads.example")).toBeNull(), T);
      await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
      // The poll's read, sent before the allow ended, arrives last.
      await act(async () => late.send({ items: [added, allow], next_cursor: cursor }));
      await act(() => vi.advanceTimersByTimeAsync(100));
      expect(within(table).queryByText("ads.example")).toBeNull();
      expect(within(table).getByText("new.example")).toBeInTheDocument();
      expect(within(table).getByText("second.example")).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it("sends no first-page read while Load more is out, and drops one that Load more overtakes (its pages replace the data)", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
      const coreCursor = (s: string) => btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      const c2 = coreCursor("2026-11-24T01:00:00.000000Z\u001fe-9dc7487d\u001fa-9");
      const c3 = coreCursor("2026-11-24T00:30:00.000000Z\u001fe-9dc7487d\u001fa-8");
      const third = { ...allow, allow_id: "a-8", target: "third.example", created_at: "2026-11-24T00:30:00.000000Z" };
      const fourth = { ...allow, allow_id: "a-7", target: "fourth.example", created_at: "2026-11-24T00:10:00.000000Z" };
      let withNew = false;
      const holds: Record<string, ReturnType<typeof held<unknown>> | undefined> = {};
      const answer = (key: string, value: unknown) => {
        const h = holds[key];
        holds[key] = undefined;
        return h ? h.promise.then(() => value) : value;
      };
      const { calls } = mockApi([
        {
          method: "GET",
          path: "/temp-allows",
          body: (c: Call) => {
            if (c.query.get("state") === "recent") return { items: [], next_cursor: null };
            const at = c.query.get("cursor");
            if (at === cursor) return { items: [second], next_cursor: c2 };
            if (at === c2) return answer("third", { items: [third], next_cursor: c3 });
            if (at === c3) return answer("fourth", { items: [fourth], next_cursor: null });
            return answer("first", { items: withNew ? [added, allow] : [allow], next_cursor: cursor });
          },
        },
      ]);
      const { queryClient } = renderApp("/temporary-allows");
      const table = await screen.findByRole("table", { name: "Active temporary allows" }, T);
      await within(table).findByText("ads.example", undefined, T);
      // Only the active allows have more pages.
      const loadMore = () => user.click(screen.getByRole("button", { name: "Load more" }));
      await loadMore();
      await within(table).findByText("second.example", undefined, T);
      await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
      // The poll's read is out when Load more starts; it arrives first.
      const first = held<unknown>();
      const page3 = held<unknown>();
      holds.first = first;
      holds.third = page3;
      withNew = true;
      let n = active(calls).length;
      await act(() => vi.advanceTimersByTimeAsync(61_000));
      await waitFor(() => expect(active(calls).length).toBe(n + 1), T);
      // Coming back to the page while it's out sends no second one.
      refocus();
      expect(active(calls)).toHaveLength(n + 1);
      await loadMore();
      await act(async () => first.send(null));
      await act(() => vi.advanceTimersByTimeAsync(100));
      expect(within(table).queryByText("new.example")).toBeNull();
      await act(async () => page3.send(null));
      expect(await within(table).findByText("third.example", undefined, T)).toBeInTheDocument();
      expect(within(table).queryByText("new.example")).toBeNull();
      // Load more is out when the poll comes: no first-page read.
      const page4 = held<unknown>();
      holds.fourth = page4;
      await loadMore();
      n = active(calls).length;
      await act(() => vi.advanceTimersByTimeAsync(61_000));
      expect(active(calls)).toHaveLength(n);
      await act(async () => page4.send(null));
      expect(await within(table).findByText("fourth.example", undefined, T)).toBeInTheDocument();
      // The next poll reads the first page and shows the new allow above the four loaded.
      await act(() => vi.advanceTimersByTimeAsync(61_000));
      expect(await within(table).findByText("new.example", undefined, T)).toBeInTheDocument();
      expect(within(table).getAllByRole("row").slice(1).map((r) => (r as HTMLTableRowElement).cells[0].querySelector(".font-mono")?.textContent)).toEqual(["new.example", "ads.example", "second.example", "third.example", "fourth.example"]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("shows a failed first-page refresh above the loaded rows, until a refresh succeeds", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
      let fail = false;
      const c2 = btoa("2026-11-24T01:00:00.000000Z\u001fe-9dc7487d\u001fa-9").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      mockApi([
        {
          method: "GET",
          path: "/temp-allows",
          refuses: true,
          body: (c: Call) => {
            if (c.query.get("state") === "recent") return { items: [], next_cursor: null };
            if (c.query.get("cursor") === c2) return coreError(503, "unavailable", "the page is gone");
            if (c.query.get("cursor")) return { items: [second], next_cursor: c2 };
            return fail ? coreError(503, "unavailable", "core is busy") : { items: [allow], next_cursor: cursor };
          },
        },
      ]);
      renderApp("/temporary-allows");
      const table = await screen.findByRole("table", { name: "Active temporary allows" }, T);
      await within(table).findByText("ads.example", undefined, T);
      await user.click(screen.getByRole("button", { name: "Load more" }));
      await within(table).findByText("second.example", undefined, T);
      fail = true;
      await act(() => vi.advanceTimersByTimeAsync(61_000));
      expect(await screen.findByTestId("refetch-error", undefined, T)).toHaveTextContent("core is busy");
      expect(within(table).getByText("ads.example")).toBeInTheDocument();
      expect(within(table).getByText("second.example")).toBeInTheDocument();
      // A failed Load more says its own error, with Retry for that page.
      await user.click(screen.getByRole("button", { name: "Load more" }));
      expect(await screen.findByTestId("next-page-error", undefined, T)).toHaveTextContent("the page is gone");
      expect(screen.getByTestId("next-page-error")).not.toHaveTextContent("core is busy");
      fail = false;
      await act(() => vi.advanceTimersByTimeAsync(61_000));
      await waitFor(() => expect(screen.queryByTestId("refetch-error")).toBeNull(), T);
      expect(within(table).getByText("second.example")).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it("does the same for DNSSEC results: a new result shows by polling with older results loaded", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
      const result = (id: number, name: string) => ({
        id,
        name,
        qtype: "A",
        outcome: "bogus",
        kind: "signature",
        zone: "example",
        ede: 6,
        ede_text: "DNSSEC Bogus",
        proof: null,
        group: "default",
        edges: [],
        clients: [],
        groups: [],
        answer_id: null,
        received_at: null,
        at: "2026-11-24T02:12:00.000000Z",
      });
      let withNew = false;
      const { calls } = mockApi([
        {
          method: "GET",
          path: "/dnssec/results",
          body: (c: Call) =>
            c.query.get("cursor") ? { items: [result(5, "older.example")], next_cursor: null } : { items: withNew ? [result(9, "fresh.example"), result(8, "first.example")] : [result(8, "first.example")], next_cursor: "8" },
        },
      ]);
      renderApp("/dnssec");
      await screen.findByText("first.example", undefined, T);
      await user.click(screen.getByRole("button", { name: "Load older results" }));
      await screen.findByText("older.example", undefined, T);
      const n = gets(calls, "/dnssec/results").length;
      withNew = true;
      await act(() => vi.advanceTimersByTimeAsync(61_000));
      expect(await screen.findByText("fresh.example", undefined, T)).toBeInTheDocument();
      expect(screen.getByText("older.example")).toBeInTheDocument();
      expect(gets(calls, "/dnssec/results").slice(n).map((c) => c.query.get("cursor"))).toEqual([null]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("and for the query log: the focus reads the newest records with older ones loaded, keeping them", async () => {
    const user = userEvent.setup();
    const first = W5["/logs?limit=3"] as { items: Rec[]; next_cursor: string };
    const all = (W5["/logs"] as { items: Rec[] }).items;
    const older = { items: [all.at(-1)], next_cursor: null };
    const newest = { ...all[0], id: "bmV3ZXN0", seq: 10, qname: "newest.example", ts: "2026-11-24T02:12:08.238000Z" };
    let withNew = false;
    const { calls } = mockApi([
      { method: "GET", path: "/logs", body: (c: Call) => (c.query.get("cursor") ? older : withNew ? { items: [newest, ...first.items.slice(0, 2)], next_cursor: first.next_cursor } : first) },
    ]);
    const { queryClient } = renderApp("/query-log");
    await screen.findByText("lookup.example", undefined, T);
    await user.click(screen.getByRole("button", { name: "Load older records" }));
    expect(await screen.findByText("ads.example", undefined, T)).toBeInTheDocument();
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    act(() => void queryClient.invalidateQueries({ queryKey: ["logs"], refetchType: "none" }));
    withNew = true;
    const n = gets(calls, "/logs").length;
    refocus();
    expect(await screen.findByText("newest.example", undefined, T)).toBeInTheDocument();
    // The third record, pushed out of the newest page, and the older page stay.
    for (const r of [...first.items, ...older.items]) expect(screen.getAllByText(String((r as Rec).qname)).length).toBeGreaterThan(0);
    expect(gets(calls, "/logs").slice(n).map((c) => c.query.get("cursor"))).toEqual([null]);
  });

  it("reads the first page of the search shown, after the search changed", async () => {
    const user = userEvent.setup();
    const first = W5["/logs?limit=3"] as { items: Rec[]; next_cursor: string };
    const all = (W5["/logs"] as { items: Rec[] }).items;
    const older = { items: [all.at(-1)], next_cursor: null };
    const { calls } = mockApi([{ method: "GET", path: "/logs", body: (c: Call) => (c.query.get("cursor") ? older : first) }]);
    const { queryClient, router } = renderApp("/query-log");
    await screen.findByText("lookup.example", undefined, T);
    await act(() => router.navigate({ to: "/query-log", search: { decision: "block" } as never }));
    await waitFor(() => expect(gets(calls, "/logs").at(-1)?.query.get("decision")).toBe("block"), T);
    await user.click(await screen.findByRole("button", { name: "Load older records" }, T));
    expect(await screen.findByText("ads.example", undefined, T)).toBeInTheDocument();
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    act(() => void queryClient.invalidateQueries({ queryKey: ["logs"], refetchType: "none" }));
    const n = gets(calls, "/logs").length;
    refocus();
    await waitFor(() => expect(gets(calls, "/logs").length).toBe(n + 1), T);
    expect(gets(calls, "/logs").slice(n).map((c) => [c.query.get("cursor"), c.query.get("decision")])).toEqual([[null, "block"]]);
  });

  it("cancels a first-page read still out when the list goes (usePagedList)", async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 15_000 } } });
    const signals: AbortSignal[] = [];
    const fetchPage = (cursor: string | undefined, signal: AbortSignal): Promise<P> => {
      if (cursor) return Promise.resolve(page(["1"], null));
      signals.push(signal);
      return signals.length === 1 ? Promise.resolve(page(["2"], "c1")) : new Promise<P>(() => undefined);
    };
    const wrapper = ({ children }: { children: React.ReactNode }) => <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
    const { result, unmount } = renderHook(() => usePagedList({ queryKey: ["list"], fetchPage, rowKey: byId }), { wrapper });
    await waitFor(() => expect(result.current.data?.pages).toHaveLength(1));
    await act(() => result.current.fetchNextPage());
    await waitFor(() => expect(result.current.data?.pages).toHaveLength(2));
    act(() => void qc.invalidateQueries({ queryKey: ["list"], refetchType: "none" }));
    refocus();
    expect(signals).toHaveLength(2);
    expect(signals[1].aborted).toBe(false);
    unmount();
    expect(signals[1].aborted).toBe(true);
    qc.clear();
  });

  it("stops reading once the page is left", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
      const { calls } = allowsCore({ first: () => ({ items: [allow], next_cursor: cursor }) });
      const { queryClient, router } = renderApp("/temporary-allows");
      const table = await screen.findByRole("table", { name: "Active temporary allows" }, T);
      await within(table).findByText("ads.example", undefined, T);
      await user.click(screen.getByRole("button", { name: "Load more" }));
      await within(table).findByText("second.example", undefined, T);
      await act(() => router.navigate({ to: "/settings" }));
      await screen.findByRole("tab", { name: "Export and restore" }, T);
      act(() => void queryClient.invalidateQueries({ queryKey: qk.tempAllows, refetchType: "none" }));
      const n = active(calls).length;
      await act(() => vi.advanceTimersByTimeAsync(61_000));
      refocus();
      await act(() => vi.advanceTimersByTimeAsync(100));
      expect(active(calls)).toHaveLength(n);
    } finally {
      vi.useRealTimers();
    }
  });
});

// ---------------------------------------------------------------------------------------------
// G2

describe("G2: a restore or reconnect replaces reads still in flight, first reads included", () => {
  it("reads again when a first read is still out (no cached data): the old answer never lands", async () => {
    // Codex's probe (target-final2-codex/ui-probes.test.ts).
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } });
    const before = held<string>();
    let reads = 0;
    const observer = new QueryObserver(qc, { queryKey: ["edges"], queryFn: () => (++reads === 1 ? before.promise : Promise.resolve("restored")) });
    const unsub = observer.subscribe(() => undefined);
    expect(reads).toBe(1);
    resync(qc);
    before.send("pre-restore");
    await waitFor(() => expect(qc.getQueryData(["edges"])).toBe("restored"));
    await new Promise((r) => setTimeout(r, 30));
    expect(qc.getQueryData(["edges"])).toBe("restored");
    expect(reads).toBe(2);
    unsub();
    qc.clear();
  });

  it("does so on `lagged` too, and leaves a manual file's read alone (its editor checks its runs)", async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } });
    const first = held<string>();
    const file = held<string>();
    let reads = 0;
    let fileReads = 0;
    const o1 = new QueryObserver(qc, { queryKey: ["alerts", {}], queryFn: () => (++reads === 1 ? first.promise : Promise.resolve("new")) });
    const o2 = new QueryObserver(qc, { queryKey: qk.manualFile("m"), queryFn: () => (++fileReads, file.promise) });
    const subs = [o1.subscribe(() => undefined), o2.subscribe(() => undefined)];
    applyEvent(qc, { type: "lagged", data: { missed: 2 } });
    first.send("old");
    file.send("the file");
    await waitFor(() => expect(qc.getQueryData(["alerts", {}])).toBe("new"));
    await waitFor(() => expect(qc.getQueryData(qk.manualFile("m"))).toBe("the file"));
    expect(fileReads).toBe(1);
    for (const s of subs) s();
    qc.clear();
  });

  it("whoever awaits a cancelled read gets the one that replaced it", async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const before = held<string>();
    let reads = 0;
    const later = () => new Promise<string>((resolve) => setTimeout(() => resolve("restored"), 50));
    const observer = new QueryObserver(qc, { queryKey: ["edges"], queryFn: () => (++reads === 1 ? before.promise : later()) });
    const unsub = observer.subscribe(() => undefined);
    const awaited = observer.refetch();
    resync(qc);
    before.send("pre-restore");
    expect((await awaited).data).toBe("restored");
    unsub();
    qc.clear();
  });

  it("an import's read of the download cap gets the settings read after it, not core's default", async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const before = held<Response>();
    let reads = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        reads++;
        if (reads === 1) return before.promise;
        return new Response(JSON.stringify({ settings: { feeds: { max_download_mib: 512 } } }), { headers: { "content-type": "application/json" } });
      }),
    );
    const cap = downloadCap(qc);
    await waitFor(() => expect(reads).toBe(1));
    invalidateAll(qc);
    before.send(new Response(JSON.stringify({ settings: { feeds: { max_download_mib: 64 } } }), { headers: { "content-type": "application/json" } }));
    expect(await cap).toEqual({ bytes: 512 * 1024 * 1024, fromSettings: true });
    expect(reads).toBe(2);
    // Settings core can't give are asked for once: core's default.
    const failing = vi.fn(async () => new Response(JSON.stringify({ error: { code: "unavailable", message: "core is busy" } }), { status: 503, headers: { "content-type": "application/json" } }));
    vi.stubGlobal("fetch", failing);
    expect(await downloadCap(new QueryClient())).toEqual({ bytes: DEFAULT_DOWNLOAD_MIB * 1024 * 1024, fromSettings: false });
    expect(failing).toHaveBeenCalledTimes(1);
  });

  it("the sidebar shows the restored open alerts when its first read was still out at the restore", async () => {
    const user = userEvent.setup();
    const alert = (id: number) => ({ id, type: "operational", severity: "warning", state: "open", kind: "edge_offline", title: `Alert ${id}`, count: 1, first_seen: "2026-11-24T02:00:00.000000Z", last_seen: "2026-11-24T02:00:00.000000Z", details: {} });
    const first = held<unknown>();
    let restored = false;
    let reads = 0;
    mockApi([
      { method: "GET", path: "/alerts", body: () => (++reads === 1 ? first.promise : { items: restored ? [alert(7)] : [alert(1), alert(2), alert(3)], next_cursor: null }) },
      {
        method: "PUT",
        path: "/config/export",
        body: () => {
          restored = true;
          return { restored: true, generation: 1, missing_secrets: [], warnings: [] };
        },
      },
    ]);
    renderApp("/settings?tab=export");
    await waitFor(() => expect(reads).toBe(1), T);
    await user.upload(await screen.findByLabelText("File", undefined, T), file(JSON.stringify(W5["GET /config/export"])));
    await user.click(await screen.findByRole("button", { name: /^Restore$/ }, T));
    await user.click(await screen.findByRole("button", { name: "Restore" }));
    await screen.findByTestId("restore-result", undefined, T);
    // The read sent before the restore answers now, with the old alerts.
    await act(async () => first.send({ items: [alert(1), alert(2), alert(3)], next_cursor: null }));
    expect(await screen.findAllByLabelText("1 open alerts", undefined, T)).not.toHaveLength(0);
    await new Promise((r) => setTimeout(r, 100));
    expect(screen.queryAllByLabelText("3 open alerts")).toHaveLength(0);
  });
});
