// Final-check fixes for the UI at 95eae2f (dev/briefs/fix-95e-ui.md; checks dev/briefs/r07/final-opus.md
// and final-codex.md): V1 an event during a read in flight never cancels it: the read lands and one
// more read follows it, so a stream of events faster than one read never starves a page; V2 Run is
// off, showing the backtest running, while one is out (core computes each in full).
import { describe, expect, it } from "vitest";
import { act, fireEvent, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { InfiniteQueryObserver, QueryClient, QueryObserver, focusManager } from "@tanstack/react-query";
import { mockApi, type Call } from "@/test/mock-api";
import { renderApp } from "@/test/render";
import { W5, capturedEvent } from "@/test/core-w5";
import { alertFrame, type AlertLike } from "@/test/events";
import { applyEvent, invalidateAll, invalidateFresh } from "@/api/events";
import { qk } from "@/api/queries";
import type { UiEventFrame } from "@/api/types";

const T = { timeout: 8000 };
const gets = (calls: Call[], path: string) => calls.filter((c) => c.method === "GET" && c.path === path);
const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));
const later = <V,>(v: V, ms: number) => pause(ms).then(() => v);

interface FakeSocket {
  open(): void;
  emit(data: unknown): void;
}
const sockets = () => (globalThis.WebSocket as unknown as { instances: FakeSocket[] }).instances;
const socket = () => sockets().at(-1)!;

/** Renders the app at `path` and opens its event socket. */
async function renderLive(path: string) {
  const before = sockets().length;
  const app = renderApp(path);
  await waitFor(() => expect(sockets().length).toBeGreaterThan(before), T);
  act(() => socket().open());
  return app;
}

/** Emits `frame()` every `ms` until the returned stop is called. */
function stream(frame: () => unknown, ms: number): () => void {
  const timer = setInterval(() => act(() => socket().emit(frame())), ms);
  return () => clearInterval(timer);
}

const ALERT = (W5["/alerts/{paged}"] as { alert: AlertLike }).alert;

describe("V1: a stream of events faster than one read", () => {
  it("DNSSEC events every 100 ms against 150 ms queue reads: the queue shows during the stream, and each later read lands too (Codex FC1, scaled)", async () => {
    const queue = W5["/dnssec/queue"] as { depth: number };
    let n = 0;
    let out = 0;
    let most = 0;
    const { calls } = mockApi([
      {
        method: "GET",
        path: "/dnssec/queue",
        body: async () => {
          most = Math.max(most, ++out);
          const answer = { ...queue, depth: 100 + ++n };
          await pause(150);
          out--;
          return answer;
        },
      },
    ]);
    const { queryClient } = await renderLive("/dnssec");
    let k = 0;
    const stop = stream(() => ({ type: "dnssec", data: { outcomes: { secure: 1 }, results: ++k } }), 100);
    try {
      // The first read's answer shows, not one replaced by the next event's read.
      expect(await screen.findByRole("table", { name: "DNSSEC queue" }, T)).toBeInTheDocument();
      expect(screen.getByText(/^101 queued/)).toBeInTheDocument();
      // Each event during a read reads once more after it: the reads that follow land as well.
      expect(await screen.findByText(/^103 queued/, undefined, T)).toBeInTheDocument();
    } finally {
      stop();
    }
    // One read at a time (none stacked on core), and none once the events end.
    expect(most).toBe(1);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    const after = gets(calls, "/dnssec/queue").length;
    await pause(300);
    expect(gets(calls, "/dnssec/queue")).toHaveLength(after);
  });

  it("alert events every 50 ms against a 150 ms feeds read: the feeds list shows during the burst (Opus FO1)", async () => {
    const { calls, fixtures } = mockApi([{ method: "GET", path: "/feeds", body: () => later(fixtures["/feeds"], 150) }]);
    const name = ((fixtures["/feeds"] as { items: { name?: string; id: string }[] }).items[0].name ?? "") || (fixtures["/feeds"] as { items: { id: string }[] }).items[0].id;
    await renderLive("/feeds");
    let count = 1;
    const stop = stream(() => alertFrame([{ ...ALERT, count: ++count }]), 50);
    try {
      expect(await screen.findByRole("link", { name }, T)).toBeInTheDocument();
    } finally {
      stop();
    }
    expect(gets(calls, "/feeds").length).toBeGreaterThan(1);
  });

  it("an alert's own event during its first evidence read: that read's copies show, then the evidence is read once more", async () => {
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
    act(() => socket().emit(alertFrame([{ ...detail.alert, count: 5 }])));
    await pause(100);
    // Not cancelled: nothing more is read while it is out.
    expect(gets(calls, `/alerts/${id}/evidence`)).toHaveLength(1);
    await act(async () => release!());
    await screen.findByTestId("evidence-copies", undefined, T);
    await waitFor(() => expect(gets(calls, `/alerts/${id}/evidence`)).toHaveLength(2), T);
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    await pause(100);
    expect(gets(calls, `/alerts/${id}/evidence`)).toHaveLength(2);
  });
});

describe("V1: invalidateFresh (unit)", () => {
  const until = (check: () => void) => waitFor(check, T);
  const client = () => new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 60_000 } } });

  /** An active query whose reads the test answers (`answers[i]` for the i-th read). */
  function observe(qc: QueryClient, key: readonly unknown[]) {
    const answers: ((v: string) => void)[] = [];
    const failures: ((e: Error) => void)[] = [];
    const observer = new QueryObserver(qc, {
      queryKey: key,
      queryFn: () =>
        new Promise<string>((r, f) => {
          answers.push(r);
          failures.push(f);
        }),
    });
    const stop = observer.subscribe(() => {});
    return { answers, failures, stop };
  }

  it("a read in flight, a first one or a refetch, isn't cancelled: it lands, then one more read follows however many events came", async () => {
    const qc = client();
    const key = ["dnssec-queue"];
    const { answers, stop } = observe(qc, key);
    await until(() => expect(answers).toHaveLength(1));
    for (let i = 0; i < 3; i++) invalidateFresh(qc, { queryKey: key });
    await pause(20);
    expect(answers).toHaveLength(1);
    answers[0]("first");
    await until(() => expect(qc.getQueryData(key)).toBe("first"));
    await until(() => expect(answers).toHaveLength(2));
    // A refetch with data the same: its answer lands, then one more read.
    invalidateFresh(qc, { queryKey: key });
    invalidateFresh(qc, { queryKey: key });
    await pause(20);
    expect(answers).toHaveLength(2);
    answers[1]("second");
    await until(() => expect(qc.getQueryData(key)).toBe("second"));
    await until(() => expect(answers).toHaveLength(3));
    answers[2]("third");
    await until(() => expect(qc.getQueryData(key)).toBe("third"));
    await pause(20);
    expect(answers).toHaveLength(3);
    expect(qc.getQueryState(key)?.isInvalidated).toBe(false);
    // Nothing in flight: read at once, as an invalidation does.
    invalidateFresh(qc, { queryKey: key });
    await until(() => expect(answers).toHaveLength(4));
    stop();
  });

  it("one event reads each query it changed once, however many of its invalidations match it (edge_status, feed_run)", async () => {
    const cases: [UiEventFrame, (readonly unknown[])[]][] = [
      [{ type: "edge_status", data: { edge: "e1", event: "heartbeat" } }, [qk.edges, qk.edgeStatus("e1")]],
      [capturedEvent("feed_run"), [qk.review, qk.providerStatus, qk.config("feed-providers")]],
    ];
    for (const [frame, keys] of cases) {
      const qc = client();
      const shown = keys.map((key) => ({ key, ...observe(qc, key) }));
      for (const s of shown) await until(() => expect(s.answers).toHaveLength(1));
      for (const s of shown) s.answers[0]("first");
      for (const s of shown) await until(() => expect(qc.getQueryData(s.key)).toBe("first"));
      applyEvent(qc, frame);
      for (const s of shown) await until(() => expect(s.answers).toHaveLength(2));
      for (const s of shown) s.answers[1]("second");
      for (const s of shown) await until(() => expect(qc.getQueryData(s.key)).toBe("second"));
      await pause(20);
      for (const s of shown) expect(s.answers.length, `${frame.type} → ${s.key.join("/")}`).toBe(2);
      for (const s of shown) s.stop();
    }
  });

  it("a Load more in flight isn't lost: its page lands, then every loaded page is read again", async () => {
    const qc = client();
    const key = qk.alertEvidence(4);
    const reads: { cursor: string | undefined; answer: (p: { items: string[]; next_cursor: string | null }) => void }[] = [];
    const observer = new InfiniteQueryObserver(qc, {
      queryKey: key,
      queryFn: ({ pageParam }) => new Promise<{ items: string[]; next_cursor: string | null }>((r) => reads.push({ cursor: pageParam, answer: r })),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (p) => p.next_cursor ?? undefined,
    });
    const stop = observer.subscribe(() => {});
    await until(() => expect(reads).toHaveLength(1));
    reads[0].answer({ items: ["a"], next_cursor: "c1" });
    await until(() => expect(qc.getQueryState(key)?.fetchStatus).toBe("idle"));
    void observer.fetchNextPage();
    await until(() => expect(reads).toHaveLength(2));
    invalidateFresh(qc, { queryKey: key, exact: true });
    await pause(20);
    expect(reads).toHaveLength(2);
    reads[1].answer({ items: ["b"], next_cursor: null });
    // The read after it covers both pages loaded, each from the page before's fresh cursor.
    await until(() => expect(reads).toHaveLength(3));
    expect(reads[2].cursor).toBeUndefined();
    reads[2].answer({ items: ["new", "a"], next_cursor: "c2" });
    await until(() => expect(reads).toHaveLength(4));
    expect(reads[3].cursor).toBe("c2");
    reads[3].answer({ items: ["b"], next_cursor: null });
    await until(() => expect((qc.getQueryData(key) as { pages: { items: string[] }[] }).pages.map((p) => p.items)).toEqual([["new", "a"], ["b"]]));
    stop();
  });

  it("a read that fails is followed by one more read too", async () => {
    const qc = client();
    const key = ["settings"];
    const { answers, failures, stop } = observe(qc, key);
    await until(() => expect(answers).toHaveLength(1));
    invalidateFresh(qc, { queryKey: key });
    failures[0](new Error("Failed to fetch"));
    await until(() => expect(answers).toHaveLength(2));
    answers[1]("after");
    await until(() => expect(qc.getQueryData(key)).toBe("after"));
    stop();
  });

  it("a read sent after the event (one replacing the read it came during) covers it: nothing more is read", async () => {
    const qc = client();
    const key = ["settings"];
    const { answers, stop } = observe(qc, key);
    await until(() => expect(answers).toHaveLength(1));
    answers[0]("first");
    await until(() => expect(qc.getQueryData(key)).toBe("first"));
    void qc.refetchQueries({ queryKey: key });
    await until(() => expect(answers).toHaveLength(2));
    invalidateFresh(qc, { queryKey: key });
    // A reconnect replaces it (invalidateAll), as a Retry would: that read is sent after the event.
    invalidateAll(qc);
    await until(() => expect(answers).toHaveLength(3));
    answers[2]("newest");
    await until(() => expect(qc.getQueryData(key)).toBe("newest"));
    await pause(20);
    expect(answers).toHaveLength(3);
    expect(qc.getQueryState(key)?.isInvalidated).toBe(false);
    stop();
  });
});

describe("V2: Run while a backtest is out", () => {
  it("is off and shows the backtest running until it lands; Run then asks core again (Codex FC2)", async () => {
    const user = userEvent.setup();
    let hold = false;
    const held: (() => void)[] = [];
    const { calls, fixtures } = mockApi([
      {
        method: "GET",
        path: "/feed-providers/hagezi/backtest",
        body: () => {
          const answer = fixtures["/feed-providers/hagezi/backtest"];
          return hold ? new Promise((r) => held.push(() => r(answer))) : answer;
        },
      },
    ]);
    renderApp("/feed-providers/hagezi?tab=backtest");
    await screen.findByRole("table", { name: "Backtest" }, T);
    const sent = () => gets(calls, "/feed-providers/hagezi/backtest");
    const run = screen.getByRole("button", { name: "Run" });
    hold = true;
    await user.click(run);
    await waitFor(() => expect(sent()).toHaveLength(2), T);
    // While it is out: Run is off and says so; pressing it, or Enter in the form, sends nothing
    // and reuses nothing.
    expect(run).toBeDisabled();
    expect(run).toHaveTextContent("Running…");
    await user.click(run);
    fireEvent.submit(screen.getByRole("form", { name: "Backtest settings" }));
    await pause(50);
    expect(sent()).toHaveLength(2);
    hold = false;
    await act(async () => held.shift()!());
    await waitFor(() => expect(run).toBeEnabled(), T);
    expect(run).toHaveTextContent("Run");
    await user.click(run);
    await waitFor(() => expect(sent()).toHaveLength(3), T);
  });

  it("feed run events don't re-run the backtest, so Run stays usable through a stream of them (Codex GC1, Opus GO2)", async () => {
    const user = userEvent.setup();
    const { calls, fixtures } = mockApi([
      { method: "GET", path: "/feed-providers/hagezi/backtest", body: () => fixtures["/feed-providers/hagezi/backtest"] },
    ]);
    renderApp("/feed-providers/hagezi?tab=backtest");
    await screen.findByRole("table", { name: "Backtest" }, T);
    const sent = () => gets(calls, "/feed-providers/hagezi/backtest");
    await waitFor(() => expect(sent()).toHaveLength(1), T);
    act(() => socket().open());
    const stop = stream(() => capturedEvent("feed_run"), 50);
    await pause(300);
    // The provider's own status and runs are read again; its backtest isn't.
    expect(sent()).toHaveLength(1);
    const run = screen.getByRole("button", { name: "Run" });
    expect(run).toBeEnabled();
    await user.clear(screen.getByLabelText("Days"));
    await user.type(screen.getByLabelText("Days"), "30");
    await user.click(run);
    await waitFor(() => expect(sent()).toHaveLength(2), T);
    expect(Object.fromEntries(sent()[1].query)).toEqual({ days: "30" });
    await pause(300);
    expect(sent()).toHaveLength(2);
    stop();
  });
});

describe("Final check of 1dabc85 (Opus): the backtest is read only when shown and when Run asks", () => {
  it("Check now on the Backtest tab doesn't re-read it (nor stack a second one on core); Run then does", async () => {
    const user = userEvent.setup();
    const { calls, fixtures } = mockApi([
      { method: "POST", path: "/feed-providers/hagezi/check", status: 202, body: { result: "started" } },
      { method: "GET", path: "/feed-providers/hagezi/backtest", body: () => fixtures["/feed-providers/hagezi/backtest"] },
    ]);
    renderApp("/feed-providers/hagezi?tab=backtest");
    await screen.findByRole("table", { name: "Backtest" }, T);
    const sent = () => gets(calls, "/feed-providers/hagezi/backtest");
    await waitFor(() => expect(sent()).toHaveLength(1), T);
    const statusReads = () => gets(calls, "/feed-providers/hagezi/status").length;
    const before = statusReads();
    await user.click(screen.getByRole("button", { name: /Check now/ }));
    // The provider's other views are read again; the backtest isn't.
    await waitFor(() => expect(statusReads()).toBeGreaterThan(before), T);
    await pause(200);
    expect(sent()).toHaveLength(1);
    const run = screen.getByRole("button", { name: "Run" });
    expect(run).toBeEnabled();
    await user.click(run);
    await waitFor(() => expect(sent()).toHaveLength(2), T);
  });

  it("isn't read again when the window regains focus, though stale", async () => {
    const { calls, fixtures } = mockApi([
      { method: "GET", path: "/feed-providers/hagezi/backtest", body: () => fixtures["/feed-providers/hagezi/backtest"] },
    ]);
    const { queryClient } = renderApp("/feed-providers/hagezi?tab=backtest");
    await screen.findByRole("table", { name: "Backtest" }, T);
    const sent = () => gets(calls, "/feed-providers/hagezi/backtest");
    await waitFor(() => expect(sent()).toHaveLength(1), T);
    await act(() => queryClient.invalidateQueries({ queryKey: qk.provider("hagezi", "backtest"), refetchType: "none" }));
    act(() => {
      focusManager.setFocused(false);
      focusManager.setFocused(true);
    });
    await pause(200);
    expect(sent()).toHaveLength(1);
    act(() => focusManager.setFocused(undefined));
  });
});

describe("GO1: Load more while an event's evidence refresh is out", () => {
  it("is held until the refresh lands, so the new copies come; then it loads the older page (Opus GO1)", async () => {
    const user = userEvent.setup();
    const detail = W5["/alerts/{paged}"] as { alert: Record<string, unknown> & { id: number } };
    const id = detail.alert.id;
    const page1 = W5["/alerts/{paged}/evidence?limit=2"] as { items: { seq: number; qname: string }[]; total: number };
    const page2 = W5["/alerts/{paged}/evidence?limit=2&cursor=1"];
    const extra = { ...page1.items[1], seq: 99, qname: "new.malware.example" };
    let stored = false;
    let release: (() => void) | undefined;
    const { calls } = mockApi([
      { method: "GET", path: `/alerts/${id}`, body: detail },
      {
        method: "GET",
        path: `/alerts/${id}/evidence`,
        body: (c: Call) => {
          if (c.query.get("cursor")) return page2;
          if (!stored) return page1;
          const fresh = { ...page1, items: [extra, ...page1.items], total: page1.total + 1 };
          return new Promise((r) => (release = () => r(fresh)));
        },
      },
    ]);
    const { queryClient } = renderApp(`/alerts/${id}`);
    await screen.findByTestId("evidence-copies", undefined, T);
    const more = screen.getByRole("button", { name: "Load older copies" });
    expect(more).toBeEnabled();
    // A copy is stored and the alert's event refreshes the evidence (useEvidenceRefresh's call).
    stored = true;
    act(() => invalidateFresh(queryClient, { queryKey: qk.alertEvidence(String(id)), exact: true }));
    await waitFor(() => expect(release).toBeDefined(), T);
    expect(more).toBeDisabled();
    await user.click(more);
    expect(gets(calls, `/alerts/${id}/evidence`).filter((c) => c.query.get("cursor"))).toHaveLength(0);
    await act(async () => release!());
    await waitFor(() => expect(screen.getByRole("table", { name: "Evidence copies" })).toHaveTextContent("new.malware.example"), T);
    await waitFor(() => expect(more).toBeEnabled(), T);
    await user.click(more);
    await waitFor(() => expect(gets(calls, `/alerts/${id}/evidence`).filter((c) => c.query.get("cursor"))).toHaveLength(1), T);
  });
});

describe("GO1 in every paged list (Codex final check of 1dabc85)", () => {
  it("each Load more is held while any read of its list is out, not only its own next page", async () => {
    // A next page sent while an event's refresh is out replaces that refresh, and what the event
    // brought never comes (api/events.ts invalidateFresh); the evidence test above shows it.
    const sources = import.meta.glob<string>(["./*.tsx", "!./*.test.tsx"], { query: "?raw", import: "default", eager: true });
    const buttons: string[] = [];
    for (const [f, src] of Object.entries(sources)) {
      for (const m of src.matchAll(/onClick=\{\(\) => void (\w+)\.fetchNextPage\(\)\} disabled=\{([^}]*)\}/g)) buttons.push(`${f}: ${m[1]} ${m[2]}`);
      const all = src.match(/fetchNextPage\(\)\}/g)?.length ?? 0;
      const guarded = [...src.matchAll(/void (\w+)\.fetchNextPage\(\)\} disabled=\{\1\.isFetching\}/g)].length;
      expect(guarded, `${f}: every Load more held while its list is read`).toBe(all);
    }
    expect(buttons.length).toBeGreaterThanOrEqual(12);
  });
});
