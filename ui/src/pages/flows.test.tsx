import { describe, expect, it } from "vitest";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { EditorView } from "@codemirror/view";
import { mockApi, mutations, type Call } from "@/test/mock-api";
import { renderApp } from "@/test/render";
import { alertFrame, feedRunFrame } from "@/test/events";

const T = { timeout: 8000 };

interface FakeSocket {
  url: string;
  open: () => void;
  emit: (d: unknown) => void;
}
const sockets = () => (globalThis.WebSocket as unknown as { instances: FakeSocket[] }).instances;

describe("text from outside core is rendered as text (core.md §12)", () => {
  it("shows an edge name with markup and control characters literally", async () => {
    mockApi([
      {
        method: "GET",
        path: "/alerts",
        body: {
          items: [
            {
              id: 9,
              type: "security",
              severity: "warning",
              kind: "category_blocked",
              dedupe_key: "k",
              title: 'Blocked <script>alert(1)</script> "x" \\ evil\u0007‮name',
              details: { name: "<img src=x onerror=alert(1)>" },
              first_seen: "2026-11-23T10:00:00Z",
              last_seen: "2026-11-23T10:05:00Z",
              count: 3,
              state: "open",
            },
          ],
          next_cursor: null,
        },
      },
    ]);
    const { container } = renderApp("/edges");
    expect(await screen.findByText("gw <img src=x onerror=alert(1)>", undefined, T)).toBeInTheDocument();
    expect(container.querySelector("img[src='x']")).toBeNull();
    await act(async () => {
      renderApp("/alerts");
    });
    expect(await screen.findByText('Blocked <script>alert(1)</script> "x" \\ evil\\x07\\u{202e}name', undefined, T)).toBeInTheDocument();
    expect(document.querySelector("script:not([src])")).toBeNull();
  });
});

describe("dashboard", () => {
  it("computes totals from heartbeat series and shows the top panels from the query log", async () => {
    const pts = (vals: number[]) => vals.map((v, i) => [1_800_000_000 + i * 300, v]);
    mockApi([
      {
        method: "GET",
        path: "/metrics",
        body: (c: Call) => {
          const series = (c.query.get("series") ?? "").split(",");
          if (!series.includes("queries")) return { step_s: 300, series: [] };
          return {
            step_s: 300,
            series: [
              { name: "queries", labels: {}, edge: null, points: pts([100, 300]) },
              { name: "by_decision.block", labels: {}, edge: null, points: pts([25, 75]) },
              { name: "cache_hits", labels: {}, edge: null, points: pts([60, null as unknown as number]) },
              { name: "cache_misses", labels: {}, edge: null, points: pts([20, 20]) },
            ],
          };
        },
      },
    ]);
    renderApp("/");
    const totals = await screen.findByLabelText("Totals", undefined, T);
    expect(within(totals).getByText("400")).toBeInTheDocument();
    expect(within(totals).getByText("25.0 %")).toBeInTheDocument(); // 100 blocked ÷ 400
    expect(within(totals).getByText("60.0 %")).toBeInTheDocument(); // 60 ÷ (60 + 40)
    // The top panels: core's captured `top` answers (blocked names, allowed names, devices).
    expect(await screen.findByRole("link", { name: "malware.example" }, T)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "www.example.com" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "tablet" })).toBeInTheDocument();
    expect(screen.queryAllByTestId("not-available")).toHaveLength(0);
  });

  it("keeps the window and edge in links to the query log", async () => {
    mockApi([{ method: "GET", path: "/top", body: { items: [{ key: "ads.example", count: 12 }] } }]);
    renderApp("/?window=6h&edge=e-cacc845b");
    const links = await screen.findAllByRole("link", { name: "ads.example" }, T);
    const href = links[0].getAttribute("href") ?? "";
    expect(href).toContain("/query-log");
    expect(href).toContain("window=6h");
    expect(href).toContain("edge=e-cacc845b");
    expect(href).toContain("qname=ads.example");
  });
});

describe("profiles", () => {
  it("creates a profile with the protections and opens it", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([
      { method: "POST", path: "/profiles", status: 201, body: (c: Call) => ({ id: (c.body as { id: string }).id, entity: c.body, warnings: [] }) },
      { method: "GET", path: "/profiles/kids", body: { id: "kids", name: "Kids", allow: [], block: ["block-common"], upstream: "cloudflare" } },
    ]);
    const { router } = renderApp("/profiles/new");
    await user.type(await screen.findByLabelText("Id", undefined, T), "kids");
    await user.type(screen.getByLabelText("Name"), "Kids");
    await user.click(screen.getByRole("button", { name: "Create profile" }));
    await waitFor(() => expect(router.state.location.pathname).toBe("/profiles/kids"), T);
    const post = mutations(calls).find((c) => c.path === "/profiles")!;
    expect(post.headers.get("x-picket-ui")).toBe("1");
    expect(post.headers.get("content-type")).toMatch(/application\/json/);
    expect(post.body).toMatchObject({ id: "kids", name: "Kids", upstream: "cloudflare", log: "full" });
  });

  it("shows core's validation issues next to their fields", async () => {
    const user = userEvent.setup();
    mockApi([
      {
        method: "POST",
        path: "/profiles",
        status: 422,
        body: {
          error: {
            code: "validation",
            message: "the change was refused",
            issues: [{ severity: "error", entity: "profile", id: "Bad", field: "id", code: "bad_profile_id", message: '"Bad" is not a profile id' }],
          },
        },
      },
    ]);
    renderApp("/profiles/new");
    await user.type(await screen.findByLabelText("Id", undefined, T), "Bad");
    await user.click(screen.getByRole("button", { name: "Create profile" }));
    expect(await screen.findByText('"Bad" is not a profile id', { selector: "p" }, T)).toBeInTheDocument();
    expect(screen.getByLabelText("Id")).toHaveAttribute("aria-invalid", "true");
  });

  it("warns when the block response is custom_ip", async () => {
    mockApi([{ method: "GET", path: "/profiles/default", body: { id: "default", name: "Default", block_response: { type: "custom_ip", ttl: 10, ipv4: "192.168.1.5" } } }]);
    renderApp("/profiles/default");
    expect(await screen.findByText(/block answers open no firewall entries/, undefined, T)).toBeInTheDocument();
  });

  it("labels lookup provider fields clearly and saves attached lookup providers", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([
      {
        method: "GET",
        path: "/lookup-providers",
        body: { items: [{ id: "q9", name: "Quad9", module: "dns", category: "security" }], next_cursor: null },
      },
      { method: "POST", path: "/profiles", status: 201, body: (c: Call) => ({ id: (c.body as { id: string }).id, entity: c.body, warnings: [] }) },
      { method: "GET", path: "/profiles/kids", body: { id: "kids", name: "Kids", allow: [], block: [], lookup_providers: [{ provider: "q9", mode: "sync", include_bundles: [], exclude_bundles: [] }], sync_lookup_budget_ms: 250, upstream: "cloudflare" } },
    ]);
    renderApp("/profiles/new");
    const addBtn = await screen.findByRole("button", { name: "Add a lookup provider" }, T);
    expect(screen.getByText("Lookup providers", { selector: "label" })).toBeInTheDocument();
    expect(screen.queryByText("Lookups", { selector: "label, span" })).toBeNull();
    expect(screen.getByLabelText("Sync lookup budget (ms)")).toBeInTheDocument();
    expect(screen.getByText("Alert lookup providers", { selector: "label" })).toBeInTheDocument();
    await user.type(screen.getByLabelText("Name"), "Kids");
    const budget = screen.getByLabelText("Sync lookup budget (ms)");
    await user.clear(budget);
    await user.type(budget, "250");
    await user.click(addBtn);
    expect(screen.getByText("Lookup provider #1")).toBeInTheDocument();
    expect(screen.getByText("Only for these bundles")).toBeInTheDocument();
    expect(screen.getByText("Except these bundles")).toBeInTheDocument();
    expect(screen.getByText(/waiting up to/)).toBeInTheDocument();
    await user.click(screen.getByLabelText("Provider"));
    await user.click(await screen.findByRole("option", { name: "Quad9 (q9)" }, T));
    expect(screen.queryByText("Lookup provider #1")).toBeNull();
    expect(screen.getAllByText("Quad9 (q9)").length).toBeGreaterThanOrEqual(2);
    await user.click(screen.getByRole("button", { name: "Create profile" }));
    await waitFor(() => expect(mutations(calls).some((c) => c.path === "/profiles")).toBe(true), T);
    const post = mutations(calls).find((c) => c.path === "/profiles")!;
    expect(post.body).toMatchObject({
      id: "kids",
      sync_lookup_budget_ms: 250,
      lookup_providers: [{ provider: "q9", mode: "sync", include_bundles: [], exclude_bundles: [] }],
    });
    expect(post.body).not.toHaveProperty("lookups");
    expect(post.body).not.toHaveProperty("lookup_budget_ms");
    expect(post.body).not.toHaveProperty("alert_providers");
  });
});

describe("manual feed editor", () => {
  async function typeInEditor(text: string) {
    const host = await screen.findByTestId("code-editor", undefined, T);
    const dom = host.querySelector(".cm-editor") as HTMLElement;
    const view = EditorView.findFromDOM(dom)!;
    act(() => view.dispatch({ changes: { from: view.state.doc.length, insert: text } }));
  }

  it("saves with the base version, then shows the run's result from the feed_run event", async () => {
    const user = userEvent.setup();
    let finished = false;
    // core returns the save's time with its version; the run that reads the file carries it as
    // updated_at, and its feed_run event as saved_at (feeds.md §1).
    const later = "2026-11-23T10:41:24.176301Z";
    const { calls, fixtures } = mockApi([
      { method: "PUT", path: "/feeds/manual-block/file", body: { version: "newversion", saved_at: later, changed: true } },
      // The status after the save: its file, and busy until its run is stored.
      { method: "GET", path: "/feeds/manual-block/status", body: () => ({ ...(fixtures["/feeds/manual-block/status"] as object), busy: !finished, version: "newversion", saved_at: later }) },
      {
        method: "GET",
        path: "/feeds/manual-block/runs",
        body: () => {
          const old = (fixtures["/feeds/manual-block/runs"] as { items: Record<string, unknown>[] }).items;
          // core stores the run row when the run ends; until then only the earlier runs exist.
          return { items: finished ? [{ ...old[0], id: 8, version: "newversion", status: "applied", updated_at: later }, ...old] : old, next_cursor: null };
        },
      },
    ]);
    const base = (fixtures["/feeds/manual-block/file"] as { version: string }).version;
    renderApp("/feeds/manual-block");
    await typeInEditor("||new.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(mutations(calls).some((c) => c.path === "/feeds/manual-block/file")).toBe(true), T);
    const put = mutations(calls).find((c) => c.path === "/feeds/manual-block/file")!;
    expect(put.body).toEqual({ content: "||ads.example^\n||tracker.example^\n||new.example^\n", base_version: base });
    expect(put.headers.get("x-picket-ui")).toBe("1");
    expect(await screen.findByText(/Waiting for the run's result/, undefined, T)).toBeInTheDocument();
    finished = true;
    const ws = sockets().at(-1)!;
    act(() => {
      ws.open();
      ws.emit(feedRunFrame([{ feed: "manual-block", run: 8, kind: "download", status: "applied", version: "newversion", saved_at: later }]));
    });
    expect(await screen.findByText("Run 8", undefined, T)).toBeInTheDocument();
  });

  it("explains a stale save (409) and offers a reload", async () => {
    const user = userEvent.setup();
    mockApi([{ method: "PUT", path: "/feeds/manual-block/file", status: 409, body: { error: { code: "conflict", message: "the file changed since it was read" } } }]);
    renderApp("/feeds/manual-block");
    await typeInEditor("||other.example^\n");
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("The file changed since you opened it", undefined, T)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Reload the file/ })).toBeInTheDocument();
  });
});

describe("rule policy switches (core.md §12)", () => {
  it("shows each option's default and the OpenAPI description, and saves a drop", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([{ method: "PUT", path: "/feeds/manual-block", body: { id: "manual-block", warnings: [] } }]);
    renderApp("/feeds/manual-block?tab=settings");
    const redirects = await screen.findByRole("switch", { name: "redirects: keep" }, T);
    // The system manual feeds keep all three.
    expect(redirects).toHaveAttribute("data-state", "checked");
    await user.hover(screen.getByRole("button", { name: "About redirects" }));
    // core's description (F8): the rules with examples, what keep allows, the default.
    expect((await screen.findAllByText(/hosts lines that map a name to another IP/, undefined, T)).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/manual feeds:/).length).toBeGreaterThan(0);
    await user.click(redirects);
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(mutations(calls).some((c) => c.path === "/feeds/manual-block")).toBe(true), T);
    const put = mutations(calls).find((c) => c.path === "/feeds/manual-block")!;
    expect(put.method).toBe("PUT");
    expect((put.body as { rule_policy: Record<string, unknown> }).rule_policy).toMatchObject({ redirects: "drop" });
  });
});

describe("edges", () => {
  it("requests a DNS cache flush and shows it pending until applied", async () => {
    const user = userEvent.setup();
    let flushed = false;
    const { calls, fixtures } = mockApi([
      {
        method: "POST",
        path: "/edges/e-cacc845b/flush",
        body: () => {
          flushed = true;
          return { request_id: "r1" };
        },
      },
      {
        method: "GET",
        path: "/edges/e-cacc845b/status",
        body: () => {
          const base = fixtures["/edges/e-cacc845b/status"] as Record<string, unknown>;
          return flushed ? { ...base, requests: [{ kind: "flush_dns", request_id: "r1", requested_at: "2026-11-23T10:00:00Z", pending: true }] } : base;
        },
      },
    ]);
    renderApp("/edges/e-cacc845b");
    await user.click(await screen.findByRole("button", { name: /Flush DNS cache/ }, T));
    await waitFor(() => expect(mutations(calls).some((c) => c.path === "/edges/e-cacc845b/flush")).toBe(true), T);
    const post = mutations(calls).find((c) => c.path === "/edges/e-cacc845b/flush")!;
    expect(post.body).toEqual({});
    expect(post.headers.get("x-picket-ui")).toBe("1");
    expect(await screen.findByRole("button", { name: /Flush pending/ }, T)).toBeDisabled();
  });

  it("adds an edge by key", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([{ method: "POST", path: "/edges", status: 201, body: { id: "e-2", warnings: [] } }]);
    renderApp("/edges");
    await user.click(await screen.findByRole("tab", { name: "Add by key" }, T));
    await user.type(screen.getByLabelText("Name"), "lab");
    await user.type(screen.getByLabelText("Key fingerprint"), `SHA256:${"B".repeat(43)}`);
    const buttons = screen.getAllByRole("button", { name: "Add edge" });
    await user.click(buttons.find((b) => b.getAttribute("type") === "submit")!);
    await waitFor(() => expect(mutations(calls).some((c) => c.path === "/edges")).toBe(true), T);
    expect(mutations(calls).find((c) => c.path === "/edges")!.body).toEqual({ name: "lab", key: `SHA256:${"B".repeat(43)}`, platform: "unifi" });
  });
});

describe("alerts", () => {
  it("deletes selected alerts in bulk", async () => {
    const user = userEvent.setup();
    const alert = (id: number) => ({
      id,
      type: "operational",
      severity: "warning",
      kind: "feed_down",
      dedupe_key: `k${id}`,
      title: `Feed down ${id}`,
      details: {},
      first_seen: "2026-11-23T10:00:00Z",
      last_seen: "2026-11-23T10:00:00Z",
      count: 1,
      state: "open",
    });
    const { calls } = mockApi([
      { method: "GET", path: "/alerts", body: { items: [alert(1), alert(2)], next_cursor: null } },
      { method: "DELETE", path: "/alerts", body: { deleted: 2 } },
    ]);
    renderApp("/alerts");
    await screen.findByText("Feed down 1", undefined, T);
    await user.click(screen.getByRole("checkbox", { name: "Select all" }));
    await user.click(screen.getByRole("button", { name: /Delete 2/ }));
    await user.click(await screen.findByRole("button", { name: "Delete" }));
    await waitFor(() => expect(mutations(calls).some((c) => c.method === "DELETE" && c.path === "/alerts")).toBe(true), T);
    expect(mutations(calls).find((c) => c.path === "/alerts")!.body).toEqual({ ids: [1, 2] });
  });
});

describe("feed providers", () => {
  it("checks a provider now", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([{ method: "POST", path: "/feed-providers/hagezi/check", status: 202, body: { result: "started" } }]);
    renderApp("/feed-providers/hagezi");
    await user.click(await screen.findByRole("button", { name: /Check now/ }, T));
    expect(await screen.findByText(/Check started/, undefined, T)).toBeInTheDocument();
    expect(mutations(calls).find((c) => c.path === "/feed-providers/hagezi/check")!.headers.get("x-picket-ui")).toBe("1");
  });

  it("puts new feeds awaiting review first, and adds one to a bundle", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([
      { method: "GET", path: "/feed-providers-review", body: [{ feed: "hagezi-tif", name: "tif.txt", alert: 3, provider: "hagezi", file: "adblock/tif.txt", since: "2026-11-23T10:00:00Z" }] },
      { method: "PUT", path: "/bundles/block-common", body: { id: "block-common", warnings: [] } },
    ]);
    renderApp("/feed-providers");
    expect(await screen.findByText(/New feeds awaiting review/, undefined, T)).toBeInTheDocument();
    await user.click(await screen.findByRole("button", { name: "Add to bundle…" }, T));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("combobox"));
    await user.click(await screen.findByRole("option", { name: /block-common/ }));
    await user.click(within(dialog).getByRole("button", { name: "Add" }));
    await waitFor(() => expect(mutations(calls).some((c) => c.path === "/bundles/block-common")).toBe(true), T);
    const body = mutations(calls).find((c) => c.path === "/bundles/block-common")!.body as { feeds: { feed: string }[] };
    expect(body.feeds.at(-1)).toEqual({ feed: "hagezi-tif", rule_types: null });
  });
});

describe("the query log", () => {
  it("searches core's log (captured records)", async () => {
    mockApi();
    renderApp("/query-log");
    expect(await screen.findByText("malware.example", undefined, T)).toBeInTheDocument();
    expect(screen.queryAllByTestId("not-available")).toHaveLength(0);
  });

  it("renders a hand-written record", async () => {
    mockApi([
      {
        method: "GET",
        path: "/logs",
        body: { items: [{ id: "r1", ts: "2026-11-23T10:00:00Z", qname: "ads.example.", qtype: "A", decision: "block", profile: "default", edge: "e-cacc845b" }], next_cursor: null },
      },
    ]);
    renderApp("/query-log");
    expect(await screen.findByText("ads.example.", undefined, T)).toBeInTheDocument();
  });
});

describe("live updates", () => {
  it("connects to the page's own origin and refetches alerts on an alert event", async () => {
    const { calls } = mockApi();
    renderApp("/alerts");
    await screen.findByRole("heading", { name: "Alerts" }, T);
    const ws = sockets().at(-1)!;
    expect(ws.url).toBe(`ws://${window.location.host}/api/ui/v1/events`);
    act(() => ws.open());
    await waitFor(() => expect(calls.filter((c) => c.path === "/alerts").length).toBeGreaterThan(0), T);
    const before = calls.filter((c) => c.path === "/alerts").length;
    act(() => ws.emit(alertFrame([{ id: 1 }])));
    await waitFor(() => expect(calls.filter((c) => c.path === "/alerts").length).toBeGreaterThan(before), T);
  });
});
