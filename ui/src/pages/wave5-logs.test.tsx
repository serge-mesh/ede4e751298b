// The wave-5 log screens against core 826b4d6's captured answers (test/core-w5.ts): the query log
// search and detail (attribution with roles, the reply a client got, the upstream answer, lookups,
// trial would-blocks), devices and the device and profile views, the trial bundle view and alert
// evidence (copies, counts, answers, wire_mismatch examples, downloads).
import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { mockApi, type Call } from "@/test/mock-api";
import { renderApp } from "@/test/render";
import { W5, recordDetail, recordId } from "@/test/core-w5";
import { b64bytes, captureDownloads } from "@/test/downloads";

const T = { timeout: 8000 };
type Rec = Record<string, unknown>;
const detailOf = (seq: number) => structuredClone(recordDetail(seq)) as Rec;
/** The card (Section) titled `title`; the nav's link of the same name isn't one. */
const card = (title: string) =>
  screen
    .queryAllByText(title)
    .map((el) => el.closest("[data-slot=card]") as HTMLElement | null)
    .find((c): c is HTMLElement => !!c);
const gets = (calls: Call[], path: string) => calls.filter((c) => c.method === "GET" && c.path === path);

async function openRecord(user: ReturnType<typeof userEvent.setup>, name: string, nth = 0) {
  const table = await screen.findByRole("table", { name: "Query log" }, T);
  const cells = await within(table).findAllByText(name, undefined, T);
  await user.click(cells[nth]);
  return screen.findByRole("dialog", undefined, T);
}

describe("query log search (GET logs)", () => {
  it("lists core's records newest first with the reason and the checks' findings", async () => {
    mockApi();
    renderApp("/query-log");
    const table = await screen.findByRole("table", { name: "Query log" }, T);
    const rows = within(table).getAllByRole("row").slice(1);
    // Captured: seq 9 (lookup.example) is newest, seq 2 (ads.example) oldest.
    expect(within(rows[0]).getByText("lookup.example")).toBeInTheDocument();
    expect(within(rows.at(-1)!).getByText("ads.example")).toBeInTheDocument();
    expect(within(rows.at(-1)!).getByText("step 3 · b1 · subs")).toBeInTheDocument();
    // Seq 4's logged CNAME and answers disagree with its answer's wire: core's wire check says so
    // (seq 3, the same name with matching fields, checked ok, has no badge).
    const named = rows.filter((r) => within(r).queryByText("www.example.com"));
    expect(named).toHaveLength(2);
    expect(within(named[0]).getByText("wire mismatch")).toBeInTheDocument();
    expect(within(named[1]).queryByText("wire mismatch")).toBeNull();
    expect(within(table).getAllByText("wire mismatch")).toHaveLength(1);
  });

  it("sends the search as core reads it, and pages with core's cursor", async () => {
    const user = userEvent.setup();
    const first = W5["/logs?limit=3"] as { items: Rec[]; next_cursor: string };
    const older = { items: [(W5["/logs"] as { items: Rec[] }).items.at(-1)], next_cursor: null };
    const { calls } = mockApi([{ method: "GET", path: "/logs", body: (c: Call) => (c.query.get("cursor") === first.next_cursor ? older : first) }]);
    renderApp("/query-log");
    await screen.findByText("lookup.example", undefined, T);
    await user.click(screen.getByRole("button", { name: "Load older records" }));
    expect(await screen.findByText("ads.example", undefined, T)).toBeInTheDocument();
    expect(gets(calls, "/logs").at(-1)!.query.get("cursor")).toBe(first.next_cursor);
    expect(screen.queryByRole("button", { name: "Load older records" })).toBeNull();
    // A name, how it matches, and the decision.
    await user.type(screen.getByLabelText("Name"), "ads.example");
    await user.click(screen.getByLabelText("Name match"));
    await user.click(await screen.findByRole("option", { name: "exact" }));
    await user.click(screen.getByLabelText("Decision"));
    await user.click(await screen.findByRole("option", { name: "block" }));
    await user.click(screen.getByRole("button", { name: /Search/ }));
    await waitFor(() => expect(gets(calls, "/logs").some((c) => c.query.get("qname") === "ads.example")).toBe(true), T);
    const q = gets(calls, "/logs").find((c) => c.query.get("qname") === "ads.example")!.query;
    expect(Object.fromEntries(q)).toEqual({ qname: "ads.example", match: "exact", decision: "block", limit: "100" });
  });
});

describe("query log detail (GET logs/{id})", () => {
  it("shows the attribution with roles, the replay's decisive step and the self-check", async () => {
    const user = userEvent.setup();
    mockApi();
    renderApp("/query-log");
    const sheet = await openRecord(user, "ads.example");
    expect(await within(sheet).findByText("replay: step 3, bundle b1", undefined, T)).toBeInTheDocument();
    expect(within(sheet).getByText("complete")).toBeInTheDocument();
    expect(within(sheet).getByText("ok")).toBeInTheDocument();
    expect(within(sheet).getByText("decisive")).toBeInTheDocument();
    expect(within(sheet).getByText("also_matched")).toBeInTheDocument();
    expect(within(sheet).getAllByText("||ads.example^")).toHaveLength(2);
    expect(within(sheet).getByRole("link", { name: "f-sec" })).toHaveAttribute("href", "/feeds/f-sec");
    // The reply: the edge's block answer is known from the preview only.
    expect(within(sheet).getByText("preview")).toBeInTheDocument();
    expect(within(sheet).getByText("ADDRESS 0.0.0.0")).toBeInTheDocument();
  });

  it("says what cancelled an overridden rule and which versions are gone", async () => {
    const user = userEvent.setup();
    const d = detailOf(2);
    const a = d.attribution as { matches: Rec[] };
    a.matches[1] = { ...a.matches[1], role: "overridden", by: "badfilter" };
    const gone = detailOf(6);
    // Captured from core 826b4d6 when a record named a published config core no longer kept.
    gone.attribution = { state: "unavailable", matches: [], decisive: null, self_check: "skipped", unavailable: [{ bundle: "", head: "55e08a9ba234c287", reason: "the published config is gone" }] };
    mockApi([
      { method: "GET", path: `/logs/${recordId(2)}`, body: d },
      { method: "GET", path: `/logs/${recordId(6)}`, body: gone },
    ]);
    renderApp("/query-log");
    let sheet = await openRecord(user, "ads.example");
    expect(await within(sheet).findByText("overridden", undefined, T)).toBeInTheDocument();
    expect(within(sheet).getByText("by a $badfilter rule")).toBeInTheDocument();
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull(), T);
    sheet = await openRecord(user, "malware.example");
    expect(await within(sheet).findByText("unavailable", undefined, T)).toBeInTheDocument();
    expect(within(sheet).getByText("the published config is gone")).toBeInTheDocument();
    expect(within(sheet).getByText("skipped")).toBeInTheDocument();
  });

  it("shows the reply from the upstream answer and saves the answer's wire", async () => {
    const user = userEvent.setup();
    const saved = captureDownloads();
    mockApi();
    renderApp("/query-log");
    // Newest first: the second www.example.com row is seq 3 (its logged fields match the answer).
    const sheet = await openRecord(user, "www.example.com", 1);
    expect(await within(sheet).findByText("answer", undefined, T)).toBeInTheDocument();
    // The reply's TTLs are clamped to p1's ttl.max (120); the upstream answer keeps its own.
    expect(within(sheet).getByText(/cdn\.example\.net 120 IN A 192\.0\.2\.1/)).toBeInTheDocument();
    expect(within(sheet).getByText(/cdn\.example\.net 256 IN A 192\.0\.2\.1/)).toBeInTheDocument();
    const answer = recordDetail(3).answer as { id: string; wire: string };
    const reply = recordDetail(3).response as { wire: string };
    const buttons = within(sheet).getAllByRole("button", { name: "Download wire" });
    expect(buttons).toHaveLength(2);
    await user.click(buttons[1]);
    expect(saved.at(-1)!.name).toBe(`answer-${answer.id}.bin`);
    expect(new Uint8Array(await saved.at(-1)!.blob.arrayBuffer())).toEqual(b64bytes(answer.wire));
    await user.click(buttons[0]);
    expect(new Uint8Array(await saved.at(-1)!.blob.arrayBuffer())).toEqual(b64bytes(reply.wire));
    expect(within(sheet).getByText("ok")).toBeInTheDocument(); // wire check
    expect(within(sheet).getByText("cloudflare · cloudflare-dot")).toBeInTheDocument();
    expect(within(sheet).getByText("0 ms")).toBeInTheDocument();
  });

  it("shows a trial bundle's would-block and each lookup's verdict", async () => {
    const user = userEvent.setup();
    mockApi();
    renderApp("/query-log");
    let sheet = await openRecord(user, "trial.example");
    expect(await within(sheet).findByText("Trial would-blocks", undefined, T)).toBeInTheDocument();
    expect(within(sheet).getAllByText("trial-b").length).toBeGreaterThan(0);
    expect(within(sheet).getByText("would_block")).toBeInTheDocument();
    expect(within(sheet).getByText("||trial.example^")).toBeInTheDocument();
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull(), T);
    sheet = await openRecord(user, "lookup.example");
    expect(await within(sheet).findByText("q9", undefined, T)).toBeInTheDocument();
    expect(within(sheet).getByText("clean")).toBeInTheDocument();
    expect(within(sheet).getByText("not listed")).toBeInTheDocument();
    // The lookup's detail is the module's JSON object (core a3eb6d5), shown as JSON text.
    expect(within(sheet).getByText((_, el) => el?.tagName === "PRE" && el.textContent === JSON.stringify({ server: "9.9.9.9" }, null, 2))).toBeInTheDocument();
    expect(within(sheet).getByText("23 ms")).toBeInTheDocument();
    expect(within(sheet).getByText("from the provider")).toBeInTheDocument();
  });
});

describe("devices and the device and profile views (GET devices, GET query-summary)", () => {
  it("lists the devices in the logs, and adds one no client names", async () => {
    const user = userEvent.setup();
    mockApi();
    renderApp("/clients");
    const table = await screen.findByRole("table", { name: "Seen devices" }, T);
    const rows = within(table).getAllByRole("row").slice(1);
    const tablet = rows.find((r) => within(r).queryAllByRole("link", { name: "tablet" }).some((a) => a.getAttribute("href") === "/clients/device?key=tablet"))!;
    expect(within(tablet).getByText("client")).toBeInTheDocument();
    expect(within(tablet).queryByRole("button", { name: /Add as client/ })).toBeNull();
    expect(within(tablet).getByText("8")).toBeInTheDocument();
    // Core has no PTR or DHCP names (null): the page says so, and the device shows its address.
    expect(screen.getByText(/Core doesn't learn PTR or DHCP host names yet/)).toBeInTheDocument();
    const byAddress = rows.find((r) => within(r).queryByRole("link", { name: "192.0.2.11" }))!;
    await user.click(within(byAddress).getByRole("button", { name: /Add as client/ }));
    const sheet = await screen.findByRole("dialog", undefined, T);
    expect(within(sheet).getByText("New client")).toBeInTheDocument();
    expect(within(sheet).getAllByText("192.0.2.11").length).toBeGreaterThan(0);
    // By its address: never the MAC logged there, which may be another device's (core c58ba80).
    expect(within(sheet).queryByText("02:aa:bb:cc:dd:02")).toBeNull();
  });

  it("shows a device's queries, block rate, top names with their bundle, and temporary allows", async () => {
    const { calls } = mockApi();
    renderApp("/clients/device?key=tablet");
    expect(await screen.findByText("50.0 %", undefined, T)).toBeInTheDocument(); // 4 of 8 blocked
    expect(Object.fromEntries(gets(calls, "/query-summary")[0].query)).toEqual({ device: "tablet", window: "24h", edge: "all" });
    const blocked = screen.getByText("Top blocked names").closest("[data-slot=card]") as HTMLElement;
    expect(within(blocked).getByRole("link", { name: "ads.example" })).toBeInTheDocument();
    expect(within(blocked).getAllByText("b1").length).toBeGreaterThan(0);
    const allows = card("Temporary allows")!;
    expect(within(allows).getByText("ads.example")).toBeInTheDocument();
    expect(within(allows).getByText("dns")).toBeInTheDocument();
  });

  it("shows a profile's devices", async () => {
    const { calls } = mockApi();
    renderApp("/clients/profile/p1");
    expect(await screen.findByText("8 queries, 4 blocked", undefined, T)).toBeInTheDocument();
    expect(screen.getByText("2 queries, 1 blocked")).toBeInTheDocument();
    expect(gets(calls, "/query-summary")[0].query.get("profile")).toBe("p1");
    // Its devices' temporary allows (core 720be97), each with the device it is for: P5 in ui-cf2.test.tsx.
    expect(within(card("Temporary allows")!).getByText("ads.example")).toBeInTheDocument();
  });
});

describe("trial bundle view (GET trial-results)", () => {
  it("shows the would-blocks by name with their rules, the devices, and core's own limits", async () => {
    const profile = (W5["GET /config/export"] as { configuration: { profiles: Rec[] } }).configuration.profiles.find((p) => p.id === "p1");
    const { calls } = mockApi([{ method: "GET", path: "/profiles/p1", body: profile }]);
    renderApp("/profiles/p1/trial/trial-b");
    expect(await screen.findByText("sub.trial.example", undefined, T)).toBeInTheDocument();
    expect(Object.fromEntries(gets(calls, "/trial-results")[0].query)).toEqual({ profile: "p1", bundle: "trial-b", window: "24h", edge: "all" });
    expect(screen.getAllByText("||trial.example^")).toHaveLength(2);
    expect(screen.getAllByText("(would_block)")).toHaveLength(2);
    expect(screen.getByRole("link", { name: "192.0.2.11" })).toBeInTheDocument();
    const limits = screen.getByRole("list", { name: "What the trial check can't see" });
    for (const l of (W5["/trial-results"] as { limits: string[] }).limits) expect(within(limits).getByText(l)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Enforce" })).toBeInTheDocument();
  });
});

describe("alert evidence (GET alerts/{id}/evidence)", () => {
  const alert = (kind: string) => W5[`/alerts/{${kind}}`] as { alert: { id: number } };

  it("shows what a security alert copies, its counts and copies, and saves the evidence", async () => {
    const user = userEvent.setup();
    const saved = captureDownloads();
    const ev = W5["/alerts/{category_blocked}/evidence"];
    const id = alert("category_blocked").alert.id;
    mockApi([
      { method: "GET", path: `/alerts/${id}`, body: alert("category_blocked") },
      { method: "GET", path: `/alerts/${id}/evidence`, body: ev },
    ]);
    renderApp(`/alerts/${id}`);
    expect(await screen.findByText("Copies records for ads.example and names under it, from tablet.", undefined, T)).toBeInTheDocument();
    const clients = screen.getByRole("table", { name: "Evidence counts per client" });
    expect(within(clients).getByText("tablet")).toBeInTheDocument();
    const names = screen.getByRole("table", { name: "Evidence counts per name" });
    expect(within(names).getByText("ads.example")).toBeInTheDocument();
    const copies = screen.getByRole("table", { name: "Evidence copies" });
    await user.click(within(copies).getByText("ads.example"));
    expect(await within(copies).findByText(/"versions"/, undefined, T)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Download evidence" }));
    expect(saved.at(-1)!.name).toBe(`alert-${id}-evidence.json`);
    expect(JSON.parse(await saved.at(-1)!.blob.text())).toEqual(ev);
  });

  it("saves an answer the copies reference, and counts past 1,000 distinct as others", async () => {
    const user = userEvent.setup();
    const saved = captureDownloads();
    const answer = recordDetail(3).answer as { id: string; wire: string; records: string[] };
    const ev = {
      ...(W5["/alerts/{category_blocked}/evidence"] as Rec),
      answers: [{ answer_id: answer.id, source: "log", wire: answer.wire, records: answer.records }],
      counts: { client: { tablet: 1 }, client_other: { "": 7 }, name: { "ads.example": 1 } },
      incomplete: true,
    };
    const id = alert("category_blocked").alert.id;
    mockApi([
      { method: "GET", path: `/alerts/${id}`, body: alert("category_blocked") },
      { method: "GET", path: `/alerts/${id}/evidence`, body: ev },
    ]);
    renderApp(`/alerts/${id}`);
    await user.click(await screen.findByRole("button", { name: "Download wire" }, T));
    expect(saved.at(-1)!.name).toBe(`alert-${id}-answer-${answer.id}.bin`);
    expect(new Uint8Array(await saved.at(-1)!.blob.arrayBuffer())).toEqual(b64bytes(answer.wire));
    expect(screen.getByText(/Breakdown incomplete/)).toBeInTheDocument();
    const clients = screen.getByRole("table", { name: "Evidence counts per client" });
    expect(within(clients).getByText("others (past 1,000 distinct)")).toBeInTheDocument();
    expect(within(clients).getByText("7")).toBeInTheDocument();
  });

  it("compares a wire_mismatch example with domain's decode and saves it as a fuzz case", async () => {
    const user = userEvent.setup();
    const saved = captureDownloads();
    const ev = W5["/alerts/{wire_mismatch}/evidence"] as { examples: { wire: string }[] };
    const id = alert("wire_mismatch").alert.id;
    mockApi([
      { method: "GET", path: `/alerts/${id}`, body: alert("wire_mismatch") },
      { method: "GET", path: `/alerts/${id}/evidence`, body: ev },
    ]);
    renderApp(`/alerts/${id}`);
    const example = await screen.findByRole("table", { name: "Example 1" }, T);
    const row = (label: string) => within(within(example).getByText(label).closest("tr")!);
    expect(row("Answers").getByText("192.0.2.99")).toBeInTheDocument();
    expect(row("Answers").getByText("192.0.2.1")).toBeInTheDocument();
    expect(row("CNAME chain").getByText("other.example")).toBeInTheDocument();
    expect(row("CNAME chain").getByText("cdn.example.net")).toBeInTheDocument();
    expect(row("Targets").getByText("svc.example")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Download as fuzz case" }));
    expect(saved.at(-1)!.name).toBe(`wire-mismatch-${id}-1.bin`);
    expect(new Uint8Array(await saved.at(-1)!.blob.arrayBuffer())).toEqual(b64bytes(ev.examples[0].wire));
  });

  it("shows a decode error and keeps no evidence section for an alert without evidence", async () => {
    const ev = structuredClone(W5["/alerts/{wire_mismatch}/evidence"]) as { examples: Rec[] };
    ev.examples[0].decoded = { error: "malformed answer: truncated" };
    const id = alert("wire_mismatch").alert.id;
    mockApi([
      { method: "GET", path: `/alerts/${id}`, body: alert("wire_mismatch") },
      { method: "GET", path: `/alerts/${id}/evidence`, body: ev },
      { method: "GET", path: "/alerts/2", body: W5["/alerts/{bundle_warning}"] },
    ]);
    const first = renderApp(`/alerts/${id}`);
    expect(await screen.findByText("malformed answer: truncated", undefined, T)).toBeInTheDocument();
    first.unmount();
    renderApp("/alerts/2");
    await screen.findByText(/cancels 1 rule/, undefined, T);
    expect(screen.queryByText("Evidence")).toBeNull();
  });
});
