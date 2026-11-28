// The other wave-5 screens against core 826b4d6's captured answers (test/core-w5.ts): lookup
// modules, presets, provider status, Test now and flush; temporary allows (paging, state filter,
// revoke); the DNSSEC queue and results; extension builds; the Web and access form without the
// LAN CA's zones (a change is a rotation: ui-cf2.test.tsx);
// config export and restore with core's refusals; the bundle page's dry run and layout; and the
// contract the mocks check (test/contract.ts).
import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { mockApi, mutations, reply, type Call } from "@/test/mock-api";
import { renderApp } from "@/test/render";
import { W5, captured } from "@/test/core-w5";
import { captureDownloads } from "@/test/downloads";
import { contractViolations } from "@/test/contract";
import { exportRefusal, scanExportText } from "./settings";
import { safePath } from "./browser-extension";
import { forProvider } from "./lookup-providers";
import { ApiError } from "@/api/errors";

const T = { timeout: 8000 };
type Rec = Record<string, unknown>;
const gets = (calls: Call[], path: string) => calls.filter((c) => c.method === "GET" && c.path === path);
const card = (title: string) =>
  screen
    .queryAllByText(title)
    .map((el) => el.closest("[data-slot=card]") as HTMLElement | null)
    .find((c): c is HTMLElement => !!c);
const coreError = (status: number, code: string, message: string, issues?: unknown[]) => reply(status, { error: { code, message, ...(issues ? { issues } : {}) } });

const PROVIDER = W5["/lookup-providers/q9"] as Rec;
const STATUS = W5["/lookup-providers/q9/status (after)"] as Rec;
const providerRoutes = [
  { method: "GET", path: "/lookup-providers", body: { items: [PROVIDER], next_cursor: null } },
  { method: "GET", path: "/lookup-providers/q9", body: PROVIDER },
  { method: "GET", path: "/lookup-providers/q9/status", body: STATUS },
];

describe("lookup providers (lookup-modules, presets, status, Test now, flush)", () => {
  it("shows core's status: calls, errors, latency, queue, verdicts, the verdict set and the last self-test", async () => {
    mockApi(providerRoutes);
    renderApp("/lookup-providers/q9");
    // Captured from core a3eb6d5 after Test now and its self-test at the create, both passed
    // (quad9 answered with its filter's NXDOMAIN).
    expect(await screen.findByText("2 (0 errors, 0 of them timeouts; 0 rejected)", undefined, T)).toBeInTheDocument();
    expect(screen.getByText("closed")).toBeInTheDocument();
    expect(screen.getByText("0.0 %")).toBeInTheDocument();
    expect(screen.getByText("p50 164 ms, p99 1,843 ms")).toBeInTheDocument();
    expect(screen.getByText(/None published/)).toBeInTheDocument();
    expect(screen.getByText("pass")).toBeInTheDocument();
    expect(screen.getByText("filtered")).toBeInTheDocument();
    expect(screen.getByText("isitblocked.org, expects block, cron 0 * * * *")).toBeInTheDocument();
    expect(card("Verdicts on core")!).toHaveTextContent(String(STATUS.cache_generation));
  });

  it("runs Test now and says the result; shows core's refusal when the module has no self-test", async () => {
    const user = userEvent.setup();
    let refuse = false;
    const passed = captured("POST /lookup-providers/q9/test").body as Rec;
    expect(passed.result).toBe("pass");
    const answers = [passed, { ...passed, result: "inconclusive", verdict: null, reason: null, detail: null, why: "no valid answer from any server" }];
    const { calls } = mockApi([
      ...providerRoutes,
      {
        method: "POST",
        path: "/lookup-providers/q9/test",
        refuses: true,
        body: () => (refuse ? coreError(422, "invalid", "this provider's module names no self-test for its config") : answers.shift()),
      },
    ]);
    renderApp("/lookup-providers/q9");
    await user.click(await screen.findByRole("button", { name: /Test now/ }, T));
    expect(await screen.findByText("Self-test of isitblocked.org passed", undefined, T)).toBeInTheDocument();
    expect(mutations(calls).find((c) => c.path === "/lookup-providers/q9/test")!.body).toEqual({});
    // Core's answer when no server answers (as a core without network gave it at c58ba80).
    await user.click(screen.getByRole("button", { name: /Test now/ }));
    expect(await screen.findByText(/Self-test of isitblocked\.org was inconclusive: no valid answer/, undefined, T)).toBeInTheDocument();
    refuse = true;
    await user.click(screen.getByRole("button", { name: /Test now/ }));
    expect(await screen.findByText("this provider's module names no self-test for its config", undefined, T)).toBeInTheDocument();
  });

  it("flushes on every edge and core and names the new cache generation", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([...providerRoutes, { method: "POST", path: "/lookup-providers/q9/flush", body: captured("POST /lookup-providers/q9/flush").body }]);
    renderApp("/lookup-providers/q9");
    await user.click(await screen.findByRole("button", { name: /Flush cache/ }, T));
    const gen = (captured("POST /lookup-providers/q9/flush").body as { cache_generation: string }).cache_generation;
    expect(await screen.findByText(new RegExp(`Cache generation moved on to ${gen}`), undefined, T)).toBeInTheDocument();
    expect(mutations(calls).filter((c) => c.path === "/lookup-providers/q9/flush")).toHaveLength(1);
  });

  it("builds a new provider's config from a preset and saves the preset with it", async () => {
    const user = userEvent.setup();
    const built = captured("POST /lookup-modules/dns/presets/quad9").body as { config: Rec; category: string | null };
    const { calls } = mockApi([
      { method: "POST", path: "/lookup-modules/dns/presets/quad9", body: built },
      { method: "POST", path: "/lookup-providers", status: 201, body: (c: Call) => ({ id: (c.body as { id: string }).id, entity: c.body, warnings: [] }) },
    ]);
    renderApp("/lookup-providers");
    await user.click(await screen.findByRole("button", { name: /New lookup provider|Add/ }, T));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("Name"), "Quad9");
    await user.click(within(dialog).getByLabelText("Module"));
    await user.click(await screen.findByRole("option", { name: "dns" }));
    await user.click(within(dialog).getByLabelText("Preset"));
    await user.click(await screen.findByRole("option", { name: "Quad9" }));
    await user.click(within(dialog).getByRole("button", { name: "Fill the config from the preset" }));
    expect(await screen.findByText("The preset filled the config form.", undefined, T)).toBeInTheDocument();
    expect(mutations(calls).find((c) => c.path === "/lookup-modules/dns/presets/quad9")!.body).toEqual({});
    await user.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() => expect(mutations(calls).some((c) => c.path === "/lookup-providers")).toBe(true), T);
    expect(mutations(calls).find((c) => c.path === "/lookup-providers")!.body).toMatchObject({ module: "dns", config: built.config, preset: { id: "quad9", params: {} } });
  });

  it("charts core's own per-provider series beside the edges' ones", async () => {
    const { calls } = mockApi(providerRoutes);
    renderApp("/lookup-providers/q9?tab=charts");
    await screen.findByText("Core's calls", undefined, T);
    await waitFor(() => expect(gets(calls, "/metrics").length).toBeGreaterThanOrEqual(13), T);
    const asked = gets(calls, "/metrics").map((c) => c.query.get("series"));
    for (const s of ["lookup_calls,lookup_timeouts,lookup_errors,lookup_rejected", "lookup_call_ms.p50,lookup_call_ms.p99", "lookup_verdicts", "lookup_queue,lookup_dropped", "rechecks,recheck_blocks", "verdict_set_records,verdict_set_overlay_bytes", "lookup_breaker_open,lookup_paused"]) {
      expect(asked).toContain(s);
    }
    expect(screen.queryAllByTestId("not-available")).toHaveLength(0);
    const line = (provider: string) => ({ name: "lookup_calls", labels: { provider }, edge: null, points: [] as [number, number | null][] });
    expect(forProvider("q9")([line("q9"), line("other"), line("q9x")]).map((l) => l.labels.provider)).toEqual(["q9"]);
  });
});

describe("temporary allows (GET temp-allows)", () => {
  it("lists active and recent allows by core's state filter, and revokes an active one", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([{ method: "POST", path: /^\/edges\/[^/]+\/allows\/a-1\/revoke$/, body: {} }]);
    renderApp("/temporary-allows");
    const active = await screen.findByRole("table", { name: "Active temporary allows" }, T);
    expect(await within(active).findByText("ads.example", undefined, T)).toBeInTheDocument();
    const recent = screen.getByRole("table", { name: "Recent temporary allows" });
    expect(await within(recent).findByText("198.51.100.7", undefined, T)).toBeInTheDocument();
    expect(within(recent).getByText("expired")).toBeInTheDocument();
    expect(gets(calls, "/temp-allows").map((c) => c.query.get("state")).sort()).toEqual(["active", "recent"]);
    const before = gets(calls, "/temp-allows").length;
    await user.click(within(active).getByRole("button", { name: "Revoke" }));
    await user.click(await screen.findByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(mutations(calls).some((c) => /\/allows\/a-1\/revoke$/.test(c.path))).toBe(true), T);
    await waitFor(() => expect(gets(calls, "/temp-allows").length).toBeGreaterThan(before), T);
  });

  it("shows a pending revoke and pages with core's cursor", async () => {
    const user = userEvent.setup();
    const one = W5["/temp-allows?state=active"] as { items: Rec[] };
    const pending = { ...one.items[0], revoke_requested_at: "2026-11-24T02:20:00.000000Z", revoke_pending: true };
    const second = { ...one.items[0], allow_id: "a-9", target: "second.example" };
    // A cursor core gave (core refuses one it didn't: 400 bad cursor).
    const cursor = (W5["/temp-allows?limit=1"] as { next_cursor: string }).next_cursor;
    const { calls } = mockApi([
      {
        method: "GET",
        path: "/temp-allows",
        body: (c: Call) =>
          c.query.get("state") === "recent" ? { items: [], next_cursor: null } : c.query.get("cursor") === cursor ? { items: [second], next_cursor: null } : { items: [pending], next_cursor: cursor },
      },
    ]);
    renderApp("/temporary-allows");
    const active = await screen.findByRole("table", { name: "Active temporary allows" }, T);
    expect(await within(active).findByText("revoke pending", undefined, T)).toBeInTheDocument();
    expect(within(active).queryByRole("button", { name: "Revoke" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "Load more" }));
    expect(await within(active).findByText("second.example", undefined, T)).toBeInTheDocument();
    expect(gets(calls, "/temp-allows").some((c) => c.query.get("cursor") === cursor && c.query.get("state") === "active")).toBe(true);
  });
});

describe("DNSSEC (GET dnssec/queue, GET dnssec/results)", () => {
  const bogus = {
    id: 41,
    name: "www.dnssec-failed.org",
    qtype: "A",
    outcome: "bogus",
    kind: "answer",
    zone: "dnssec-failed.org",
    ede: 6,
    ede_text: "DNSSEC Bogus",
    proof: "rrsig has expired",
    group: "cloudflare",
    edges: ["e-9dc7487d"],
    clients: ["tablet"],
    groups: ["cloudflare"],
    answer_id: "4575132879dd0098",
    received_at: "2026-11-24T02:12:01.238000Z",
    at: "2026-11-24T02:13:30.000000Z",
  };

  it("shows the queue with its depth and what shares each check", async () => {
    mockApi();
    renderApp("/dnssec");
    const q = await screen.findByRole("table", { name: "DNSSEC queue" }, T);
    expect(within(q).getByText("www.example.com")).toBeInTheDocument();
    expect(within(q).getByText("answer")).toBeInTheDocument();
    expect(within(q).getByText("tablet")).toBeInTheDocument();
    expect(screen.getByText("1 queued.")).toBeInTheDocument();
  });

  it("shows Bogus results by default, every outcome on request, and pages with core's cursor", async () => {
    const user = userEvent.setup();
    const secure = { ...bogus, id: 40, name: "secure.example", outcome: "secure", zone: null, ede: null, ede_text: null, proof: null };
    const { calls } = mockApi([
      {
        method: "GET",
        path: "/dnssec/results",
        body: (c: Call) => (c.query.get("outcome") === "bogus" ? { items: [bogus], next_cursor: null } : c.query.get("cursor") === "41" ? { items: [secure], next_cursor: null } : { items: [bogus], next_cursor: "41" }),
      },
    ]);
    renderApp("/dnssec");
    const results = await screen.findByRole("list", { name: "DNSSEC results" }, T);
    expect(within(results).getByText("EDE 6 DNSSEC Bogus")).toBeInTheDocument();
    expect(within(results).getByText("dnssec-failed.org")).toBeInTheDocument();
    expect(within(results).getByText("rrsig has expired")).toBeInTheDocument();
    expect(gets(calls, "/dnssec/results")[0].query.get("outcome")).toBe("bogus");
    await user.click(screen.getByLabelText("Outcome"));
    await user.click(await screen.findByRole("option", { name: "Every outcome" }));
    await user.click(await screen.findByRole("button", { name: "Load older results" }, T));
    expect(await screen.findByText("secure.example", undefined, T)).toBeInTheDocument();
    const last = gets(calls, "/dnssec/results").at(-1)!.query;
    expect(last.get("cursor")).toBe("41");
    expect(last.has("outcome")).toBe(false);
  });
});

describe("browser extension builds (GET browser-extension)", () => {
  it("lists each build with its size and SHA-256, linking only core's own download path", async () => {
    const build = { browser: "firefox", version: "0.1.0", file: "picket-browser-extension-0.1.0-firefox.xpi", path: "/browser-extension/picket-browser-extension-0.1.0-firefox.xpi", size: 51234, sha256: "ab".repeat(32) };
    const odd = { ...build, browser: "brave", file: "picket-browser-extension-0.1.0-brave.zip", path: "https://elsewhere.example/x.zip" };
    mockApi([{ method: "GET", path: "/browser-extension", body: { items: [build, odd] } }]);
    renderApp("/browser-extension");
    expect(await screen.findAllByText("Version 0.1.0, 50.0 KiB", undefined, T)).toHaveLength(2);
    const links = screen.getAllByRole("link", { name: /Download/ });
    expect(links).toHaveLength(1);
    expect(links[0]).toHaveAttribute("href", build.path);
    expect(safePath("/browser-extension/a.zip", "a.zip")).toBe("/browser-extension/a.zip");
    expect(safePath("/browser-extension/../a.zip", "../a.zip")).toBeNull();
    expect(safePath("/browser-extension/b.zip", "a.zip")).toBeNull();
  });

  it("says when the package carries no builds (captured: none installed)", async () => {
    mockApi();
    renderApp("/browser-extension");
    expect(await screen.findByText("No builds in this core package.", undefined, T)).toBeInTheDocument();
  });
});

describe("the Web and access form leaves the LAN CA's zones to Settings → LAN CA (core.md §11)", () => {
  it("has no zones control: a change there would be a new root", async () => {
    mockApi();
    renderApp("/settings?tab=web");
    await screen.findByLabelText("Names", undefined, T);
    expect(screen.queryByTestId("lanca-zones")).toBeNull();
    expect(screen.queryByText("Zones")).toBeNull();
  });

  it("saves other web settings without sending the zones", async () => {
    const user = userEvent.setup();
    const { calls, fixtures } = mockApi([{ method: "PUT", path: "/settings", body: (c: Call) => (fixtures["/settings"] as object) ?? c.body }]);
    renderApp("/settings?tab=web");
    // web.names is a tag list (schema-form TagInput, id `…-web_names`), labelled by its field.
    const names = await screen.findByLabelText("Names", undefined, T);
    expect(names.id).toMatch(/-web_names$/);
    await user.type(names, "core.home.arpa{Enter}");
    await user.click(screen.getByRole("button", { name: /Save/ }));
    await waitFor(() => expect(mutations(calls).some((c) => c.path === "/settings")).toBe(true), T);
    const sent = mutations(calls).find((c) => c.path === "/settings")!.body as Rec;
    // Only the changed section, whole (settingsPatch), and never the LAN CA's zones.
    expect(Object.keys(sent)).toEqual(["web"]);
    expect(sent.web).toEqual({ ...(fixtures["/settings"] as { settings: { web: Rec } }).settings.web, names: ["core.home.arpa"] });
    expect(sent).not.toHaveProperty("lanca");
  });
});

describe("config export and restore (GET/PUT config/export)", () => {
  const doc = W5["GET /config/export"];
  const file = (content: string, name = "picket-config-2026-11-24.json") => new File([content], name, { type: "application/json" });

  it("downloads the export under core's file name", async () => {
    const user = userEvent.setup();
    const saved = captureDownloads();
    mockApi([{ method: "GET", path: "/config/export", body: JSON.stringify(doc), headers: { "content-type": "application/json", "content-disposition": 'attachment; filename="picket-config-2026-11-24.json"' } }]);
    renderApp("/settings?tab=export");
    await user.click(await screen.findByRole("button", { name: /Download export/ }, T));
    await waitFor(() => expect(saved).toHaveLength(1), T);
    expect(saved[0].name).toBe("picket-config-2026-11-24.json");
    const got = JSON.parse(await saved[0].blob.text()) as { manual_files: { feed: string; file: string[] }[] };
    // Manual files travel as base64 chunk lists.
    expect(Array.isArray(got.manual_files.find((m) => m.feed === "f-sec")!.file)).toBe(true);
  });

  it("runs one export at a time from the page", async () => {
    const user = userEvent.setup();
    captureDownloads();
    let release: () => void = () => {};
    const gate = new Promise<void>((r) => (release = r));
    const { calls } = mockApi([{ method: "GET", path: "/config/export", body: JSON.stringify(doc), headers: { "content-disposition": 'attachment; filename="picket-config-2026-11-24.json"' } }]);
    const real = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input instanceof Request ? input.url : input).endsWith("/config/export")) await gate;
      return real(input, init);
    }) as typeof fetch;
    try {
      renderApp("/settings?tab=export");
      await user.click(await screen.findByRole("button", { name: /Download export/ }, T));
      const busy = await screen.findByRole("button", { name: /Writing the export/ }, T);
      expect(busy).toBeDisabled();
      release();
      expect(await screen.findByRole("button", { name: /Download export/ }, T)).toBeEnabled();
      expect(gets(calls, "/config/export")).toHaveLength(1);
    } finally {
      globalThis.fetch = real;
    }
  });

  it("explains each refusal of the export: one at a time, disk space, a part too large", async () => {
    const user = userEvent.setup();
    let answer = coreError(409, "busy", "an export is being written; try again when it ends");
    mockApi([{ method: "GET", path: "/config/export", body: () => answer }]);
    renderApp("/settings?tab=export");
    const button = await screen.findByRole("button", { name: /Download export/ }, T);
    await user.click(button);
    expect(await screen.findByText(/Another export is being written or downloaded/, undefined, T)).toBeInTheDocument();
    answer = coreError(507, "insufficient_storage", "the data disk has too little free space for the export (at least 512 MiB must stay free besides it)");
    await user.click(button);
    expect(await screen.findByText(/at least 512 MiB must stay free besides it\)\. Free space on core's data disk/, undefined, T)).toBeInTheDocument();
    answer = coreError(422, "invalid", "the export would be larger than 1024 MiB: the manual feed f-sec's file is 1100 MiB");
    await user.click(button);
    expect(await screen.findByText(/the manual feed f-sec's file is 1100 MiB/, undefined, T)).toBeInTheDocument();
  });

  it("restores a document a real core wrote and lists the secrets still missing and core's warnings", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([{ method: "PUT", path: "/config/export", body: { restored: true, generation: 1, missing_secrets: ["aws_secret"], warnings: ["feed f-old's provider is disabled"] } }]);
    renderApp("/settings?tab=export");
    await user.upload(await screen.findByLabelText("File", undefined, T), file(JSON.stringify(doc)));
    expect(await screen.findByTestId("export-head", undefined, T)).toHaveTextContent("A config export from picket-core 0.1.0");
    expect(screen.getByTestId("export-head")).toHaveTextContent("(format 1)");
    await user.click(screen.getByRole("button", { name: /^Restore$/ }));
    await user.click(await screen.findByRole("button", { name: "Restore" }));
    const result = await screen.findByTestId("restore-result", undefined, T);
    expect(within(result).getByText(/aws_secret/)).toBeInTheDocument();
    expect(within(result).getByRole("link", { name: "set them under Secrets" })).toHaveAttribute("href", "/settings?tab=secrets");
    expect(within(result).getByText("feed f-old's provider is disabled")).toBeInTheDocument();
    expect(mutations(calls).find((c) => c.path === "/config/export")!.body).toEqual(doc);
  });

  it("shows core's restore refusals: one at a time, size, disk space, other zones, a bad reference with its issues", async () => {
    const user = userEvent.setup();
    const answers = [
      coreError(409, "busy", "a restore is running; try again when it ends"),
      coreError(413, "too_large", "a config export is at most 1024 MiB"),
      coreError(507, "insufficient_storage", "the data disk has too little free space for the restore (at least 512 MiB must stay free besides it)"),
      reply(422, captured("PUT /config/export (other zones)").body),
      reply(422, captured("PUT /config/export (bad reference)").body),
      reply(422, captured("PUT /config/export (newer)").body),
    ];
    let n = 0;
    mockApi([{ method: "PUT", path: "/config/export", refuses: true, body: () => answers[n++] }]);
    renderApp("/settings?tab=export");
    await user.upload(await screen.findByLabelText("File", undefined, T), file(JSON.stringify(doc)));
    const restore = async () => {
      await user.click(await screen.findByRole("button", { name: /^Restore$/ }, T));
      await user.click(await screen.findByRole("button", { name: "Restore" }));
    };
    await restore();
    expect(await screen.findByTestId("restore-error", undefined, T)).toHaveTextContent("Another restore is running");
    await restore();
    await waitFor(() => expect(screen.getByTestId("restore-error")).toHaveTextContent("larger than a config export can be (1 GiB)"), T);
    await restore();
    await waitFor(() => expect(screen.getByTestId("restore-error")).toHaveTextContent("Free space on core's data disk"), T);
    await restore();
    await waitFor(() => expect(screen.getByTestId("restore-error")).toHaveTextContent("the export needs lanca.zones example.arpa"), T);
    await restore();
    await waitFor(() => expect(screen.getByTestId("restore-error")).toHaveTextContent('no bundle "nope"'), T);
    expect(screen.getByText("What the document fails")).toBeInTheDocument();
    await restore();
    await waitFor(() => expect(screen.getByTestId("restore-error")).toHaveTextContent("an export of format 99"), T);
  });

  it("refuses before sending what core would refuse: a feed export, not an export, larger than 1 GiB", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi();
    renderApp("/settings?tab=export");
    const input = await screen.findByLabelText("File", undefined, T);
    await user.upload(input, file(JSON.stringify({ picket_feed_export: 1, feed: { id: "x" } }), "feed.json"));
    expect(await screen.findByText(/This is a feed export/, undefined, T)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Restore$/ })).toBeDisabled();
    const big = file(JSON.stringify(doc));
    Object.defineProperty(big, "size", { value: 1024 * 1024 * 1024 + 1 });
    await user.upload(input, big);
    expect(await screen.findByText("The document is larger than a config export can be (1 GiB).", undefined, T)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Restore$/ })).toBeDisabled();
    expect(mutations(calls)).toHaveLength(0);
  });

  it("reads a document's top level and words refusals (unit)", () => {
    expect(scanExportText(JSON.stringify(doc))).toMatchObject({ kind: "export", format: 1, coreVersion: "0.1.0" });
    expect(scanExportText('﻿{"format_version": 1}')).toMatchObject({ kind: "export", format: 1 });
    expect(scanExportText('{"picket_feed_export": 1}').kind).toBe("feed-export");
    expect(scanExportText("||ads.example^").kind).toBe("not-object");
    expect(scanExportText('{"settings": {}}').kind).toBe("no-format");
    expect(scanExportText(JSON.stringify(doc).slice(0, 4096)).kind).toBe("export");
    expect(exportRefusal(new ApiError(409, "busy", "x"), "export")).toMatch(/Another export/);
    expect(exportRefusal(new ApiError(409, "busy", "x"), "restore")).toMatch(/Another restore.*Nothing was changed/);
    expect(exportRefusal(new ApiError(422, "invalid", "core's words"), "restore")).toBe("core's words");
  });
});

describe("bundle detail: the tiering dry run and the stats layout", () => {
  it("shows the dry run's count of blocks that would have come from cold, and puts long stats on their own row", async () => {
    const status = structuredClone(W5["/bundles/b1/status"]) as Rec;
    status.dry_run = {
      status: "done",
      definition_hash: "d1",
      started_at: "2026-11-24T02:00:00.000000Z",
      finished_at: "2026-11-24T02:01:00.000000Z",
      window_from: "2026-11-21T02:00:00.000000Z",
      window_to: "2026-11-24T02:00:00.000000Z",
      blocks: 200,
      cold_blocks: 50,
      proposed: { hot_max_mib: 64, tiers: { "f-sec": "cold" } },
      detail: { hot: 150, cold: 50, top_cold_keys: [["ads.example", 30]] },
      error: null,
    };
    mockApi([
      { method: "GET", path: "/bundles/b1", body: W5["/bundles/b1"] },
      { method: "GET", path: "/bundles/b1/status", body: status },
      { method: "GET", path: "/bundles/b1/versions", body: { items: [], next_cursor: null } },
      { method: "GET", path: "/bundles/b1/warnings", body: { items: [], next_cursor: null } },
    ]);
    renderApp("/bundles/b1");
    const run = await screen.findByTestId("dry-run", undefined, T);
    expect(within(run).getByText("50 (25.0 %)")).toBeInTheDocument();
    expect(within(run).getByText("done")).toBeInTheDocument();
    const stats = screen.getByTestId("bundle-stats");
    const digest = within(stats).getByText("wide_digest").parentElement!;
    expect(digest.className).toMatch(/col-span-3/);
    expect(within(digest).getByText(String((status.stats as Rec).wide_digest)).className).toMatch(/break-all/);
    const keys = within(stats).getByText("hot_keys").parentElement!;
    expect(keys.className).not.toMatch(/col-span/);
    expect(card("Last build's counts and sizes")).toBeDefined();
  });
});

describe("the contract the mocks check for the wave-5 endpoints (test/contract.ts)", () => {
  const q = (s = "") => new URLSearchParams(s);
  const settings = (queryLogs: string) => (p: string) => (p === "/settings" ? { settings: { retention: { query_logs: queryLogs } } } : undefined);

  it("models the query parameters core takes and refuses", () => {
    expect(contractViolations("GET", "/logs", q("qname=a.example&match=exact&decision=block&limit=100"), undefined)).toEqual([]);
    expect(contractViolations("GET", "/logs", q("match=fuzzy"), undefined)).toEqual([expect.stringMatching(/match=fuzzy/)]);
    expect(contractViolations("GET", "/logs", q("decision=blocked"), undefined)).toEqual([expect.stringMatching(/decision=blocked/)]);
    expect(contractViolations("GET", "/logs", q("from=yesterday"), undefined)).toEqual([expect.stringMatching(/400 from: an RFC 3339 time/)]);
    expect(contractViolations("GET", "/logs", q("from=2026-11-24T02:00:00.000Z"), undefined)).toEqual([]);
    expect(contractViolations("GET", "/logs", q("limit=ten"), undefined)).toEqual([expect.stringMatching(/limit: a whole number/)]);
    expect(contractViolations("GET", "/logs", q("window=24h"), undefined)).toEqual([expect.stringMatching(/ignores the query parameter window/)]);
    expect(contractViolations("GET", "/top", q("window=24h"), undefined)).toEqual([expect.stringMatching(/400 kind is required/)]);
    expect(contractViolations("GET", "/top", q("kind=blocked&limit=101"), undefined)).toEqual([expect.stringMatching(/limit: 1 to 100/)]);
    expect(contractViolations("GET", "/top", q("kind=domains"), undefined)).toEqual([expect.stringMatching(/kind=domains/)]);
    expect(contractViolations("GET", "/top", q("kind=blocked&window=72h"), undefined, settings("1d"))).toEqual([expect.stringMatching(/422 the window is longer than the query-log retention/)]);
    expect(contractViolations("GET", "/top", q("kind=blocked&window=24h"), undefined, settings("1d"))).toEqual([]);
    expect(contractViolations("GET", "/query-summary", q("device=tablet&profile=p1"), undefined)).toEqual([expect.stringMatching(/name one device or one profile/)]);
    expect(contractViolations("GET", "/query-summary", q("window=24h"), undefined)).toEqual([expect.stringMatching(/name one device or one profile/)]);
    expect(contractViolations("GET", "/query-summary", q("profile=p1&window=6h"), undefined)).toEqual([]);
    expect(contractViolations("GET", "/trial-results", q("profile=p1"), undefined)).toEqual([expect.stringMatching(/400 bundle is required/)]);
    expect(contractViolations("GET", "/trial-results", q("profile=&bundle=b"), undefined)).toEqual([expect.stringMatching(/profile and bundle: ids/)]);
    expect(contractViolations("GET", "/trial-results", q("profile=p1&bundle=trial-b&window=1h"), undefined)).toEqual([]);
    expect(contractViolations("GET", "/temp-allows", q("state=ended"), undefined)).toEqual([expect.stringMatching(/state=ended/)]);
    expect(contractViolations("GET", "/temp-allows", q(`state=active&limit=100&cursor=${(W5["/temp-allows?limit=1"] as { next_cursor: string }).next_cursor}`), undefined)).toEqual([]);
    expect(contractViolations("GET", "/temp-allows", q("state=active&cursor=x"), undefined)).toEqual([expect.stringMatching(/400 bad cursor/)]);
    expect(contractViolations("GET", "/dnssec/results", q("outcome=bogus&cursor=41"), undefined)).toEqual([]);
    expect(contractViolations("GET", "/dnssec/results", q("outcome=failed"), undefined)).toEqual([expect.stringMatching(/outcome=failed/)]);
    expect(contractViolations("GET", "/dnssec/results", q("cursor=next"), undefined)).toEqual([expect.stringMatching(/cursor isn't one this API gave/)]);
    expect(contractViolations("GET", "/dnssec/queue", q("limit=5"), undefined)).toEqual([]);
  });

  it("models the bodies and refusals of the wave-5 writes", () => {
    expect(contractViolations("POST", "/lookup-providers/q9/flush", q(), {})).toEqual([]);
    expect(contractViolations("POST", "/lookup-providers/q9/test", q(), {})).toEqual([]);
    expect(contractViolations("POST", "/lookup-providers/q9/flush", q(), [])).toEqual([expect.stringMatching(/is array, not object/)]);
    expect(contractViolations("POST", "/lookup-modules/dns/presets/quad9", q(), { transport: "dot" })).toEqual([]);
    expect(contractViolations("POST", "/lookup-modules/dns/presets/quad9", q(), { x: "a".repeat(70_000) })).toEqual([expect.stringMatching(/64 KiB/)]);
    const identity = (p: string) => (p === "/identity" ? { lanca_zones: ["home.arpa"] } : undefined);
    const doc = W5["GET /config/export"] as { configuration: { settings: Rec } };
    expect(contractViolations("PUT", "/config/export", q(), doc, identity)).toEqual([]);
    expect(contractViolations("PUT", "/config/export", q(), { ...doc, format_version: 2 }, identity)).toEqual([expect.stringMatching(/422 the document is from a newer release/)]);
    expect(contractViolations("PUT", "/config/export", q(), { ...doc, configuration: { ...doc.configuration, settings: { ...doc.configuration.settings, "lanca.zones": ["example.arpa"] } } }, identity)).toEqual([
      expect.stringMatching(/422 the document's lanca\.zones differ/),
    ]);
    expect(contractViolations("PUT", "/config/export", q(), { configuration: {} }, identity)).toEqual([expect.stringMatching(/format_version: required/), expect.stringMatching(/format_version: required/)]);
  });
});
