// The UI on core c58ba80's API (dev/briefs/ui-adapt-c58.md), against answers captured from a real
// core at c58ba80 (test/core-w5.ts, scripts/capture-w5.mjs): P2 LAN CA rotations name the root
// they replace (`lanca.rotate_from`: 422 without it, 409 for a replaced root, 503 while core's clock
// isn't synchronised, `clock_synced`), the `lanca` UI event, listeners not yet on the current root;
// P3 evidence newest stored first (old cursors 400, older copies to load, newer ones since the first
// page); P4 Test now's 409 while core reloads the provider; P5 devices' `mac`/`macs`, an alert of
// several edges (`edge` null), a lookup provider's `category_blocked`, a restore's warnings;
// P6 the contract the mocks check.
import { describe, expect, it } from "vitest";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient } from "@tanstack/react-query";
import { mockApi, mutations, reply, takeViolations, type Call } from "@/test/mock-api";
import { renderApp } from "@/test/render";
import { W5, captured, capturedSettings } from "@/test/core-w5";
import { TEST_NOW_RELOADING, checkSchema, contractViolations, isEvidenceCursor, refusalViolations } from "@/test/contract";
import { applyEvent } from "@/api/events";
import { StaleRoot, qk } from "@/api/queries";
import { ApiError } from "@/api/errors";
import { normalizeZones, rotationBlocked, sameZones, zonesRefusal } from "./lanca";
import { blockedBy, seenOnSeveralEdges } from "./alerts";
import { isReloading } from "./lookup-providers";
import { SEEN_AT_ADDRESS_TEXT, newClientOf } from "./clients";
import type { Alert, EvidenceView, SeenDevice, SettingsView, UiEventFrame } from "@/api/types";

const T = { timeout: 8000 };
type Rec = Record<string, unknown>;
const gets = (calls: Call[], path: string) => calls.filter((c) => c.method === "GET" && c.path === path);
const q = (s = "") => new URLSearchParams(s);

interface FakeSocket {
  open(): void;
  emit(data: unknown): void;
}
const socket = () => (globalThis.WebSocket as unknown as { instances: FakeSocket[] }).instances.at(-1)!;

const FRESH = capturedSettings("/settings (fresh)");
const ROTATING = capturedSettings("/settings (rotating)");
const ROTATED = capturedSettings("/settings (rotated)");
const UNSYNCED = capturedSettings("/settings (clock not synchronised)");
const bodyOf = (key: string) => captured(key).body;
const messageOf = (key: string) => (bodyOf(key) as { error: { message: string } }).error.message;
const apiError = (key: string) => {
  const b = bodyOf(key) as { error: { code: string; message: string } };
  return new ApiError(captured(key).status, b.error.code, b.error.message);
};
const lancaEvents = W5.events.lanca as Extract<UiEventFrame, { type: "lanca" }>[];
const lancaEvent = (event: string) => lancaEvents.find((f) => f.data.event === event)!;

describe("P2: rotations name the root they replace; the clock; the lanca event (core c58ba80)", () => {
  it("a dirty draft whose root another change replaced says so and sends nothing until Reload or Keep my zones", async () => {
    const user = userEvent.setup();
    let state: SettingsView = FRESH;
    const { calls } = mockApi([
      // The contract reads the LAN CA core has now from it (`pure`): rotate_from must name it.
      { method: "GET", path: "/settings", pure: true, body: () => state },
      // Core's answer: a new root for the zones sent (a root still the one named would be "kept").
      { method: "PUT", path: "/settings", body: () => ({ ...ROTATED, lanca: { ...ROTATED.lanca, fingerprint: `SHA256:${"2".repeat(64)}`, zones: ["home.arpa", "other.example"] } }) },
    ]);
    renderApp("/settings?tab=lanca");
    const zones = await screen.findByLabelText("Zones", undefined, T);
    await user.type(zones, "other.example{Enter}");
    // Another tab's rotation: core's `lanca` event reads the settings again.
    state = { ...ROTATED, lanca: { ...ROTATED.lanca } };
    act(() => socket().open());
    act(() => socket().emit(lancaEvent("rotated")));
    const moved = await screen.findByTestId("lanca-moved", undefined, T);
    expect(moved).toHaveTextContent(ROTATED.lanca.fingerprint);
    expect(moved).toHaveTextContent("home.arpa, lan.example");
    // The draft stays; no change is offered against a root the admin hasn't seen.
    expect(within(zones.parentElement!).getByText("other.example")).toBeInTheDocument();
    const button = screen.getByRole("button", { name: /Change zones/ });
    expect(button).toBeDisabled();
    await user.click(within(moved).getByRole("button", { name: "Keep my zones" }));
    expect(screen.queryByTestId("lanca-moved")).toBeNull();
    expect(within(zones.parentElement!).getByText("other.example")).toBeInTheDocument();
    expect(button).toBeEnabled();
    await user.click(button);
    const dialog = await screen.findByRole("alertdialog", undefined, T);
    expect(dialog).toHaveTextContent(`replacing root ${ROTATED.lanca.fingerprint}`);
    await user.click(within(dialog).getByRole("button", { name: "Make a new root" }));
    await screen.findByTestId("lanca-rotated", undefined, T);
    expect(mutations(calls)).toHaveLength(1);
    expect(mutations(calls)[0].body).toEqual({ lanca: { zones: ["home.arpa", "other.example"], rotate_from: ROTATED.lanca.fingerprint } });
  });

  it("its own rotation shows at once from core's answer, before the settings are read again", async () => {
    const user = userEvent.setup();
    let release: (() => void) | null = null;
    let rotated = false;
    mockApi([
      {
        method: "GET",
        path: "/settings",
        pure: true,
        // After the rotation, the read is held: the page has only core's answer meanwhile.
        body: () => (rotated ? new Promise((ok) => (release = () => ok(ROTATING))) : FRESH),
      },
      {
        method: "PUT",
        path: "/settings",
        refuses: true,
        body: () => {
          rotated = true;
          return bodyOf("PUT /settings lanca.zones (rotation)");
        },
      },
    ]);
    renderApp("/settings?tab=lanca");
    const zones = await screen.findByLabelText("Zones", undefined, T);
    await user.type(zones, "lan.example{Enter}");
    await user.click(screen.getByRole("button", { name: /Change zones/ }));
    await user.click(await screen.findByRole("button", { name: "Make a new root" }, T));
    await screen.findByTestId("lanca-rotated", undefined, T);
    await waitFor(() => expect(release).not.toBeNull(), T);
    const root = screen.getByText("Current root").closest("[data-slot=card]") as HTMLElement;
    expect(within(root).getByText(ROTATING.lanca.fingerprint)).toBeInTheDocument();
    expect(within(zones.parentElement!).getByText("lan.example")).toBeInTheDocument();
    expect(screen.queryByTestId("lanca-moved")).toBeNull();
    act(() => release!());
    expect(await screen.findByTestId("previous-root", undefined, T)).toBeInTheDocument();
    expect(within(zones.parentElement!).getByText("lan.example")).toBeInTheDocument();
  });

  it("Reload drops the draft for the zones of the root core has now; a clean form follows a new root by itself", async () => {
    const user = userEvent.setup();
    let state: SettingsView = FRESH;
    mockApi([{ method: "GET", path: "/settings", body: () => state }]);
    const { queryClient } = renderApp("/settings?tab=lanca");
    const zones = await screen.findByLabelText("Zones", undefined, T);
    // Clean: it follows.
    state = ROTATED;
    await act(() => queryClient.invalidateQueries({ queryKey: qk.settings }));
    await waitFor(() => expect(within(zones.parentElement!).getByText("lan.example")).toBeInTheDocument(), T);
    expect(screen.queryByTestId("lanca-moved")).toBeNull();
    // Dirty: it says so; Reload takes the current zones.
    await user.type(zones, "x.example{Enter}");
    state = { ...FRESH, lanca: { ...FRESH.lanca, fingerprint: "SHA256:" + "1".repeat(64), zones: ["home.arpa", "y.example"] } };
    await act(() => queryClient.invalidateQueries({ queryKey: qk.settings }));
    const moved = await screen.findByTestId("lanca-moved", undefined, T);
    await user.click(within(moved).getByRole("button", { name: "Reload" }));
    expect(screen.queryByTestId("lanca-moved")).toBeNull();
    expect(within(zones.parentElement!).getByText("y.example")).toBeInTheDocument();
    expect(within(zones.parentElement!).queryByText("x.example")).toBeNull();
    expect(screen.getByRole("button", { name: /Change zones/ })).toBeDisabled();
  });

  it("a root replaced while the confirmation is open: the change still names the root the admin decided on", async () => {
    const user = userEvent.setup();
    let state: SettingsView = FRESH;
    const { calls } = mockApi([
      { method: "GET", path: "/settings", pure: true, body: () => state },
      { method: "PUT", path: "/settings", refuses: true, body: () => reply(409, bodyOf("PUT /settings lanca.zones (replaced root)")) },
    ]);
    const { queryClient } = renderApp("/settings?tab=lanca");
    await user.type(await screen.findByLabelText("Zones", undefined, T), "other.example{Enter}");
    await user.click(screen.getByRole("button", { name: /Change zones/ }));
    const dialog = await screen.findByRole("alertdialog", undefined, T);
    state = ROTATED;
    await act(() => queryClient.invalidateQueries({ queryKey: qk.settings }));
    await waitFor(() => expect(screen.getByTestId("lanca-moved")).toBeInTheDocument(), T);
    await user.click(within(dialog).getByRole("button", { name: "Make a new root" }));
    expect(await screen.findByTestId("lanca-refusal", undefined, T)).toHaveTextContent("The LAN CA root changed since you started editing");
    expect(mutations(calls)[0].body).toEqual({ lanca: { zones: ["home.arpa", "other.example"], rotate_from: FRESH.lanca.fingerprint } });
  });

  it("shows core's 409 for a root replaced meanwhile as 'changed elsewhere', with core's words and the root it has now", async () => {
    const user = userEvent.setup();
    let state: SettingsView = FRESH;
    const { calls } = mockApi([
      { method: "GET", path: "/settings", body: () => state },
      {
        method: "PUT",
        path: "/settings",
        refuses: true,
        body: () => {
          // Another tab's rotation committed between this page's read and its save.
          state = ROTATING;
          return reply(409, bodyOf("PUT /settings lanca.zones (replaced root)"));
        },
      },
    ]);
    renderApp("/settings?tab=lanca");
    await user.type(await screen.findByLabelText("Zones", undefined, T), "other.example{Enter}");
    await user.click(screen.getByRole("button", { name: /Change zones/ }));
    await user.click(await screen.findByRole("button", { name: "Make a new root" }, T));
    const refusal = await screen.findByTestId("lanca-refusal", undefined, T);
    expect(refusal).toHaveTextContent("The LAN CA root changed since you started editing");
    expect(refusal).toHaveTextContent(messageOf("PUT /settings lanca.zones (replaced root)"));
    expect(refusal).toHaveTextContent(/Nothing was changed: reload the settings and decide again/);
    expect(refusal).not.toHaveTextContent("still in use");
    expect(mutations(calls)[0].body).toMatchObject({ lanca: { rotate_from: FRESH.lanca.fingerprint } });
    // The refusal names the root core has now (read right after) and says it once.
    await waitFor(() => expect(refusal).toHaveTextContent(ROTATING.lanca.fingerprint), T);
    expect(screen.queryByTestId("lanca-moved")).toBeNull();
  });

  it("offers no change while core's clock isn't synchronised and says why; a 503 meanwhile shows core's words", async () => {
    const user = userEvent.setup();
    expect(UNSYNCED.lanca.clock_synced).toBe(false);
    mockApi([{ method: "GET", path: "/settings", body: UNSYNCED }]);
    const first = renderApp("/settings?tab=lanca");
    const clock = await screen.findByTestId("lanca-clock", undefined, T);
    expect(clock).toHaveTextContent("Core's clock isn't synchronised yet");
    expect(clock).toHaveTextContent(/NTP/);
    await user.type(screen.getByLabelText("Zones"), "lan.example{Enter}");
    expect(screen.getByRole("button", { name: /Change zones/ })).toBeDisabled();
    expect(screen.queryByTestId("lanca-blocked")).toBeNull();
    first.unmount();
    // Synchronised when the page read it, not by the save: core's 503.
    mockApi([
      { method: "GET", path: "/settings", body: FRESH },
      { method: "PUT", path: "/settings", refuses: true, body: () => reply(503, bodyOf("PUT /settings lanca.zones (clock not synchronised)")) },
    ]);
    renderApp("/settings?tab=lanca");
    await user.type(await screen.findByLabelText("Zones", undefined, T), "lan.example{Enter}");
    expect(screen.queryByTestId("lanca-clock")).toBeNull();
    await user.click(screen.getByRole("button", { name: /Change zones/ }));
    await user.click(await screen.findByRole("button", { name: "Make a new root" }, T));
    const refusal = await screen.findByTestId("lanca-refusal", undefined, T);
    expect(refusal).toHaveTextContent("Core's clock isn't synchronised yet");
    expect(refusal).toHaveTextContent(messageOf("PUT /settings lanca.zones (clock not synchronised)"));
  });

  it("names the listeners not yet on the current root; previous_dropped reads the settings again and the root's use ends", async () => {
    let state: SettingsView = ROTATING;
    const { calls } = mockApi([{ method: "GET", path: "/settings", body: () => state }]);
    const { queryClient } = renderApp("/settings?tab=lanca");
    const previous = await screen.findByTestId("previous-root", undefined, T);
    const table = within(previous).getByRole("table");
    expect(within(table).getByRole("columnheader", { name: "Listeners not on the current root yet" })).toBeInTheDocument();
    expect(within(table).getByText("lan-dot")).toBeInTheDocument();
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    act(() => socket().open());
    // The socket's first open reads the settings once more (events keep them fresh: keptByEvents).
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), T);
    const settings = gets(calls, "/settings").length;
    state = ROTATED;
    act(() => socket().emit(lancaEvent("previous_dropped")));
    await waitFor(() => expect(screen.queryByTestId("previous-root")).toBeNull(), T);
    expect(gets(calls, "/settings").length).toBe(settings + 1);
    expect(screen.queryByTestId("lanca-blocked")).toBeNull();
  });

  it("a lanca event reads the settings and the identity again, nothing else (unit)", () => {
    expect(lancaEvents.map((f) => f.data.event)).toEqual(["rotated", "previous_dropped"]);
    expect(lancaEvent("rotated").data.current).toBe(ROTATED.lanca.fingerprint);
    expect(lancaEvent("previous_dropped").data.root).toBe(FRESH.lanca.fingerprint);
    for (const f of lancaEvents) expect(checkSchema({ $ref: "#/components/schemas/UiEventFrame" }, f)).toEqual([]);
    const qc = new QueryClient();
    const keys = [qk.settings, qk.identity, qk.edges, ["alerts"], qk.config("listeners")];
    for (const k of keys) qc.setQueryData(k, {});
    applyEvent(qc, lancaEvent("rotated"));
    const stale = keys.filter((k) => qc.getQueryCache().find({ queryKey: k, exact: true })?.state.isInvalidated).map((k) => k.join("/"));
    expect(stale).toEqual(["settings", "identity"]);
  });

  it("tells core's refusals apart: replaced root, previous root in use, clock, orphans, others (unit)", () => {
    expect(captured("PUT /settings lanca.zones (replaced root)").status).toBe(409);
    expect(captured("PUT /settings lanca.zones (previous root in use)").status).toBe(409);
    // A 409 is a replaced root only when the root core has now isn't the one named (useRotateLanca).
    expect(zonesRefusal(new StaleRoot(apiError("PUT /settings lanca.zones (replaced root)"), ROTATING)).kind).toBe("stale");
    expect(zonesRefusal(apiError("PUT /settings lanca.zones (previous root in use)")).kind).toBe("in-use");
    expect(zonesRefusal(apiError("PUT /settings lanca.zones (clock not synchronised)")).kind).toBe("clock");
    expect(zonesRefusal(apiError("PUT /settings lanca.zones (orphans)")).kind).toBe("orphans");
    expect(zonesRefusal(apiError("PUT /settings lanca.zones (public suffix)")).kind).toBe("other");
    expect(zonesRefusal(apiError("PUT /settings lanca.zones (no rotate_from)")).kind).toBe("other");
    expect(rotationBlocked(FRESH.lanca)).toBeNull();
    expect(rotationBlocked(ROTATING.lanca)).toBe("in-use");
    expect(rotationBlocked(UNSYNCED.lanca)).toBe("clock");
    expect(rotationBlocked({ can_rotate: false, clock_synced: false })).toBe("in-use");
    expect(sameZones(["Home.Arpa."], ["home.arpa"])).toBe(true);
    expect(sameZones(["home.arpa"], ["home.arpa", "lan"])).toBe(false);
    expect(normalizeZones([" A.example. ", "a.example", ""])).toEqual(["a.example"]);
  });
});

describe("P3: evidence newest stored first (core c58ba80)", () => {
  const detail = W5["/alerts/{paged}"] as { alert: Alert };
  const id = detail.alert.id;
  const page1 = W5["/alerts/{paged}/evidence?limit=2"] as EvidenceView;
  const page2 = W5["/alerts/{paged}/evidence?limit=2&cursor=1"] as EvidenceView;
  const second = W5["second edge"] as string;

  it("lists the copy stored last first, though its event time is older, then the older copies", async () => {
    const user = userEvent.setup();
    expect(page1.items[0].edge).toBe(second);
    expect(Date.parse(page1.items[0].ts)).toBeLessThan(Date.parse(page1.items[1].ts));
    mockApi([
      { method: "GET", path: `/alerts/${id}`, body: detail },
      { method: "GET", path: `/alerts/${id}/evidence`, body: (c: Call) => (c.query.get("cursor") ? page2 : page1) },
    ]);
    renderApp(`/alerts/${id}`);
    const copies = await screen.findByRole("table", { name: "Evidence copies" }, T);
    const edges = () => within(copies).getAllByRole("row").slice(1).map((r) => (r as HTMLTableRowElement).cells[4].textContent);
    expect(edges()).toEqual([second, page1.items[1].edge]);
    await user.click(screen.getByRole("button", { name: "Load older copies" }));
    await waitFor(() => expect(edges()).toHaveLength(4), T);
    expect(edges()).toEqual([...page1.items, ...page2.items].map((i) => i.edge));
  });

  it("says when newer copies were stored after the first page was read, and shows them from a fresh first page", async () => {
    const user = userEvent.setup();
    let stored = false;
    const extra = { ...page1.items[1], seq: 99, qname: "new.malware.example" };
    const { calls } = mockApi([
      { method: "GET", path: `/alerts/${id}`, body: detail },
      {
        method: "GET",
        path: `/alerts/${id}/evidence`,
        body: (c: Call) => {
          // A copy stored after the first page's read: the next page counts it in its total, and it
          // comes first on a fresh first page.
          if (c.query.get("cursor")) {
            stored = true;
            return { ...page2, total: 5 };
          }
          return stored ? { ...page1, items: [extra, ...page1.items], total: 5 } : page1;
        },
      },
    ]);
    renderApp(`/alerts/${id}`);
    await screen.findByTestId("evidence-copies", undefined, T);
    expect(screen.queryByTestId("evidence-newer")).toBeNull();
    await user.click(screen.getByRole("button", { name: "Load older copies" }));
    const newer = await screen.findByTestId("evidence-newer", undefined, T);
    expect(newer).toHaveTextContent("1 newer copy was stored since the first page was read.");
    expect(screen.getByTestId("evidence-copies")).toHaveTextContent("Copies (4 of 5)");
    const n = gets(calls, `/alerts/${id}/evidence`).length;
    await user.click(within(newer).getByRole("button", { name: "Show the newest" }));
    await waitFor(() => expect(screen.getByTestId("evidence-copies")).toHaveTextContent("Copies (5)"), T);
    expect(gets(calls, `/alerts/${id}/evidence`).slice(n)[0].query.get("cursor")).toBeNull();
    expect(within(screen.getByRole("table", { name: "Evidence copies" })).getAllByRole("row")[1]).toHaveTextContent("new.malware.example");
    expect(screen.queryByTestId("evidence-newer")).toBeNull();
  });

  it("models core's cursors: its next_cursor passes, a cursor of core 720be97's form is 400 as captured (unit)", () => {
    const old = W5["/alerts/{paged}/evidence (old cursor)"] as { status: number; body: { error: { code: string } }; cursor: string };
    expect(old.status).toBe(400);
    expect(old.body.error.code).toBe("bad_request");
    expect(isEvidenceCursor(old.cursor)).toBe(false);
    expect(contractViolations("GET", `/alerts/${id}/evidence`, q(`limit=2&cursor=${old.cursor}`), undefined)).toEqual([expect.stringMatching(/400 bad cursor/)]);
    const next = (W5["evidence cursors"] as { first: string }).first;
    expect(isEvidenceCursor(next)).toBe(true);
    expect(contractViolations("GET", `/alerts/${id}/evidence`, q(`limit=2&cursor=${next}`), undefined)).toEqual([]);
    const cursor = (t: string) => Buffer.from(t).toString("base64url");
    expect(isEvidenceCursor(cursor("-7"))).toBe(true);
    expect(isEvidenceCursor(cursor("9223372036854775807"))).toBe(true);
    expect(isEvidenceCursor(cursor("9223372036854775808"))).toBe(false);
    expect(isEvidenceCursor(cursor("12 "))).toBe(false);
    expect(isEvidenceCursor(cursor(""))).toBe(false);
    // A refusal core doesn't give there is flagged.
    expect(refusalViolations("GET", `/alerts/${id}/evidence`, 400, old.body)).toEqual([]);
    expect(refusalViolations("GET", `/alerts/${id}/evidence`, 422, { error: { code: "invalid" } })).toEqual([expect.stringMatching(/never answers 422/)]);
  });
});

describe("P4: Test now while core reloads the provider (409)", () => {
  const PROVIDER = W5["/lookup-providers/q9"] as Rec;
  const STATUS = W5["/lookup-providers/q9/status (after)"] as Rec;
  const routes = [
    { method: "GET", path: "/lookup-providers", body: { items: [PROVIDER], next_cursor: null } },
    { method: "GET", path: "/lookup-providers/q9", body: PROVIDER },
    { method: "GET", path: "/lookup-providers/q9/status", body: STATUS },
  ];

  it("says core is still loading the saved settings, and Retry runs the test once it has", async () => {
    const user = userEvent.setup();
    let reloading = true;
    const { calls } = mockApi([
      ...routes,
      { method: "POST", path: "/lookup-providers/q9/test", refuses: true, body: () => (reloading ? reply(TEST_NOW_RELOADING.status, TEST_NOW_RELOADING.body) : bodyOf("POST /lookup-providers/q9/test")) },
    ]);
    renderApp("/lookup-providers/q9");
    await user.click(await screen.findByRole("button", { name: /Test now/ }, T));
    const alert = await screen.findByTestId("test-now-reloading", undefined, T);
    expect(alert).toHaveTextContent("Core is still loading this provider's saved settings");
    expect(alert).toHaveTextContent("provider is being reloaded");
    expect(alert).toHaveTextContent(/didn't run/);
    // Not a toast too.
    expect(screen.getAllByText(/provider is being reloaded/)).toHaveLength(1);
    reloading = false;
    await user.click(within(alert).getByRole("button", { name: /Retry/ }));
    // The captured result (pass or inconclusive: the capture host's network decides).
    expect(await screen.findByText(/Self-test of isitblocked\.org (passed|was inconclusive|got a wrong verdict)/, undefined, T)).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByTestId("test-now-reloading")).toBeNull(), T);
    expect(mutations(calls).filter((c) => c.path === "/lookup-providers/q9/test")).toHaveLength(2);
  });

  it("models Test now's refusals: 409 conflict, 422 invalid, 503 busy; nothing else (unit)", () => {
    expect(isReloading(new ApiError(409, "conflict", "provider is being reloaded"))).toBe(true);
    expect(isReloading(new ApiError(422, "invalid", "no self-test"))).toBe(false);
    expect(isReloading(new Error("x"))).toBe(false);
    const v = (status: number, code: string) => refusalViolations("POST", "/lookup-providers/q9/test", status, { error: { code, message: "" } });
    expect(v(409, "conflict")).toEqual([]);
    expect(v(422, "invalid")).toEqual([]);
    expect(v(503, "busy")).toEqual([]);
    expect(v(404, "not_found")).toEqual([]);
    expect(v(409, "busy")).toEqual([expect.stringMatching(/409 has code conflict, not "busy"/)]);
    expect(v(503, "unavailable")).toEqual([expect.stringMatching(/503 has code busy/)]);
    // The auth layer's plain-text 503 can come anywhere.
    expect(refusalViolations("POST", "/lookup-providers/q9/test", 503, "too many password checks at once; try again\n")).toEqual([]);
  });
});

describe("P5: devices' MACs, alerts of several edges, lookup blocks, a restore's warnings", () => {
  const devices = (W5["/devices"] as { items: SeenDevice[] }).items;
  const byAddress = devices.find((d) => d.key === "192.0.2.11")!;

  it("shows an address-keyed device's MAC as seen at its address, without speaking for the device", async () => {
    // Core c58ba80: `mac` null, `macs` the MAC logged at its address (maybe another device's).
    expect(byAddress.mac).toBeNull();
    expect(byAddress.macs).toEqual(["02:aa:bb:cc:dd:02"]);
    mockApi();
    renderApp("/clients");
    const table = await screen.findByRole("table", { name: "Seen devices" }, T);
    const row = within(table).getByRole("link", { name: "192.0.2.11" }).closest("tr")!;
    expect(within(row).getByText("02:aa:bb:cc:dd:02")).toBeInTheDocument();
    expect(within(row).getByText("seen at its address")).toBeInTheDocument();
    // A locally administered MAC, but not this device's own: no private-MAC mark here.
    expect(within(row).queryByText("private MAC")).toBeNull();
    const own = within(table).getByRole("link", { name: "02:aa:bb:cc:dd:02" }).closest("tr")!;
    expect(within(own).getByText("private MAC")).toBeInTheDocument();
    expect(within(own).queryByText("seen at its address")).toBeNull();
  });

  it("adds a device as a client by its own MAC, else by its addresses, never by a MAC seen at its address (unit)", () => {
    expect(SEEN_AT_ADDRESS_TEXT).toMatch(/another device's/);
    expect(newClientOf(byAddress)).toEqual({ name: "", macs: [], source_ips: ["192.0.2.11"] });
    const mac = devices.find((d) => d.key === "02:aa:bb:cc:dd:02")!;
    expect(newClientOf(mac)).toEqual({ name: "", macs: ["02:aa:bb:cc:dd:02"], source_ips: [] });
    // A device keyed by a name no client entry has now (core 07acc1c: no MAC, nothing inferred):
    // offered under that name, by its addresses.
    const laptop = devices.find((d) => d.key === "laptop")!;
    expect([laptop.mac, laptop.macs, laptop.client]).toEqual([null, [], null]);
    expect(newClientOf(laptop)).toEqual({ name: "laptop", macs: [], source_ips: ["192.0.2.12"] });
    // A MAC key as the edge logged it (upper case): core's `mac` is its lower-case form.
    expect(newClientOf({ ...mac, key: "02:AA:BB:CC:DD:02" })).toEqual({ name: "", macs: ["02:aa:bb:cc:dd:02"], source_ips: [] });
  });

  it("an alert raised from several edges' records names none: 'several edges', and each copy its edge", async () => {
    const detail = W5["/alerts/{paged}"] as { alert: Alert };
    expect(detail.alert.edge).toBeNull();
    mockApi([
      { method: "GET", path: `/alerts/${detail.alert.id}`, body: detail },
      { method: "GET", path: `/alerts/${detail.alert.id}/evidence`, body: W5["/alerts/{paged}/evidence"] },
    ]);
    renderApp(`/alerts/${detail.alert.id}`);
    const about = (await screen.findByText("About", { selector: "dt" }, T)).nextElementSibling as HTMLElement;
    expect(about).toHaveTextContent("several edges");
    expect(within(about).queryByRole("link", { name: /^edge / })).toBeNull();
    const copies = await screen.findByRole("table", { name: "Evidence copies" }, T);
    expect(within(copies).getByText(W5["second edge"] as string)).toBeInTheDocument();
    expect(within(copies).getAllByText(W5["trial edge"] as string).length).toBeGreaterThan(0);
  });

  it("knows an alert of several edges from one about no edge (unit)", () => {
    const detail = (W5["/alerts/{paged}"] as { alert: Alert }).alert;
    expect(seenOnSeveralEdges(detail)).toBe(true);
    expect(seenOnSeveralEdges({ ...detail, edge: "e-1" })).toBe(false);
    const warning = (W5["/alerts/{bundle_warning}"] as { alert: Alert }).alert;
    expect(warning.edge).toBeNull();
    expect(seenOnSeveralEdges(warning)).toBe(false);
    expect(seenOnSeveralEdges({ ...detail, details: { ...(detail.details as Rec), edge: undefined } })).toBe(false);
    // Only kinds core raises from records say so (a details.edge elsewhere is about something else).
    expect(seenOnSeveralEdges({ ...detail, kind: "wire_mismatch" })).toBe(false);
  });

  it("shows what blocked a category_blocked alert: a lookup provider's verdict, or the feeds", async () => {
    const lookup = W5["/alerts/{lookup block}"] as { alert: Alert };
    mockApi([
      { method: "GET", path: `/alerts/${lookup.alert.id}`, body: lookup },
      { method: "GET", path: `/alerts/${lookup.alert.id}/evidence`, body: W5["/alerts/{lookup block}/evidence"] },
    ]);
    const first = renderApp(`/alerts/${lookup.alert.id}`);
    const providers = await screen.findByRole("table", { name: "Blocking lookup providers" }, T);
    const row = within(providers).getByRole("link", { name: "q9" }).closest("tr")!;
    expect(within(providers).getByRole("link", { name: "q9" })).toHaveAttribute("href", "/lookup-providers/q9");
    expect(row).toHaveTextContent("security");
    // Core 07acc1c sends the score as a decimal; the page shows it as sent.
    expect((lookup.alert.details as { providers: { score: number }[] }).providers[0].score).toBe(0.97);
    expect(row).toHaveTextContent("0.97");
    expect(row).toHaveTextContent("listed: malware");
    expect(row).toHaveTextContent("fresh");
    expect(row).toHaveTextContent('"list": "malware"');
    expect(screen.queryByRole("table", { name: "Blocking feeds" })).toBeNull();
    first.unmount();
    const feed = W5["/alerts/{paged}"] as { alert: Alert };
    mockApi([
      { method: "GET", path: `/alerts/${feed.alert.id}`, body: feed },
      { method: "GET", path: `/alerts/${feed.alert.id}/evidence`, body: W5["/alerts/{paged}/evidence"] },
    ]);
    renderApp(`/alerts/${feed.alert.id}`);
    const feeds = await screen.findByRole("table", { name: "Blocking feeds" }, T);
    expect(within(feeds).getByRole("link", { name: "f-sec" })).toHaveAttribute("href", "/feeds/f-sec");
    expect(feeds).toHaveTextContent("security");
    expect(screen.queryByRole("table", { name: "Blocking lookup providers" })).toBeNull();
  });

  it("reads a category_blocked alert's feeds and providers defensively (unit)", () => {
    const lookup = (W5["/alerts/{lookup block}"] as { alert: Alert }).alert;
    const got = blockedBy(lookup.details as Rec);
    expect(got.feeds).toEqual([]);
    expect(got.providers).toEqual([{ provider: "q9", category: "security", score: 0.97, reason: "listed: malware", detail: { list: "malware", server: "9.9.9.9" }, cached: false }]);
    // Both, as a details object may name them; junk entries are dropped.
    expect(blockedBy({ feeds: [{ feed: "f" }, { category: "x" }, "f2", null], providers: [{ provider: "p", score: "high", cached: "no" }] })).toEqual({
      feeds: [{ feed: "f", category: null }],
      providers: [{ provider: "p", category: null, score: null, reason: null, detail: null, cached: null }],
    });
    expect(blockedBy({ feeds: "f", providers: {} })).toEqual({ feeds: [], providers: [] });
    expect(blockedBy({ feeds: Array.from({ length: 100 }, (_, i) => ({ feed: `f${i}` })) }).feeds).toHaveLength(64);
  });

  it("shows a restore's warning that the edges' configs couldn't be rendered after the commit (200), and says so", async () => {
    const user = userEvent.setup();
    const done = bodyOf("PUT /config/export") as { restored: boolean; missing_secrets: string[]; warnings: string[] };
    // Core c58ba80's wording (config/export.rs `restore_file`); a render can't be made to fail from outside.
    const render = "The edges' configs could not be rendered after the restore (rendering failed); core keeps trying, and the edges keep their last config until it works.";
    mockApi([{ method: "PUT", path: "/config/export", body: { ...done, warnings: [render, ...done.warnings] } }]);
    renderApp("/settings?tab=export");
    const doc = W5["GET /config/export"];
    await user.upload(await screen.findByLabelText("File", undefined, T), new File([JSON.stringify(doc)], "picket-config.json", { type: "application/json" }));
    await screen.findByTestId("export-head", undefined, T);
    await user.click(screen.getByRole("button", { name: /^Restore$/ }));
    await user.click(await screen.findByRole("button", { name: "Restore" }));
    const result = await screen.findByTestId("restore-result", undefined, T);
    expect(within(result).getByText(render)).toBeInTheDocument();
    for (const w of done.warnings) expect(within(result).getByText(w)).toBeInTheDocument();
    expect(await screen.findByText(`Restored, with ${done.warnings.length + 1} warnings: see below`, undefined, T)).toBeInTheDocument();
  });
});

describe("P6: the contract models rotate_from (unit)", () => {
  const listeners = { items: [{ id: "lan-dot", tls: { managed: "dns.home.arpa" } }] };
  const at = (s: SettingsView) => (p: string) => (p === "/settings" ? s : p === "/listeners" ? listeners : undefined);
  const put = (body: Rec, s: SettingsView) => contractViolations("PUT", "/settings", q(), body, at(s));
  const zones = (z: unknown, from?: unknown) => ({ lanca: from === undefined ? { zones: z } : { zones: z, rotate_from: from } });

  it("checks each captured answer's request as core did, in core's order", () => {
    const fp = FRESH.lanca.fingerprint;
    expect(captured("PUT /settings lanca.zones (rotation)").status).toBe(200);
    expect(put(zones(["home.arpa", "lan.example"], fp), FRESH)).toEqual([]);
    expect(captured("PUT /settings lanca.zones (no rotate_from)").status).toBe(422);
    expect(put(zones(["home.arpa", "lan.example"]), FRESH)).toEqual([expect.stringMatching(/422 lanca\.zones would replace the LAN CA root: send lanca\.rotate_from/)]);
    // Core takes a null rotate_from as none (core 07acc1c: the document types it string or null).
    expect(captured("PUT /settings lanca.zones (null rotate_from)").status).toBe(422);
    expect(put(zones(["home.arpa", "lan.example"], null), FRESH)).toEqual([expect.stringMatching(/422 .*send lanca\.rotate_from/)]);
    expect(put(zones(["home.arpa", "lan.example"], 7), FRESH)).toEqual([expect.stringMatching(/422 lanca\.rotate_from is the current LAN CA root's fingerprint/), expect.stringMatching(/rotate_from: is integer, not string/)]);
    expect(captured("PUT /settings lanca.zones (stale rotate_from)").status).toBe(409);
    expect(put(zones(["home.arpa", "lan.example"], "SHA256:" + "0".repeat(64)), FRESH)).toEqual([expect.stringMatching(/409 lanca_root_changed: lanca\.rotate_from names SHA256:0+, but the LAN CA root is/)]);
    expect(captured("PUT /settings lanca.zones (replaced root)").status).toBe(409);
    expect(put(zones(["home.arpa", "lan.example", "other.example"], fp), ROTATING)).toEqual([expect.stringMatching(/409 lanca_root_changed: lanca\.rotate_from names/)]);
    expect(captured("PUT /settings lanca.zones (previous root in use)").status).toBe(409);
    expect(put(zones(["home.arpa"], ROTATING.lanca.fingerprint), ROTATING)).toEqual([expect.stringMatching(/409 conflict: the previous LAN CA root is still in use/)]);
    expect(captured("PUT /settings lanca.zones (clock not synchronised)").status).toBe(503);
    expect(put(zones(["home.arpa", "lan.example"], UNSYNCED.lanca.fingerprint), UNSYNCED)).toEqual([expect.stringMatching(/503 the wall clock isn't synchronised/)]);
    // The clock is checked before a previous root's use (lanca::rotation step 1).
    const both = { ...ROTATING, lanca: { ...ROTATING.lanca, clock_synced: false } };
    expect(put(zones(["home.arpa"], ROTATING.lanca.fingerprint), both)).toEqual([expect.stringMatching(/^PUT \/settings: 503/)]);
    expect(captured("PUT /settings lanca.zones (orphans)").status).toBe(422);
    expect(put(zones(["lan.example"], fp), FRESH)).toEqual([expect.stringMatching(/422 lanca\.zones lan\.example would orphan names in use: dns\.home\.arpa \(listener lan-dot\)/)]);
    expect(put({ ...zones(["home.arpa", "lan.example"], fp), web: { names: ["core.other.example"] } }, FRESH)).toEqual([expect.stringMatching(/core\.other\.example \(web\.names\)/)]);
    expect(captured("PUT /settings lanca.zones (public suffix)").status).toBe(422);
    expect(put(zones(["com"], fp), FRESH)).toEqual([expect.stringMatching(/422 lanca zone "com" is a public suffix/)]);
    // Zones are checked before rotate_from: no rotate_from and a public suffix is the suffix's 422.
    expect(put(zones(["com"]), FRESH)).toEqual([expect.stringMatching(/public suffix/)]);
    expect(put(zones([], fp), FRESH)).toEqual([expect.stringMatching(/422 lanca\.zones needs at least one zone/)]);
    expect(put(zones(["not a name"], fp), FRESH)).toEqual([expect.stringMatching(/422 lanca zone "not a name" is not a DNS name/)]);
  });

  it("passes the same zones (as sets) without rotate_from, and the dotted form; the body is core's SettingsPatch", () => {
    expect(put(zones(["LAN.example.", "home.arpa"]), ROTATED)).toEqual([]);
    expect(put(zones(["home.arpa"], "SHA256:" + "0".repeat(64)), FRESH)).toEqual([]);
    expect(put({ "lanca.zones": ["home.arpa", "lan.example"], "lanca.rotate_from": FRESH.lanca.fingerprint }, FRESH)).toEqual([]);
    expect(put({ "lanca.zones": ["home.arpa", "lan.example"] }, FRESH)).toEqual([expect.stringMatching(/send lanca\.rotate_from/)]);
    expect(put({ "lanca.zones": ["home.arpa", "lan.example"], "lanca.rotate_from": "SHA256:x" }, FRESH)).toEqual([expect.stringMatching(/409/)]);
    // rotate_from alone changes nothing (core ignores it).
    expect(put({ lanca: { rotate_from: FRESH.lanca.fingerprint } }, FRESH)).toEqual([]);
  });

  it("the mock core flags an error core can't give, and reads a pure route's state for the rules", async () => {
    let state: SettingsView = ROTATING;
    mockApi([
      { method: "GET", path: "/settings", pure: true, body: () => state },
      { method: "PUT", path: "/settings", body: () => bodyOf("PUT /settings lanca.zones (rotation)") },
      { method: "POST", path: "/lookup-providers/q9/test", refuses: true, body: () => reply(409, { error: { code: "busy", message: "x" } }) },
    ]);
    const send = (method: string, path: string, body: unknown) =>
      fetch(`/api/ui/v1${path}`, { method, headers: { "content-type": "application/json", "x-picket-ui": "1" }, body: JSON.stringify(body) });
    expect((await send("POST", "/lookup-providers/q9/test", {})).status).toBe(409);
    expect(takeViolations()).toEqual([expect.stringMatching(/POST \/lookup-providers\/\{id\}\/test: core's 409 has code conflict, not "busy"/)]);
    // The settings core has now come from the pure route: a rotation from another root is a 409.
    expect((await send("PUT", "/settings", zones(["home.arpa", "x.example"], FRESH.lanca.fingerprint))).status).toBe(422);
    expect(takeViolations()).toEqual([expect.stringMatching(/409 lanca_root_changed: lanca\.rotate_from names/)]);
    state = FRESH;
    expect((await send("PUT", "/settings", zones(["home.arpa", "lan.example"], FRESH.lanca.fingerprint))).status).toBe(200);
    expect(takeViolations()).toEqual([]);
  });

  it("models PUT settings' refusal codes: 409 lanca_root_changed or conflict, 422 invalid or validation, 503 unavailable", () => {
    const v = (status: number, code: string) => refusalViolations("PUT", "/settings", status, { error: { code, message: "" } });
    expect(v(409, "conflict")).toEqual([]);
    expect(v(409, "lanca_root_changed")).toEqual([]);
    expect(v(422, "invalid")).toEqual([]);
    expect(v(422, "validation")).toEqual([]);
    expect(v(503, "unavailable")).toEqual([]);
    expect(v(503, "busy")).toEqual([expect.stringMatching(/503 has code unavailable/)]);
    expect(v(409, "invalid")).toEqual([expect.stringMatching(/409 has code lanca_root_changed or conflict/)]);
    expect(v(404, "not_found")).toEqual([expect.stringMatching(/never answers 404/)]);
    for (const k of ["(no rotate_from)", "(null rotate_from)", "(stale rotate_from)", "(replaced root)", "(previous root in use)", "(clock not synchronised)", "(orphans)", "(public suffix)"]) {
      const c = captured(`PUT /settings lanca.zones ${k}`);
      expect(refusalViolations("PUT", "/settings", c.status, c.body), k).toEqual([]);
    }
  });
});
