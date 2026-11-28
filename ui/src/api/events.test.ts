import { describe, expect, it, vi } from "vitest";
import { QueryClient } from "@tanstack/react-query";
import { applyEvent, eventsUrl, keptByEvents, parseEvent } from "./events";
import { feedRunFrame } from "@/test/events";

describe("UI WebSocket events (api.md §7)", () => {
  it("connects to the page's own host, wss under https", () => {
    expect(eventsUrl({ protocol: "https:", host: "core.home.arpa:8443" })).toBe("wss://core.home.arpa:8443/api/ui/v1/events");
    expect(eventsUrl({ protocol: "http:", host: "10.0.0.2:8443" })).toBe("ws://10.0.0.2:8443/api/ui/v1/events");
  });

  it("accepts only {type, data} JSON frames", () => {
    expect(parseEvent('{"type":"alert","data":{"alerts":[],"alerts_truncated":false,"changes":0}}')).toEqual({ type: "alert", data: { alerts: [], alerts_truncated: false, changes: 0 } });
    expect(parseEvent("not json")).toBeNull();
    expect(parseEvent('{"data":1}')).toBeNull();
    expect(parseEvent(new ArrayBuffer(2))).toBeNull();
  });

  it("invalidates what each event changes", () => {
    const qc = new QueryClient();
    const spy = vi.spyOn(qc, "invalidateQueries");
    const keys = () => spy.mock.calls.map((c) => JSON.stringify((c[0] as { queryKey?: unknown })?.queryKey ?? null));
    applyEvent(qc, { type: "edge_status", data: { edge: "e1", event: "heartbeat" } });
    expect(keys()).toEqual(expect.arrayContaining(['["edges"]', '["edges","e1","status"]']));
    spy.mockClear();
    applyEvent(qc, feedRunFrame([{ feed: "f", run: 1 }]));
    expect(keys()).toEqual(expect.arrayContaining(['["feeds"]', '["feed-providers"]']));
    spy.mockClear();
    applyEvent(qc, { type: "alert", data: { alerts: [], alerts_truncated: false, changes: 1 } });
    // An open public-suffix list follows its grouped warning (#49).
    expect(keys()).toEqual(expect.arrayContaining(['["alerts"]', '["bundlePublicSuffixes"]']));
    spy.mockClear();
    applyEvent(qc, { type: "bundle_version", data: { bundle: "b" } });
    expect(keys()).toEqual(expect.arrayContaining(['["bundles"]', '["bundlePublicSuffixes"]', '["browser-lists"]']));
    // Events keep it fresh, so the socket's first open reads it once more.
    expect(keptByEvents(["bundlePublicSuffixes", "b", "f"])).toBe(true);
    // A suffix's further rules (issue 115) sit under the same key, so they follow too.
    expect(keptByEvents(["bundlePublicSuffixes", "b", "f", "rules", "co.uk", "c1"])).toBe(true);
    spy.mockClear();
    applyEvent(qc, { type: "lagged", data: { missed: 3 } });
    // Everything, and (round 3, W7) closed editors' manual files marked stale.
    expect(keys()).toEqual(["null", '["manual-file"]']);
  });
});
