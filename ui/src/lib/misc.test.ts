import { describe, expect, it } from "vitest";
import { computeCoverage } from "./coverage";
import { nextRuns, parseCron } from "./cron";
import { formatBytes, formatSeconds, parseDuration } from "./format";
import { allowedWindows } from "@/components/common/window-picker";
import { isHyperVMac, isPrivateMac, normalizeMac } from "@/pages/clients";
import { ruleFor, ruleSafe } from "@/components/common/append-rule";
import { importBody, inspectImport, readHeader, topLevelKeys } from "./import-file";
import { settingsPatch } from "@/pages/settings";
import { profileEndpoints } from "@/pages/profiles";
import type { Settings } from "@/api/types";

describe("DNSSEC coverage shares (core.md §12)", () => {
  it("adds up to 100 % with queued and not-logged answers", () => {
    const { rows, total } = computeCoverage({
      answersGot: 1000,
      logged: 800,
      classes: { secure: 300, insecure: 200, bogus: 5, indeterminate: 5, fallback: 50, forward_zone: 100, edge: 40 },
      fallbackOutcomes: { secure: 50 },
    });
    expect(total).toBe(1000);
    const share = (k: string) => rows.find((r) => r.key === k)!.share;
    expect(share("bogus_indeterminate")).toBeCloseTo(0.01);
    expect(share("queued")).toBeCloseTo(0.1); // 800 logged − 700 classified
    expect(share("not_logged")).toBeCloseTo(0.2);
    expect(rows.reduce((a, r) => a + r.share, 0)).toBeCloseTo(1);
  });
  it("treats the logged answers as the whole when lost heartbeats make not-logged negative", () => {
    const { rows, total } = computeCoverage({ answersGot: 50, logged: 100, classes: { secure: 100 }, fallbackOutcomes: {} });
    expect(total).toBe(100);
    expect(rows.find((r) => r.key === "not_logged")!.count).toBe(0);
    expect(rows.reduce((a, r) => a + r.share, 0)).toBeCloseTo(1);
  });
});

describe("cron (self-test schedules)", () => {
  it("reads 5-field expressions and gives the next runs in UTC", () => {
    expect(parseCron("0 * * * *")).not.toBeNull();
    expect(parseCron("61 * * * *")).toBeNull();
    expect(parseCron("bad")).toBeNull();
    const runs = nextRuns("0 * * * *", 2, new Date("2026-11-23T10:15:00Z"))!;
    expect(runs.map((d) => d.toISOString())).toEqual(["2026-11-23T11:00:00.000Z", "2026-11-23T12:00:00.000Z"]);
    expect(nextRuns("30 6 * * mon", 1, new Date("2026-11-23T10:00:00Z"))![0].toISOString()).toBe("2026-11-30T06:30:00.000Z");
  });
});

describe("formatting", () => {
  it("parses durations", () => {
    expect(parseDuration("3d")).toBe(259200);
    expect(parseDuration("1h30m")).toBe(5400);
    expect(parseDuration("nope")).toBeNull();
  });
  it("formats sizes and spans", () => {
    expect(formatBytes(1536)).toBe("1.5 KiB");
    expect(formatSeconds(7200)).toBe("2.0 h");
  });
  it("offers no window longer than the retention", () => {
    expect(allowedWindows(86400)).toEqual(["1h", "6h", "24h"]);
    expect(allowedWindows(3 * 86400)).toEqual(["1h", "6h", "24h", "72h"]);
    expect(allowedWindows(600)).toEqual(["1h"]);
  });
});

describe("MAC marks (core.md §12 Clients)", () => {
  it("marks locally administered and Hyper-V MACs", () => {
    expect(isPrivateMac("da:a1:19:00:00:01")).toBe(true);
    expect(isPrivateMac("00:11:22:33:44:55")).toBe(false);
    expect(isHyperVMac("00-15-5D-01-02-03")).toBe(true);
    expect(normalizeMac("AABB.CCDD.EEFF")).toBe("aa:bb:cc:dd:ee:ff");
    expect(normalizeMac("zz")).toBeNull();
  });
});

describe("one-click rules", () => {
  it("refuses names that could turn into another rule", () => {
    expect(ruleSafe("ads.example.com")).toBe(true);
    expect(ruleSafe("evil.com$dnsrewrite=1.2.3.4")).toBe(false);
    expect(ruleSafe("a^|b")).toBe(false);
    expect(ruleSafe("two words")).toBe(false);
    expect(ruleFor("allow", "Ads.Example.")).toBe("@@||ads.example^");
    expect(ruleFor("block", "ads.example")).toBe("||ads.example^");
  });
});

describe("feed imports (api.md §7, feeds.md §4)", () => {
  const body = async (text: string, file = false) =>
    JSON.parse(await (await importBody({ file: file ? new File([text], "x") : null, text: file ? "" : text, info: null })).body.text()) as unknown;

  it("sends a JSON export as is and anything else as {file}", async () => {
    const exp = JSON.stringify({ picket_feed_export: 1, feed: { id: "x" }, entries: [] });
    expect(await body(exp)).toEqual({ picket_feed_export: 1, feed: { id: "x" }, entries: [] });
    expect(await body("ads.example\n")).toEqual({ file: "ads.example\n" });
    expect(await body('{"name": "misp list"}')).toEqual({ file: '{"name": "misp list"}' });
  });

  it("builds a file's body chunk by chunk, escaping what JSON needs", async () => {
    const text = 'a "quoted" \\ line\twith tab\n\u0001ctl é 😀\n'.repeat(5000);
    expect(await body(text, true)).toEqual({ file: text });
  });

  it("tells exports from plain lists by their head", () => {
    expect(inspectImport('{"picket_feed_export":1,"exported_at":"t","feed":{"id":"f","format":"hosts","category":"security"},"entries":[{"raw":"x"').declared).toMatchObject({ id: "f", format: "hosts", category: "security" });
    const header = "! picket-feed-export: 1\n! feed: sec-a\n! name: Sec A\n! format: adblock\n! format_options: {}\n! category: security\n! warn_on: null\n! picket-first-seen: 2026-11-23\n||x^\n";
    expect(inspectImport(header)).toEqual({ kind: "file-export", declared: expect.objectContaining({ id: "sec-a", name: "Sec A", format: "adblock", category: "security" }) });
    expect(readHeader("# picket-feed-export: 1\n# format: hosts\n0.0.0.0 x\n")).toMatchObject({ format: "hosts" });
    expect(readHeader("! Title: some list\n||x^\n")).toBeNull();
    expect(inspectImport('{"name":"n","type":"string","picket_feed":{"id":"w","category":"mixed"},"list":["a","b"')).toEqual({
      kind: "misp-export",
      declared: expect.objectContaining({ id: "w", format: "misp-warninglist", category: "mixed" }),
    });
    expect(inspectImport('{"description":"d","list":["a.example",').kind).toBe("misp-list");
    expect(inspectImport("ads.example\n").kind).toBe("list");
    expect(topLevelKeys('{"a":"x\\"y","b":{"c":[1,"}"]},"d":[')?.keys).toEqual(["a", "b", "d"]);
  });
});

describe("settings saves", () => {
  it("send only the changed top-level keys", () => {
    const a = { web: { port: 8443 }, retention: { metrics: "3d" } } as unknown as Settings;
    const b = { web: { port: 8443 }, retention: { metrics: "1d" } } as unknown as Settings;
    expect(settingsPatch(a, b, ["web", "retention"])).toEqual({ retention: { metrics: "1d" } });
  });
});

describe("profile endpoints", () => {
  it("builds DoH URLs and DoT names from assigned listeners", () => {
    const out = profileEndpoints("kids", [
      { id: "doh", proto: "doh", bind: "192.168.1.1:443", tls: { managed: "dns.home.arpa" }, edges: ["e1"] },
      { id: "doh2", proto: "doh", bind: "192.168.1.1:8443", edges: ["e1"] },
      { id: "dot", proto: "dot", bind: "[::]:853", tls: { managed: "dot.home.arpa" }, edges: ["e1"] },
      { id: "unassigned", proto: "doh", bind: "10.0.0.1:443", edges: [] },
    ]);
    expect(out.map((e) => e.value)).toEqual(["https://dns.home.arpa/dns-query/kids", "https://192.168.1.1:8443/dns-query/kids", "kids.dot.home.arpa"]);
  });
});
