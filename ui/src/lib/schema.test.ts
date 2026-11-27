import { describe, expect, it } from "vitest";
import dns from "@/test/fixtures/dns-module-schema.json";
import { openapiRoot } from "./openapi";
import { activeWarning, classify, collectWarnings, defaultValue, matchVariant, validate, type SchemaRoot } from "./schema";

const dnsRoot = dns as unknown as SchemaRoot;
const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` });

describe("classify", () => {
  it("reads `type: [T, null]` as a nullable T", () => {
    const c = classify((dnsRoot.$defs as Record<string, unknown>).RawServer as never, dnsRoot);
    expect(c.kind).toBe("object");
    const port = classify(c.schema.properties!.port, dnsRoot);
    expect(port).toMatchObject({ kind: "integer", nullable: true });
  });

  it("reads anyOf [X, null] as a nullable X, keeping the reference's fields", () => {
    const c = classify((dnsRoot.properties as Record<string, unknown>).self_test as never, dnsRoot);
    expect(c.kind).toBe("object");
    expect(c.nullable).toBe(true);
    expect(Object.keys(c.schema.properties ?? {})).toEqual(["name", "expect", "cron"]);
  });

  it("flattens oneOf of consts and enums into one enum (BlockResponseType)", () => {
    const c = classify(ref("BlockResponseType"), openapiRoot);
    expect(c.kind).toBe("enum");
    expect(c.options?.map((o) => o.value)).toEqual(["nxdomain", "nodata", "refused", "null_ip", "custom_ip"]);
    expect(c.options?.find((o) => o.value === "custom_ip")?.description).toMatch(/ipv4/);
  });

  it("finds the tag of a tagged union (a feed provider's trigger)", () => {
    const c = classify(ref("Trigger"), openapiRoot);
    expect(c.kind).toBe("union");
    expect(c.tag).toBe("kind");
    expect(matchVariant(c, { kind: "cron", cron: "0 * * * *" })).toBe(1);
    expect(matchVariant(c, { kind: "sqs" })).toBe(2);
  });

  it("handles a union of a const and an object (core's resolver)", () => {
    const c = classify(ref("Resolver"), openapiRoot);
    expect(c.kind).toBe("union");
    expect(matchVariant(c, "system")).toBe(0);
    expect(matchVariant(c, { protocol: "dot", ip: "9.9.9.10", tls_host: "dns10.quad9.net" })).toBe(1);
  });

  it("reads rule policy options as nullable enums (null = the default)", () => {
    const rp = classify(ref("RulePolicy"), openapiRoot);
    const redirects = classify(rp.schema.properties!.redirects, openapiRoot);
    expect(redirects).toMatchObject({ kind: "enum", nullable: true });
    expect(redirects.options?.map((o) => o.value)).toEqual(["drop", "keep"]);
  });
});

describe("defaultValue", () => {
  it("fills a new profile from the schema's defaults", () => {
    const p = defaultValue(ref("ProfileDef"), openapiRoot) as Record<string, unknown>;
    expect(p.upstream).toBe("cloudflare");
    expect(p.log).toBe("full");
    expect(p.block_response).toEqual({ ttl: 10, type: "null_ip" });
    expect(p.trial_bundles).toEqual([]);
    expect(p.allowed_sources).toEqual(["0.0.0.0/0", "::/0"]);
    expect("system" in p).toBe(false); // read-only fields are core's to set
  });

  it("starts a module config with its defaults and required fields", () => {
    const v = defaultValue(dnsRoot, dnsRoot) as Record<string, unknown>;
    expect(v).toMatchObject({ transport: "dot", qtype: "A", rules: [], servers: [], self_test: null });
  });
});

describe("x-picket-warning (providers.md §1)", () => {
  it("applies while the field holds a listed value", () => {
    const transport = classify((dnsRoot.properties as Record<string, unknown>).transport as never, dnsRoot).schema;
    expect(activeWarning(transport, "udp")).toMatch(/^Plain DNS is unencrypted/);
    expect(activeWarning(transport, "dot")).toBeNull();
  });
  it("is collected across a whole config, for marking providers in lists", () => {
    expect(collectWarnings(dnsRoot, { transport: "tcp", servers: [] }, dnsRoot)).toHaveLength(1);
    expect(collectWarnings(dnsRoot, { transport: "doh", servers: [] }, dnsRoot)).toHaveLength(0);
  });
});

describe("validate", () => {
  it("checks required fields, bounds, patterns and item counts", () => {
    const errs = validate(dnsRoot, { servers: [{ ip: "", port: 70000 }], rules: [{ id: "Bad Id", when: {}, verdict: "block" }] }, dnsRoot);
    expect(errs["servers.0.ip"]).toBe("Required.");
    expect(errs["servers.0.port"]).toBe("At most 65535.");
    expect(errs["rules.0.id"]).toMatch(/Doesn't match/);
  });
  it("leaves nullable and defaulted fields to core", () => {
    expect(validate(dnsRoot, { servers: [{ ip: "9.9.9.9", port: null }] }, dnsRoot)).toEqual({});
  });
});
