// What core accepts, for the test mocks: every request a test makes is checked against core's
// OpenAPI document (paths, query parameters, request bodies) and the rules core applies on top of
// it that matter to the UI (ids it refuses, enums its query types take). A mock that answers 2xx
// to a request core would refuse makes the test fail, so hand-written routes can't hide a body or
// query core would answer with 422.
import doc from "@/api/openapi.json";
import { isNotBuiltEndpoint } from "@/api/availability";
import { parseDuration } from "@/lib/format";

type Schema = Record<string, unknown>;

const root = doc as unknown as { paths: Record<string, Record<string, Schema>>; components: { schemas: Record<string, Schema> } };
const PREFIX = "/api/ui/v1";

interface Op {
  template: string;
  op: Schema;
}

/** The OpenAPI operation for a method and path (after /api/ui/v1), preferring literal segments. */
export function findOperation(method: string, path: string): Op | null {
  const got = path.split("/").filter(Boolean);
  let best: Op | null = null;
  let bestLiterals = -1;
  for (const [full, ops] of Object.entries(root.paths)) {
    const op = ops[method.toLowerCase()];
    if (!op) continue;
    const want = full.slice(PREFIX.length).split("/").filter(Boolean);
    if (want.length !== got.length) continue;
    let literals = 0;
    let ok = true;
    for (let i = 0; i < want.length; i++) {
      if (want[i].startsWith("{")) continue;
      if (want[i] !== decodeURIComponent(got[i])) {
        ok = false;
        break;
      }
      literals++;
    }
    if (ok && literals > bestLiterals) {
      best = { template: full.slice(PREFIX.length), op };
      bestLiterals = literals;
    }
  }
  return best;
}

function resolve(s: Schema | undefined): Schema {
  let cur = s ?? {};
  for (let i = 0; i < 16 && typeof cur.$ref === "string"; i++) {
    const name = (cur.$ref as string).split("/").pop() ?? "";
    cur = root.components.schemas[name] ?? {};
  }
  return cur;
}

function typeOf(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (typeof v === "number") return Number.isInteger(v) ? "integer" : "number";
  return typeof v;
}

/** A strict JSON Schema check (types, enums, required, unknown keys where denied); errors by path. */
export function checkSchema(s0: Schema | boolean | undefined, v: unknown, path = "body", depth = 0): string[] {
  if (depth > 40) return [];
  // A boolean schema (`true`: anything, as core's document gives an untyped value).
  if (typeof s0 === "boolean") return s0 ? [] : [`${path}: not allowed`];
  const s = resolve(s0);
  const errs: string[] = [];
  for (const k of ["oneOf", "anyOf"] as const) {
    const variants = s[k] as Schema[] | undefined;
    if (variants) {
      const results = variants.map((x) => checkSchema(x, v, path, depth + 1));
      if (!results.some((r) => r.length === 0)) errs.push(`${path}: matches no variant (${results.map((r) => r[0]).join(" | ")})`);
    }
  }
  for (const x of (s.allOf as Schema[] | undefined) ?? []) errs.push(...checkSchema(x, v, path, depth + 1));
  if (s.enum && !(s.enum as unknown[]).some((e) => JSON.stringify(e) === JSON.stringify(v))) errs.push(`${path}: ${JSON.stringify(v)} isn't one of ${JSON.stringify(s.enum)}`);
  if ("const" in s && JSON.stringify(s.const) !== JSON.stringify(v)) errs.push(`${path}: must be ${JSON.stringify(s.const)}`);
  const t = s.type as string | string[] | undefined;
  if (t) {
    const types = Array.isArray(t) ? t : [t];
    const vt = typeOf(v);
    if (!types.includes(vt) && !(vt === "integer" && types.includes("number"))) {
      errs.push(`${path}: is ${vt}, not ${types.join("|")}`);
      return errs;
    }
  }
  if (typeOf(v) === "object") {
    const o = v as Record<string, unknown>;
    const props = (s.properties as Record<string, Schema> | undefined) ?? {};
    for (const r of (s.required as string[] | undefined) ?? []) if (!(r in o)) errs.push(`${path}.${r}: required`);
    for (const [k, x] of Object.entries(o)) {
      if (k in props) errs.push(...checkSchema(props[k], x, `${path}.${k}`, depth + 1));
      else if (s.additionalProperties === false) errs.push(`${path}.${k}: unknown field`);
      else if (s.additionalProperties && typeof s.additionalProperties === "object") errs.push(...checkSchema(s.additionalProperties as Schema, x, `${path}.${k}`, depth + 1));
    }
  }
  if (Array.isArray(v) && s.items) v.forEach((x, i) => errs.push(...checkSchema(s.items as Schema, x, `${path}[${i}]`, depth + 1)));
  return errs;
}

/** config/validate.rs `is_slug`. */
const isSlug = (s: string) => /^[a-z0-9][a-z0-9_-]{0,63}$/.test(s);
/** config/validate.rs `is_profile_id` (core.md §2). */
const isProfileId = (s: string) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(s) && !s.endsWith("-full");

const ENTITY_CREATES: Record<string, (id: string) => boolean> = {
  "/profiles": isProfileId,
  "/feeds": isSlug,
  "/feed-providers": isSlug,
  "/lookup-providers": isSlug,
  "/bundles": isSlug,
  "/upstreams": isSlug,
  "/upstream-groups": isSlug,
  "/listeners": isSlug,
  "/forward-zones": isSlug,
};

/**
 * A query parameter's value against its schema in core's OpenAPI document (core 720be97 types
 * its parameters: enums, whole numbers, booleans); core answers `400` otherwise. The enums the
 * tests used to model by hand (logs/api.rs, lookups/api.rs, dnssec/api.rs, feeds/transfer.rs)
 * come from the document now, and so do the bounds (core 07acc1c: every `limit` 1 to 500, 1 to
 * 100 on `top`, the backtest's `days` 1 to 60 and `k` 0.1 to 50; outside, `400 "limit: 1 to
 * 500"`, no longer clamped).
 */
function paramViolations(method: string, template: string, param: Schema, value: string): string[] {
  const s = resolve(param.schema as Schema | undefined);
  const name = String(param.name);
  const allowed = s.enum as unknown[] | undefined;
  const outside = (n: number) => (typeof s.minimum === "number" && n < s.minimum) || (typeof s.maximum === "number" && n > s.maximum);
  const range = `${method} ${template}: 400 ${name}: ${String(s.minimum ?? "")} to ${String(s.maximum ?? "")}`;
  if (allowed && !allowed.includes(value)) return [`${method} ${template}: ${name}=${value} isn't one of ${allowed.join(", ")}`];
  if (s.type === "integer") {
    if (!/^\d+$/.test(value)) return [`${method} ${template}: 400 ${name}: a whole number`];
    if (outside(Number(value))) return [range];
  }
  if (s.type === "number") {
    // serde reads an f64: a decimal number (Rust's f64 parse, not JavaScript's: no hex, no blank).
    if (!/^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/.test(value)) return [`${method} ${template}: 400 ${name}: a number`];
    if (outside(Number(value))) return [range];
  }
  if (s.type === "boolean" && value !== "true" && value !== "false") return [`${method} ${template}: 400 ${name}: true or false`];
  return [];
}

/** What a GET of a path answers in the test (its mock route, else the fixture), for rules that depend on core's state. */
export type Lookup = (path: string) => unknown;

/** feeds/transfer.rs `read_header`: a line-format file export's header keys (`feed` as `id`), or null when it isn't one. */
function readExportHeader(text: string): Record<string, unknown> | null {
  const m: Record<string, unknown> = {};
  let isExport = false;
  for (const line of text.split("\n").slice(0, 64)) {
    const t = line.trim();
    if (!t.startsWith("!") && !t.startsWith("#")) break;
    const rest = t.slice(1).trim();
    const at = rest.indexOf(":");
    if (at < 0) continue;
    const k = rest.slice(0, at).trim();
    const v = rest.slice(at + 1).trim();
    if (k === "picket-feed-export") isExport = true;
    else if (k === "picket-first-seen") break;
    else if (k === "feed") m.id = v;
    else if (["name", "provider", "format", "category", "exported_at"].includes(k)) m[k] = v;
    else if (["format_options", "rule_policy", "warn_on"].includes(k)) {
      try {
        m[k] = JSON.parse(v);
      } catch {
        // core skips a value it can't read.
      }
    }
  }
  return isExport ? m : null;
}

/**
 * What an import body is, as core's `make_file` tells it (feeds/transfer.rs): an export with the
 * settings it declares (which keys it names), a MISP warninglist without `picket_feed`, or a plain
 * list (`expected`: the format the query or the feed names, which makes a bare MISP list text).
 */
function importBodyKind(body: unknown, expected: string | null): { declared: Record<string, unknown> | null; mispList: boolean } {
  const b = body as Record<string, unknown> | null;
  if (b && typeof b === "object" && Object.keys(b)[0] === "picket_feed_export") return { declared: (b.feed as Record<string, unknown>) ?? {}, mispList: false };
  const text = typeof b?.file === "string" ? b.file.replace(/^\uFEFF/, "") : "";
  let json: unknown = null;
  if (text.trimStart().startsWith("{")) {
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
  }
  const o = json && typeof json === "object" && !Array.isArray(json) ? (json as Record<string, unknown>) : null;
  if (o?.picket_feed && typeof o.picket_feed === "object") return { declared: { ...(o.picket_feed as Record<string, unknown>), format: "misp-warninglist" }, mispList: false };
  if (o && Array.isArray(o.list) && (expected === null || expected === "misp-warninglist")) return { declared: null, mispList: true };
  return { declared: readExportHeader(text), mispList: false };
}

const warnList = (q: string) => q.split(",").map((x) => x.trim()).filter(Boolean);
/** feeds/transfer.rs `same_bundles`: two `warn_on` lists name the same warn bundles (a set: order and repeats aside). */
const sameBundles = (a: string[], b: string[]) => {
  const x = new Set(a);
  const y = new Set(b);
  return x.size === y.size && [...x].every((v) => y.has(v));
};
/** config/model.rs `RulePolicy::resolved`: a left-out switch is `keep` on a manual feed, `drop` on a provider feed (`browser_changes`: `keep`). */
const resolvedPolicy = (rp: Record<string, string | null | undefined>, k: string, manual: boolean) => rp[k] ?? (manual || k === "browser_changes" ? "keep" : "drop");

/**
 * `POST feeds/import` (feeds/transfer.rs `new_manual_def`): a query setting that differs from one
 * the export declares is `422` naming the field (equal is fine; one the export leaves out fills
 * it); a format named for a bare MISP list makes core read it as text in that format.
 */
function newFeedConflicts(query: URLSearchParams, body: unknown): string[] {
  const out: string[] = [];
  const { declared: d, mispList } = importBodyKind(body, query.get("format"));
  const refuse = (field: string, why: string) => out.push(`POST /feeds/import: 422 (field ${field}): ${why}`);
  const b = body as Record<string, unknown> | null;
  if (query.has("format") && !d && !mispList && typeof b?.file === "string" && /^\s*\{/.test(b.file)) {
    try {
      if (Array.isArray((JSON.parse(b.file) as { list?: unknown }).list)) out.push("POST /feeds/import: format given for a MISP warninglist: core reads it as text in that format");
    } catch {
      // Not JSON: a plain list.
    }
  }
  if (!d) return out;
  const has = (k: string) => k in d;
  const q = (k: string) => query.get(k);
  if (q("format") !== null && has("format") && q("format") !== d.format) refuse("format", `the export declares ${String(d.format)}`);
  const fo = (d.format_options ?? {}) as { domains_as?: string | null };
  if (q("domains_as") !== null && has("format_options") && q("domains_as") !== (fo.domains_as ?? "exact")) refuse("format_options", `the export declares domains_as ${fo.domains_as ?? "exact"}`);
  if (q("category") !== null && has("category") && q("category") !== d.category) refuse("category", `the export declares ${String(d.category)}`);
  if (q("warn_on") !== null && has("warn_on")) {
    const category = q("category") ?? (typeof d.category === "string" ? d.category : "mixed");
    const applied = (Array.isArray(d.warn_on) ? d.warn_on : category === "security" ? ["warn-common"] : []) as string[];
    if (!sameBundles(applied, warnList(q("warn_on") ?? ""))) refuse("warn_on", `the export's applies as ${JSON.stringify(applied)}`);
  }
  if (has("rule_policy")) {
    // As it applies to the new (manual) feed.
    const rp = (d.rule_policy ?? {}) as Record<string, string | null | undefined>;
    for (const k of ["redirects", "client_rules", "browser_changes"]) {
      if (q(k) !== null && q(k) !== resolvedPolicy(rp, k, true)) refuse("rule_policy", `the export declares ${k} ${resolvedPolicy(rp, k, true)}`);
    }
  }
  return out;
}

/**
 * `POST feeds/{id}/import` (feeds/transfer.rs `existing_query`, `same_format`): each setting the
 * query names must be the feed's own, an export (or a bare MISP list) must have the feed's format
 * and `format_options`, a MISP export goes only into a `misp-warninglist` feed, and a provider feed
 * takes no `replace`; else `422`.
 */
function intoFeedConflicts(path: string, query: URLSearchParams, body: unknown, lookup?: Lookup): string[] {
  const out: string[] = [];
  const refuse = (why: string) => out.push(`POST /feeds/{id}/import: 422${why.startsWith("(") ? " " : ": "}${why}`);
  const def = lookup?.(path.replace(/\/import$/, "")) as
    | {
        format?: string;
        format_options?: { domains_as?: string | null };
        provider?: string | null;
        category?: string;
        warn_on?: string[] | null;
        rule_policy?: Record<string, string | null | undefined>;
      }
    | undefined;
  const format = def?.format ?? query.get("format");
  const { declared: d } = importBodyKind(body, format ?? null);
  if (d && typeof d.format === "string" && query.has("format") && d.format !== query.get("format")) refuse(`the query says format ${query.get("format")} and the export ${d.format}`);
  if (!def) return out;
  if (def.provider && query.get("mode") === "replace") refuse("replace on a provider feed");
  if (query.has("format") && query.get("format") !== def.format) refuse(`(field format): the feed's is ${String(def.format)}`);
  if (query.has("domains_as") && query.get("domains_as") !== (def.format_options?.domains_as ?? "exact")) refuse(`(field format_options): the feed's domains_as is ${def.format_options?.domains_as ?? "exact"}`);
  if (d && typeof d.format === "string" && d.format !== def.format) refuse(`the export's format ${d.format} isn't the feed's ${String(def.format)}`);
  // A fixture that leaves a setting out says nothing about it (core always returns every field).
  // same_format compares an export's options as they are (FormatOptions equality: a left-out
  // domains_as isn't `exact`). A bare MISP list has the default options, which every MISP feed has
  // (domains_as is plain-only, config/validate.rs).
  const declaredOptions = (d?.format_options ?? {}) as { domains_as?: string | null };
  if (d && def.format_options !== undefined && (declaredOptions.domains_as ?? null) !== (def.format_options.domains_as ?? null)) {
    refuse(`the import's format_options ${JSON.stringify(declaredOptions)} differ from the feed's ${JSON.stringify(def.format_options)}`);
  }
  // The other settings the query may name (core 768d30b): each must be the feed's own; warn_on
  // compares as a set, as it applies (null follows the category), the rule policy as it applies.
  const category = def.category;
  if (category !== undefined && query.has("category") && query.get("category") !== category) refuse(`(field category): the feed's is ${category}`);
  if (category !== undefined && def.warn_on !== undefined && query.has("warn_on")) {
    const applied = def.warn_on ?? (category === "security" ? ["warn-common"] : []);
    if (!sameBundles(warnList(query.get("warn_on") ?? ""), applied)) refuse(`(field warn_on): the feed's is ${JSON.stringify(applied)}`);
  }
  if (def.rule_policy !== undefined) {
    for (const k of ["redirects", "client_rules", "browser_changes"]) {
      const own = resolvedPolicy(def.rule_policy, k, !def.provider);
      if (query.has(k) && query.get(k) !== own) refuse(`(field rule_policy.${k}): the feed's is ${own}`);
    }
  }
  return out;
}

/** F2: `warn_on` names warn bundles (core validates the new feed as an entity: 422, field warn_on). */
function warnOnRefused(query: URLSearchParams, lookup?: Lookup): string[] {
  const w = query.get("warn_on");
  if (w === null || !lookup) return [];
  const page = lookup("/bundles") as { items?: { id?: string; action?: string }[] } | undefined;
  const warn = new Set((page?.items ?? []).filter((b) => b.action === "warn").map((b) => b.id));
  return warnList(w)
    .filter((b) => !warn.has(b))
    .map((b) => `POST /feeds/import: 422 (field warn_on): ${JSON.stringify(b)} isn't a warn bundle`);
}


/**
 * web/api.rs `decode_cursor`: a cursor is unpadded URL-safe base64 (the base64 crate's
 * URL_SAFE_NO_PAD, which also refuses non-zero trailing bits) of UTF-8 text; else `400 bad cursor`.
 */
export function isCoreCursor(c: string): boolean {
  if (!/^[A-Za-z0-9_-]*$/.test(c) || c.length % 4 === 1) return false;
  const digit = (ch: string) => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".indexOf(ch);
  const extra = c.length % 4;
  if (extra && digit(c[c.length - 1]) & (extra === 2 ? 0b1111 : 0b11)) return false;
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(c, "base64url"));
    return true;
  } catch {
    return false;
  }
}
const isRfc3339 = (v: string) => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/i.test(v) && !Number.isNaN(Date.parse(v));
const printable = (v: string, max: number) => v.trim().length <= max && !/\p{Cc}/u.test(v);

/** What a test's core (its `/settings` mock or fixture) keeps the query log for, in seconds (default 72 h). */
function queryLogRetention(lookup?: Lookup): number {
  const s = lookup?.("/settings") as { settings?: { retention?: { query_logs?: string } } } | undefined;
  return parseDuration(s?.settings?.retention?.query_logs) ?? 72 * 3600;
}

/** A test's core's settings view (`/settings`: the settings and the LAN CA's state). */
type SettingsLookup =
  | { settings?: { lanca?: { zones?: string[] }; web?: { names?: string[] } }; lanca?: { zones?: string[]; fingerprint?: string; previous?: unknown[]; clock_synced?: boolean } }
  | undefined;

/** The LAN CA's zones of a test's core (the settings' LAN CA view, else `/identity`, else the settings), when the test names them. */
function lancaZones(lookup?: Lookup): string[] | null {
  const s = lookup?.("/settings") as SettingsLookup;
  if (s?.lanca?.zones) return s.lanca.zones;
  const id = lookup?.("/identity") as { lanca_zones?: string[] } | undefined;
  if (id?.lanca_zones) return id.lanca_zones;
  return s?.settings?.lanca?.zones ?? null;
}

/** lanca::normalize_zones, as far as equality goes: trimmed, lowercase, no trailing dot, sorted, deduplicated. */
const normZones = (z: unknown) => (Array.isArray(z) ? [...new Set(z.map((x) => String(x).trim().toLowerCase().replace(/\.$/, "")))].sort() : null);

/** lanca::is_dns_name, roughly: labels of letters, digits and hyphens, not starting or ending with a hyphen. */
const isDnsName = (z: string) => z.length <= 253 && z.split(".").every((l) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l));
/** Public suffixes core refuses as zones (psl.rs; a few of the bundled list, home.arpa excepted). */
const PUBLIC_SUFFIXES = new Set(["com", "net", "org", "io", "de", "uk", "co.uk", "arpa", "github.io"]);
/** lanca::name_under_zones: a name (a leading `*.` allowed) that is a zone or under one. */
const nameUnderZones = (name: string, zones: string[]) => {
  const n = name.toLowerCase().replace(/\.$/, "").replace(/^\*\./, "");
  return zones.some((z) => n === z || n.endsWith(`.${z}`));
};

/**
 * PUT settings with other `lanca.zones` rotates the LAN CA root (lanca::rotation; web/api.rs
 * `put_settings`, core c58ba80), in core's order: zones core can't take are `422` (not DNS names, a
 * public suffix, none); the same zones (as sets, a form saving the whole object) pass and
 * `lanca.rotate_from` is ignored then; other zones need `lanca.rotate_from` (`422` without it, with
 * null, which core takes as left out, or when it isn't a string) naming the current root (`409
 * lanca_root_changed` when the settings' `lanca.fingerprint` is another: a change replaced it, core
 * 07acc1c); then `503` while core's clock isn't synchronised (`lanca.clock_synced` false), `409
 * conflict` while a previous root is still in use (`lanca.previous`), and `422` when a managed
 * listener name or `web.names` (the patch's, else the settings') wouldn't be under the new zones.
 * A 409's code comes after its status (`409 conflict: …`): a mock answering another code fails
 * (`refusalViolations`).
 */
function zonesRefusals(body: unknown, lookup: Lookup | undefined, bad: (status: number, why: string) => void) {
  const b = body as Record<string, unknown> | null;
  const lanca = b?.lanca as { zones?: unknown; rotate_from?: unknown } | undefined;
  const wanted = lanca?.zones ?? b?.["lanca.zones"];
  if (wanted === undefined || wanted === null) return;
  if (!Array.isArray(wanted) || wanted.some((z) => typeof z !== "string")) return bad(422, "lanca.zones is a list of DNS names");
  const zones = normZones(wanted) ?? [];
  if (zones.length === 0) return bad(422, "lanca.zones needs at least one zone");
  const notName = zones.find((z) => !isDnsName(z));
  if (notName !== undefined) return bad(422, `lanca zone ${JSON.stringify(notName)} is not a DNS name`);
  const suffix = zones.find((z) => z !== "home.arpa" && PUBLIC_SUFFIXES.has(z));
  if (suffix !== undefined) return bad(422, `lanca zone ${JSON.stringify(suffix)} is a public suffix`);
  if (JSON.stringify(zones) === JSON.stringify(normZones(lancaZones(lookup) ?? ["home.arpa"]))) return;
  const s = lookup?.("/settings") as SettingsLookup;
  const from = lanca?.rotate_from ?? b?.["lanca.rotate_from"] ?? null;
  if (from === null) return bad(422, "lanca.zones would replace the LAN CA root: send lanca.rotate_from with the current root's fingerprint");
  if (typeof from !== "string") return bad(422, "lanca.rotate_from is the current LAN CA root's fingerprint (SHA256:…)");
  if (s?.lanca?.fingerprint !== undefined && from !== s.lanca.fingerprint) return bad(409, `lanca_root_changed: lanca.rotate_from names ${from}, but the LAN CA root is ${s.lanca.fingerprint} now`);
  if (s?.lanca?.clock_synced === false) return bad(503, "the wall clock isn't synchronised yet");
  if ((s?.lanca?.previous ?? []).length > 0) return bad(409, "conflict: the previous LAN CA root is still in use");
  const listeners = (lookup?.("/listeners") as { items?: { id?: string; tls?: { managed?: string | null } | null }[] } | undefined)?.items ?? [];
  const webNames = ((b?.web as { names?: string[] } | undefined)?.names ?? s?.settings?.web?.names ?? []) as string[];
  const lost = [
    ...listeners.filter((l) => l.tls?.managed && !nameUnderZones(l.tls.managed, zones)).map((l) => `${l.tls?.managed} (listener ${l.id})`),
    ...webNames.filter((n) => !nameUnderZones(n, zones)).map((n) => `${n} (web.names)`),
  ];
  if (lost.length) bad(422, `lanca.zones ${zones.join(", ")} would orphan names in use: ${lost.join(", ")}`);
}

/**
 * logs/query.rs `evidence` (core c58ba80): the `next_cursor` of an earlier page, URL-safe base64 of
 * the last copy's row id (a whole number, i64); core 720be97's cursors (an event time and a row id)
 * and anything else are `400 bad cursor`.
 */
export function isEvidenceCursor(c: string): boolean {
  if (!isCoreCursor(c)) return false;
  const text = Buffer.from(c, "base64url").toString("utf8");
  if (!/^[+-]?\d+$/.test(text)) return false;
  const n = BigInt(text);
  return n >= -(2n ** 63n) && n < 2n ** 63n;
}

/**
 * The refusals core's handlers give on endpoints whose error answers the UI tells apart (status
 * and error `code`; web/error.rs): a mock answering one of these statuses with a code core can't
 * give there, or a status core's handler never gives there, fails the test, as a 2xx core would
 * refuse does. Other statuses pass (401, 413, 429, 500 and the like come from layers in front of
 * every handler), and so does a 503 without a JSON error (the auth layer's plain-text "too many
 * password checks").
 * - PUT settings: `409 lanca_root_changed` (a replaced root) or `conflict` (a previous root in use;
 *   core 07acc1c: when the request's state says which, `zonesRefusals`, only that one), `422
 *   invalid` (bad zones, no, a null or a malformed `lanca.rotate_from`, orphaned names) or
 *   `validation` (the patch against the model), `503 unavailable` (core's clock isn't synchronised);
 * - Test now (lookups/api.rs `test_now`, core c58ba80): `404 not_found` (no such provider in
 *   core.db), `409 conflict` "provider is being reloaded" (the lookup runtime hasn't reached the
 *   committed config within its bounded wait), `422 invalid` (the module names no self-test),
 *   `503 busy` (the light lane is full);
 * - an alert's evidence: `400 bad_request` (a limit or cursor core didn't give), `404 not_found`.
 */
const REFUSALS: Record<string, Record<number, string[]>> = {
  "PUT /settings": { 400: ["bad_request"], 404: [], 409: ["lanca_root_changed", "conflict"], 422: ["invalid", "validation"], 503: ["unavailable"] },
  "POST /lookup-providers/{id}/test": { 400: ["bad_request"], 404: ["not_found"], 409: ["conflict"], 422: ["invalid"], 503: ["busy"] },
  "GET /alerts/{id}/evidence": { 400: ["bad_request"], 404: ["not_found"], 409: [], 422: [] },
};

/** Core's Test now answer while its lookup runtime hasn't reached the committed config (lookups/api.rs `committed_in_runtime`). */
export const TEST_NOW_RELOADING = { status: 409, body: { error: { code: "conflict", message: "provider is being reloaded" } } } as const;

/**
 * What's wrong with a mock's error answer for an endpoint whose refusals REFUSALS models; `[]`
 * otherwise. `predicted` is what the contract says core would refuse in the request
 * (`contractViolations`): where it names the code core answers with that status (`409 conflict: …`),
 * the mock must answer that code.
 */
export function refusalViolations(method: string, path: string, status: number, body: unknown, predicted: string[] = []): string[] {
  const found = findOperation(method, path);
  const known = found ? REFUSALS[`${method} ${found.template}`] : undefined;
  if (!known || !(status in known)) return [];
  const code = (body as { error?: { code?: unknown } } | null)?.error?.code;
  if (status === 503 && code === undefined) return [];
  const codes = known[status];
  if (codes.length === 0) return [`${method} ${found!.template}: core's handler never answers ${status}`];
  if (typeof code !== "string" || !codes.includes(code)) return [`${method} ${found!.template}: core's ${status} has code ${codes.join(" or ")}, not ${JSON.stringify(code)}`];
  const want = predicted.map((v) => new RegExp(`^\\S+ \\S+: ${status} ([a-z_]+): `).exec(v)?.[1]).find((c) => c !== undefined && codes.includes(c));
  if (want !== undefined && code !== want) return [`${method} ${found!.template}: core answers this request ${status} ${want}, not ${JSON.stringify(code)}`];
  return [];
}

/**
 * The UI events whose frames a test's fake socket checks against core's `UiEventFrame` (strict:
 * required fields, enums, no unknown fields where the document denies them): the LAN CA's
 * (`lanca` with its `LancaEventKind` and `previous`, `lanca_served`), the DNSSEC queue's
 * (`dnssec_queued`), `restore` with its generation (core 07acc1c), `job` with its `run` and
 * `dropped`, and the coalesced `alert` and `feed_run` with their bounded lists (core a3eb6d5:
 * test/events.ts builds them; `listViolations`). Others are emitted partly by tests on purpose (the
 * UI reads them defensively) and aren't checked.
 */
const CHECKED_EVENTS = new Set(["lanca", "lanca_served", "dnssec_queued", "restore", "job", "alert", "feed_run"]);

/** Core's bound on an `alert` event's `alerts` and a `feed_run` event's `runs` (web/events.rs MAX_EVENT_ALERTS, MAX_EVENT_RUNS). */
const MAX_EVENT_LIST = 64;

/**
 * How core fills a coalesced list (web/events.rs `Coalesced`): each alert once and each run once,
 * at most 64; past that the event says it is truncated, with 64 listed and more changes counted
 * (`changes`, `stored`). An event that lists all has at least one item: every alert change lists
 * its alert (a change counted but not listed truncates the list) and every run stored is listed.
 * (Core lists fewer than 64 in a truncated `alert` event only when it can't read the alerts whose
 * evidence changed; no test models that.)
 */
function listViolations(type: string, data: Record<string, unknown>): string[] {
  const [items, truncated, count, key] =
    type === "alert" ? [data.alerts as { id: number }[], data.alerts_truncated, data.changes as number, "id"] : [data.runs as { run: number }[], data.runs_truncated, data.stored as number, "run"];
  const n = items.length;
  const out: string[] = [];
  const what = `event ${type}: ${n} listed`;
  if (new Set(items.map((x) => (x as Record<string, unknown>)[key])).size !== n) out.push(`${what}, one ${key} more than once`);
  if (truncated) {
    if (n !== MAX_EVENT_LIST) out.push(`${what} in a truncated list (core lists ${MAX_EVENT_LIST})`);
    if (count <= n) out.push(`${what} in a truncated list, counting ${count}`);
  } else {
    if (n === 0 || n > MAX_EVENT_LIST) out.push(`${what} in a list that isn't truncated`);
    if (type === "alert" ? count < n : count !== n) out.push(`${what}, counting ${count}`);
  }
  return out;
}

/** What's wrong with a UI event frame a test emits (CHECKED_EVENTS), as core's document types it and core fills it; `[]` otherwise. */
export function eventViolations(frame: unknown): string[] {
  const type = (frame as { type?: unknown } | null)?.type;
  if (typeof type !== "string" || !CHECKED_EVENTS.has(type)) return [];
  const found = checkSchema({ $ref: "#/components/schemas/UiEventFrame" }, frame, `event ${type}`);
  if (found.length || (type !== "alert" && type !== "feed_run")) return found;
  return listViolations(type, (frame as { data: Record<string, unknown> }).data);
}

/**
 * Successful answers a mock must give in core's shape (the document's response schema), where the
 * UI reads a field core added: a restore's `generation` (core 07acc1c), which tells the restoring
 * tab its own `restore` event.
 */
const CHECKED_ANSWERS: Record<string, string> = { "PUT /config/export": "RestoreResult" };

/** What's wrong with a mock's 2xx answer for an endpoint in CHECKED_ANSWERS; `[]` otherwise. */
export function answerViolations(method: string, path: string, status: number, body: unknown): string[] {
  const found = findOperation(method, path);
  const schema = found && status < 300 ? CHECKED_ANSWERS[`${method} ${found.template}`] : undefined;
  return schema ? checkSchema({ $ref: `#/components/schemas/${schema}` }, body, "answer").map((e) => `${method} ${found!.template}: ${e}`) : [];
}

/**
 * The wave-5 endpoints' own refusals beyond what core's OpenAPI document types (core 720be97):
 * logs/api.rs and logs/query.rs (400 for a bad time or name, 422 for a window past the query-log
 * retention), lookups/api.rs, dnssec/api.rs, config/export.rs (the restore's format, zones and
 * size), lookups/api.rs's temp-allows cursor (400), the evidence's cursor (400), a provider's
 * listing's prefix, `q` and cursor (400) and PUT settings' lanca.zones (a rotation's
 * lanca.rotate_from, 422, 409 and 503). The limits' bounds are the document's now
 * (`paramViolations`).
 */
function waveFiveRefusals(method: string, template: string, query: URLSearchParams, body: unknown, lookup?: Lookup): string[] {
  const out: string[] = [];
  const q = (k: string) => query.get(k);
  const bad = (status: number, why: string) => out.push(`${method} ${template}: ${status} ${why}`);
  // The window's values are the document's enum (contractViolations); past the retention is 422.
  const window = () => {
    const secs = ({ "1h": 3600, "6h": 21600, "24h": 86400, "72h": 259200 } as Record<string, number>)[q("window") ?? "24h"];
    if (secs !== undefined && secs > queryLogRetention(lookup)) bad(422, "the window is longer than the query-log retention");
  };
  if (method === "GET") {
    switch (template) {
      case "/logs":
        for (const k of ["from", "to"]) if (q(k) && !isRfc3339(q(k) ?? "")) bad(400, `${k}: an RFC 3339 time`);
        for (const [k, max] of [["edge", 256], ["client", 64], ["device", 256], ["qname", 253], ["profile", 128], ["bundle", 128]] as const) {
          if (q(k) !== null && !printable(q(k) ?? "", max)) bad(400, `${k}: at most ${max} printable characters`);
        }
        break;
      case "/top":
        window();
        break;
      case "/query-summary": {
        const d = q("device") || null;
        const p = q("profile") || null;
        if (!((d && !p && d.length <= 256) || (p && !d && p.length <= 128))) bad(400, "name one device or one profile");
        window();
        break;
      }
      case "/trial-results":
        // Both required (the document says so); each an id.
        for (const k of ["profile", "bundle"]) if (q(k) !== null && (q(k) === "" || (q(k) ?? "").length > 128)) bad(400, "profile and bundle: ids");
        window();
        break;
      case "/temp-allows":
        if (q("cursor") !== null && !isCoreCursor(q("cursor") ?? "")) bad(400, "bad cursor");
        break;
      case "/feed-providers/{id}/listing":
        // feeds/api.rs `provider_listing`: `prefix` at most 4,096 bytes, `q` at most 256 characters, the cursor a key as web/api.rs encodes it (`delimiter` is the document's enum).
        if (new TextEncoder().encode(q("prefix") ?? "").length > 4096) bad(400, "prefix: at most 4096 bytes");
        if ([...(q("q") ?? "")].length > 256) bad(400, "q: at most 256 characters");
        if (q("cursor") !== null && !isCoreCursor(q("cursor") ?? "")) bad(400, "bad cursor");
        break;
      case "/dnssec/results":
        if (q("cursor") !== null && !/^-?\d+$/.test(q("cursor") ?? "")) bad(400, "cursor isn't one this API gave");
        break;
      case "/alerts/{id}/evidence":
        if (q("cursor") !== null && !isEvidenceCursor(q("cursor") ?? "")) bad(400, "bad cursor");
        break;
    }
  }
  if (method === "POST" && template === "/lookup-modules/{module}/presets/{preset}" && JSON.stringify(body ?? null).length > 64 * 1024) bad(422, "preset parameters are limited to 64 KiB");
  if (method === "PUT" && template === "/settings") zonesRefusals(body, lookup, bad);
  if (method === "PUT" && template === "/config/export") {
    const doc = body as { format_version?: unknown; configuration?: { settings?: Record<string, unknown> } } | null;
    if (!doc || typeof doc !== "object" || Array.isArray(doc)) bad(422, "the body isn't a config export document");
    else {
      // stream.rs reads format_version as a u32 (a missing one is "missing field"); export.rs
      // `check_head` refuses 0 and a newer format.
      if (!("format_version" in doc)) bad(422, "format_version: required");
      else if (typeof doc.format_version !== "number" || !Number.isInteger(doc.format_version) || doc.format_version < 0 || doc.format_version > 0xffffffff) bad(422, "format_version: a whole number");
      else if (doc.format_version === 0) bad(422, "an export of format 0 (this release reads formats 1 to 1)");
      else if (doc.format_version > 1) bad(422, "the document is from a newer release");
      const zones = doc.configuration?.settings?.["lanca.zones"];
      const have = lancaZones(lookup);
      if (zones !== undefined && have && JSON.stringify(normZones(zones)) !== JSON.stringify(normZones(have))) bad(422, "the document's lanca.zones differ from this instance's");
    }
  }
  return out;
}

/** What core would refuse (or, for a write's query parameter, ignore) in a request; `lookup` answers GETs for rules that need core's state. */
export function contractViolations(method: string, path: string, query: URLSearchParams, body: unknown, lookup?: Lookup): string[] {
  if (!path.startsWith("/") || path.startsWith("/events")) return [];
  const found = findOperation(method, path);
  if (!found) return isNotBuiltEndpoint(path) ? [] : [`${method} ${path}: core serves no such endpoint`];
  const out: string[] = [];
  const params = ((found.op.parameters as Schema[] | undefined) ?? []).filter((p) => p.in === "query");
  const byName = new Map(params.map((p) => [p.name as string, p]));
  for (const [k, v] of query) {
    // Core ignores a query parameter it doesn't take: on a write that loses what the UI meant, on
    // a read it answers something else than asked (untyped `request()` calls aren't checked by
    // the generated client's types).
    const param = byName.get(k);
    if (!param) out.push(`${method} ${found.template}: core ignores the query parameter ${k}`);
    else out.push(...paramViolations(method, found.template, param, v));
  }
  for (const p of params) if (p.required === true && !query.has(p.name as string)) out.push(`${method} ${found.template}: 400 ${String(p.name)} is required`);
  if (found.template === "/feeds/import" && query.has("id") && !isSlug(query.get("id") ?? "")) out.push(`POST /feeds/import: id ${JSON.stringify(query.get("id"))} isn't a valid id`);
  if (found.template === "/feeds/import" && method === "POST") out.push(...newFeedConflicts(query, body), ...warnOnRefused(query, lookup));
  if (found.template === "/feeds/{id}/import" && method === "POST") out.push(...intoFeedConflicts(path, query, body, lookup));
  out.push(...waveFiveRefusals(method, found.template, query, body, lookup));
  const reqBody = found.op.requestBody as Schema | undefined;
  const schema = (reqBody?.content as Record<string, { schema?: Schema }> | undefined)?.["application/json"]?.schema;
  if (method !== "GET" && method !== "DELETE" && schema) out.push(...checkSchema(schema, body).map((e) => `${method} ${found.template}: ${e}`));
  if (found.template === "/feeds/import" || found.template === "/feeds/{id}/import") {
    const b = body as Record<string, unknown> | null;
    const keys = b && typeof b === "object" ? Object.keys(b) : [];
    if (!(keys[0] === "picket_feed_export" || (keys.length === 1 && keys[0] === "file" && typeof b?.file === "string"))) out.push(`${method} ${found.template}: the body is neither a JSON export nor {"file": "…"}`);
  }
  if (found.template === "/feeds/{id}/file/lines") {
    const lines = (body as { lines?: unknown[] } | null)?.lines ?? [];
    if (lines.some((l) => typeof l === "string" && /[\r\n]/.test(l))) out.push("POST /feeds/{id}/file/lines: a line holds a line break");
  }
  const create = method === "POST" ? ENTITY_CREATES[found.template] : undefined;
  if (create) {
    const id = (body as { id?: unknown } | null)?.id;
    if (typeof id !== "string" || id === "") out.push(`POST ${found.template}: a new entity needs an id (core derives none)`);
    else if (!create(id)) out.push(`POST ${found.template}: ${JSON.stringify(id)} isn't a valid id`);
  }
  return out;
}
