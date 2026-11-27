#!/usr/bin/env node
// Captures the wave-5 UI API answers the tests use (src/test/fixtures/w5.json, read by
// src/test/core-w5.ts) from a real picket-core with data: manual feeds in a block bundle and a
// trial bundle, a profile that alerts on security feeds, a client, a lookup provider, and log
// records posted through the edge API by a fake edge (an Ed25519 identity, as core's tests make).
// Since core 720be97 also: the UI events core sends meanwhile (`events`), the fake edge's session
// (hello, heartbeats acknowledging a revoke: a `revoked` allow), devices with their MACs, evidence
// pages, the per-edge trial metric, and a LAN CA rotation with core's refusals (names the new
// zones wouldn't cover, a public suffix, a previous root still in use) and the root's use ending.
// Since core c58ba80 also: rotations name `lanca.rotate_from` (refusals without it and with a
// stale one), the edge reports the root behind its listener's certificate (`cert_roots`), a block
// by a sync lookup provider (`category_blocked` with `details.providers`), a second edge whose copy
// makes an alert one of several edges (`edge` null) and is stored after newer ones (evidence pages
// go newest stored first), an old-format evidence cursor (400), and a second throwaway core whose
// clock isn't synchronised (`clock_synced` false, a rotation's 503: run under `unshare -rm` with
// systemd-timesyncd's flag hidden and a `timedatectl` that says no).
// Since core 07acc1c also: a device keyed by a client name no entry has and one whose entry lists
// no MACs (both `mac` null: core no longer infers one), the lookup block's record (a decimal
// `score`), every `limit` and the backtest's `days` and `k` out of range (400, `limits`), a
// rotation with `lanca.rotate_from` null (422, as left out), `lanca_root_changed` for a replaced
// root, and the `dnssec_queued` and `lanca_served` events.
// Since core a3eb6d5 also: the coalesced `alert` and `feed_run` events, with a burst of alerts
// raised and bulk-deleted that makes `alert` events list only some (`alerts_truncated`), and
// `dnssec_queued` counting every queue change.
// Node built-ins, the openssl and unshare CLIs only. It starts a throwaway core on ports
// 18963/18964 (the unsynchronised one on 18965/18966) and stops it at the end.
//
// Usage: node ui/scripts/capture-w5.mjs <picket-core binary> <empty work dir> <out.json>
// Then replace the work dir's path in out.json (core_disk_low names it) before saving it as
// src/test/fixtures/w5.json.
import { spawn, execFileSync } from "node:child_process";
import https from "node:https";
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import crypto from "node:crypto";

// A minimal BLAKE3 (hash mode) for inputs of one chunk (≤ 1024 bytes): an answer record's id is
// the first 16 hex characters of its wire's BLAKE3 (api.md §5), which core checks. Checked against
// the reference test vectors below.
const IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;
function g(s, a, b, c, d, x, y) {
  s[a] = (s[a] + s[b] + x) >>> 0; s[d] = rotr(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotr(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b] + y) >>> 0; s[d] = rotr(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotr(s[b] ^ s[c], 7);
}
function compress(cv, m, counter, len, flags) {
  const s = [...cv, IV[0], IV[1], IV[2], IV[3], counter >>> 0, 0, len, flags];
  let w = m.slice();
  for (let r = 0; r < 7; r++) {
    g(s, 0, 4, 8, 12, w[0], w[1]); g(s, 1, 5, 9, 13, w[2], w[3]); g(s, 2, 6, 10, 14, w[4], w[5]); g(s, 3, 7, 11, 15, w[6], w[7]);
    g(s, 0, 5, 10, 15, w[8], w[9]); g(s, 1, 6, 11, 12, w[10], w[11]); g(s, 2, 7, 8, 13, w[12], w[13]); g(s, 3, 4, 9, 14, w[14], w[15]);
    w = PERM.map((i) => w[i]);
  }
  return s.slice(0, 8).map((v, i) => (v ^ s[i + 8]) >>> 0);
}
function blake3hex(buf) {
  if (buf.length > 1024) throw new Error("single-chunk BLAKE3 only");
  let cv = IV.slice();
  const blocks = Math.max(1, Math.ceil(buf.length / 64));
  for (let i = 0; i < blocks; i++) {
    const block = Buffer.alloc(64);
    const part = buf.subarray(i * 64, i * 64 + 64);
    part.copy(block);
    const m = Array.from({ length: 16 }, (_, j) => block.readUInt32LE(j * 4));
    const flags = (i === 0 ? 1 : 0) | (i === blocks - 1 ? 2 | 8 : 0);
    cv = compress(cv, m, 0, part.length, flags);
  }
  const out = Buffer.alloc(32);
  cv.forEach((v, i) => out.writeUInt32LE(v, i * 4));
  return out.toString("hex");
}
const check = (input, want) => {
  const got = blake3hex(Buffer.from(input));
  if (got !== want) throw new Error(`blake3 self-check failed for ${JSON.stringify(input)}: ${got}`);
};
check("", "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
check("abc", "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85");


const [bin, work, outFile] = process.argv.slice(2);
const WEB = 18963;
const EDGE = 18964;
const data = path.join(work, "data");
fs.rmSync(work, { recursive: true, force: true });
fs.mkdirSync(work, { recursive: true });
execFileSync(bin, ["init", "--data-dir", data, "--web-port", String(WEB), "--edge-port", String(EDGE)], { stdio: "inherit" });
const log = fs.openSync(path.join(work, "core.log"), "w");
// The clock counts as synchronised (README §2 Clocks): rotations, CSR signing and scheduled work wait for it.
const core = spawn(bin, ["run", "--data-dir", data], { stdio: ["ignore", log, log], env: { ...process.env, PICKET_CLOCK_SYNCED: "1" } });
let core2 = null;
const stop = () => {
  for (const c of [core, core2]) {
    try {
      c?.kill("SIGTERM");
    } catch {
      /* gone */
    }
  }
};
process.on("exit", () => {
  stop();
  if (outFile && !fs.existsSync(outFile)) fs.writeFileSync(outFile + ".partial", JSON.stringify(out, null, 1));
});
const password = fs.readFileSync(path.join(data, "initial-password"), "utf8").trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function req(opts, body) {
  return new Promise((resolve, reject) => {
    const r = https.request({ host: "127.0.0.1", rejectUnauthorized: false, ...opts }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const buf = Buffer.concat(chunks);
        let json;
        try {
          json = JSON.parse(buf.toString("utf8"));
        } catch {
          json = undefined;
        }
        resolve({ status: res.statusCode, headers: res.headers, buf, json });
      });
    });
    r.on("error", reject);
    if (body !== undefined) r.write(body);
    r.end();
  });
}

const auth = "Basic " + Buffer.from(`admin:${password}`).toString("base64");

/**
 * A WebSocket client (RFC 6455) over node:https: masked text frames out; text frames in (kept in
 * `frames`), pings answered, a close ends it. Enough for core's UI events and the edge session.
 */
function wsConnect(port, p, headers = {}, tlsOpts = {}) {
  return new Promise((resolve, reject) => {
    const r = https.request({
      host: "127.0.0.1",
      port,
      path: p,
      method: "GET",
      rejectUnauthorized: false,
      ...tlsOpts,
      headers: { connection: "Upgrade", upgrade: "websocket", "sec-websocket-version": "13", "sec-websocket-key": crypto.randomBytes(16).toString("base64"), ...headers },
    });
    r.on("upgrade", (_res, socket, head) => {
      const frames = [];
      const waiters = [];
      let buf = head;
      let open = true;
      const write = (payload, op) => {
        if (!open) return;
        const mask = crypto.randomBytes(4);
        const n = payload.length;
        const header = n < 126 ? Buffer.from([0x80 | op, 0x80 | n]) : Buffer.from([0x80 | op, 0x80 | 126, n >> 8, n & 255]);
        socket.write(Buffer.concat([header, mask, Buffer.from(payload.map((b, i) => b ^ mask[i % 4]))]));
      };
      socket.on("data", (d) => {
        buf = Buffer.concat([buf, d]);
        for (;;) {
          if (buf.length < 2) return;
          let len = buf[1] & 0x7f;
          let off = 2;
          if (len === 126) {
            if (buf.length < 4) return;
            len = buf.readUInt16BE(2);
            off = 4;
          } else if (len === 127) {
            if (buf.length < 10) return;
            len = Number(buf.readBigUInt64BE(2));
            off = 10;
          }
          if (buf.length < off + len) return;
          const op = buf[0] & 0x0f;
          const payload = buf.subarray(off, off + len);
          buf = buf.subarray(off + len);
          if (op === 1) {
            const v = JSON.parse(payload.toString("utf8"));
            frames.push(v);
            for (const w of waiters.splice(0)) w();
          } else if (op === 9) write(payload, 0xa);
          else if (op === 8) socket.end();
        }
      });
      socket.on("close", () => {
        open = false;
      });
      resolve({
        frames,
        send: (v) => write(Buffer.from(JSON.stringify(v)), 1),
        /** The first frame (from `from` on) that `f` accepts, within `ms`. */
        async next(f, from = 0, ms = 30_000) {
          const end = Date.now() + ms;
          for (;;) {
            const hit = frames.slice(from).find(f);
            if (hit) return hit;
            if (Date.now() > end || !open) throw new Error(`no matching frame on ${p}`);
            await new Promise((ok) => {
              waiters.push(ok);
              setTimeout(ok, 500);
            });
          }
        },
        close() {
          write(Buffer.alloc(0), 8);
          open = false;
          socket.destroy();
        },
      });
    });
    r.on("response", (res) => reject(new Error(`WebSocket ${p}: ${res.statusCode}`)));
    r.on("error", reject);
    r.end();
  });
}
async function ui(method, p, body, extraHeaders = {}) {
  const headers = { authorization: auth, "x-picket-ui": "1", ...extraHeaders };
  let b;
  if (body !== undefined) {
    b = Buffer.isBuffer(body) ? body : Buffer.from(JSON.stringify(body));
    headers["content-type"] = "application/json";
    headers["content-length"] = String(b.length);
  }
  return req({ port: WEB, method, path: `/api/ui/v1${p}`, headers }, b);
}
async function ok(method, p, body) {
  const r = await ui(method, p, body);
  if (r.status >= 300) throw new Error(`${method} ${p}: ${r.status} ${r.buf.toString().slice(0, 500)}`);
  return r.json;
}

const out = {};
const keep = (k, v) => {
  out[k] = v;
  return v;
};
async function capture(p, key = p) {
  const r = await ui("GET", p);
  if (r.status !== 200) throw new Error(`GET ${p}: ${r.status} ${r.buf.toString().slice(0, 400)}`);
  return keep(key, r.json);
}
async function waitFor(what, f, ms = 60_000) {
  const end = Date.now() + ms;
  for (;;) {
    const v = await f().catch(() => null);
    if (v) return v;
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await sleep(500);
  }
}

await waitFor("core", async () => (await ui("GET", "/identity")).status === 200);
const identity = await capture("/identity");
// Core's UI events while the rest runs (api.md §7; the page's own Origin and basic auth).
const uiEvents = await wsConnect(WEB, "/api/ui/v1/events", { authorization: auth, origin: `https://127.0.0.1:${WEB}` });
keep("/settings (fresh)", await ok("GET", "/settings"));

// --- configuration -------------------------------------------------------------------------
async function manualFeed(id, category, text) {
  await ok("POST", "/feeds", { id, name: id, category, format: "adblock" });
  await ok("PUT", `/feeds/${id}/file`, { content: text, base_version: null });
}
await manualFeed("f-sec", "security", "||ads.example^\n||tracker.example^\n||malware.example^\n||198.51.100.7^\n");
await manualFeed("f-priv", "privacy", "||ads.example^\n||tracker.example^$badfilter\n|tracker.example^\n");
await manualFeed("f-trial", "security", "||trial.example^\n@@||ok.trial.example^\n||203.0.113.9^\n");
await ok("POST", "/bundles", { id: "b1", name: "b1", action: "block", feeds: [{ feed: "f-sec" }, { feed: "f-priv" }] });
await ok("POST", "/bundles", { id: "trial-b", name: "trial-b", action: "block", feeds: [{ feed: "f-trial" }] });
await ok("POST", "/profiles", { id: "p1", name: "p1", block: ["b1"], trial_bundles: ["trial-b"], ttl: { min: 30, max: 120 }, alert_categories: ["security"] });
await ok("POST", "/clients", { name: "tablet", macs: ["02:11:22:33:44:55"], source_ips: ["192.0.2.10/32"], profile: "p1" });
// A client entry that lists no MACs: the device keyed by its name has no `mac` (core 07acc1c).
await ok("POST", "/clients", { name: "phone", macs: [], source_ips: ["192.0.2.13/32"] });
// A disabled feed provider (it never downloads here), for the backtest's `days` and `k`.
const provider = await ui("POST", "/feed-providers", { id: "hagezi", name: "HaGeZi", module: "github", enabled: false, config: { owner: "hagezi", repo: "dns-blocklists", branch: "main" }, files: [{ match: "adblock/tif.txt", feed: { category: "security", format: "adblock" } }], trigger: { kind: "dynamic", min_interval: "2m" } });
if (provider.status >= 300) console.log("feed provider:", provider.status, provider.buf.toString().slice(0, 300));
// A head that read every member feed's first run (the compiler builds again on new runs).
const head = async (b) =>
  waitFor(
    `a head of ${b} with every feed's run`,
    async () => {
      const s = await ok("GET", `/bundles/${b}/status`);
      return s.head && !s.building && Object.values(s.feed_runs ?? {}).length && Object.values(s.feed_runs).every((n) => n > 0) ? s : null;
    },
    180_000,
  );
for (const f of ["f-sec", "f-priv", "f-trial"])
  await waitFor(`${f}'s first run`, async () => ((await ok("GET", `/feeds/${f}/runs?limit=5`)).items ?? []).some((r) => r.status === "applied"), 120_000).catch(() => null);
await ok("POST", "/bundles/b1/build", {});
await ok("POST", "/bundles/trial-b/build", {});
const b1 = await head("b1");
await head("trial-b");
keep("/bundles/b1", await ok("GET", "/bundles/b1"));
keep("/bundles/b1/status", b1);

// A lookup provider (dns module; its calls fail here, which is fine for the shapes).
const modules = await capture("/lookup-modules");
const dns = modules.find((m) => m.id === "dns") ?? modules[0];
const preset = dns?.presets?.[0];
if (preset) {
  const built = await ui("POST", `/lookup-modules/${dns.id}/presets/${preset.id}`, {});
  keep(`POST /lookup-modules/${dns.id}/presets/${preset.id}`, { status: built.status, body: built.json });
}

// --- the fake edge -------------------------------------------------------------------------
/**
 * Registers a fake edge (an Ed25519 identity) and fetches its published config object (api.md
 * §1), so core keeps that config for replay; its records name the config and b1's head.
 */
async function fakeEdge(name) {
  const key = path.join(work, `${name}.key`);
  const cert = path.join(work, `${name}.crt`);
  execFileSync("openssl", ["genpkey", "-algorithm", "ed25519", "-out", key]);
  execFileSync("openssl", ["req", "-x509", "-new", "-key", key, "-subj", `/CN=${name}`, "-days", "30", "-out", cert]);
  const spki = crypto.createPublicKey(fs.readFileSync(key)).export({ type: "spki", format: "der" });
  const fp = "SHA256:" + crypto.createHash("sha256").update(spki).digest("base64").replace(/=+$/, "");
  const edge = await ok("POST", "/edges", { name, key: fp });
  const opts = { port: EDGE, key: fs.readFileSync(key), cert: fs.readFileSync(cert), minVersion: "TLSv1.3", ALPNProtocols: ["http/1.1"] };
  const cfg = await waitFor(
    `${name}'s published config naming b1's head`,
    async () => {
      const c = await ok("GET", `/edges/${edge.id}/config`);
      return c?.id && c.config?.bundles?.b1 === b1.head ? c : null;
    },
    120_000,
  );
  const fpPath = crypto.createHash("sha256").update(spki).digest("base64url");
  const fetched = await req({ ...opts, method: "GET", path: `/objects/configs/${fpPath}.json` });
  if (fetched.status !== 200) throw new Error(`${name} config fetch: ${fetched.status} ${fetched.buf.toString().slice(0, 300)}`);
  const etag = String(fetched.headers.etag ?? "").replace(/"/g, "");
  const configId = etag || cfg.id;
  console.log(name, "config", configId.slice(0, 16), "published", cfg.id.slice(0, 16));
  return { id: edge.id, opts, cfg, versions: { config: configId.slice(0, 16), bundles: { b1: b1.head.slice(0, 16) } } };
}
const e1 = await fakeEdge("e1");
const edgeId = e1.id;
const edgeOpts = e1.opts;
keep(`/edges/${edgeId}/config`, e1.cfg);
const versions = e1.versions;

const ts = (t) => new Date(t).toISOString().replace(/\.(\d{3})Z$/, ".$1000Z");
const now = Date.now() - 60_000;
const q = (seq, at, qname, decision, reason, extra = {}) => ({
  t: "q",
  ts: ts(at),
  boot: "b-cap",
  seq,
  listener: "lan-dns",
  proto: "udp",
  client: "192.0.2.10",
  device: "tablet",
  profile: "p1",
  qname,
  qtype: "A",
  do: false,
  rcode: "NOERROR",
  decision,
  reason,
  answers: [],
  targets: [],
  truncated: false,
  cname: [],
  lookups: [],
  upstream: null,
  fw: null,
  us: { total: 41, filter: 6 },
  versions,
  ...extra,
});
function dnsName(n) {
  const parts = [];
  for (const l of n.split(".").filter(Boolean)) parts.push(Buffer.from([l.length]), Buffer.from(l));
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}
function answerWire(qname, chain, addrs) {
  const count = chain.length + addrs.length;
  const m = [Buffer.from([0x12, 0x34, 0x81, 0x80, 0, 1, 0, count, 0, 0, 0, 0]), dnsName(qname), Buffer.from([0, 1, 0, 1])];
  let owner = qname;
  for (const c of chain) {
    const t = dnsName(c);
    m.push(dnsName(owner), Buffer.from([0, 5, 0, 1, 0, 0, 1, 0]), Buffer.from([t.length >> 8, t.length & 255]), t);
    owner = c;
  }
  for (const a of addrs) m.push(dnsName(owner), Buffer.from([0, 1, 0, 1, 0, 0, 1, 0, 0, 4]), Buffer.from(a));
  return Buffer.concat(m);
}
async function blake3(buf) {
  // api.md §5: an answer's id is the first 16 hex characters of its wire's BLAKE3 (core checks it).
  return blake3hex(buf).slice(0, 16);
}
const wire = answerWire("www.example.com", ["cdn.example.net"], [[192, 0, 2, 1]]);
const aid = await blake3(wire);
const lines = [
  { t: "answer", ts: ts(now), boot: "b-cap", seq: 1, id: aid, wire: wire.toString("base64") },
  q(2, now, "ads.example", "block", { step: 3, bundle: "b1", key: "ads.example", kind: "subs", stage: "query" }, { answers: ["0.0.0.0"] }),
  q(3, now + 1000, "www.example.com", "allow", null, { answer_id: aid, cname: ["cdn.example.net"], answers: ["192.0.2.1"], upstream: { group: "cloudflare", upstream: "cloudflare-dot", rtt_ms: 12 } }),
  q(4, now + 2000, "www.example.com", "allow", null, { answer_id: aid, cname: ["other.example"], answers: ["192.0.2.99"], targets: ["svc.example"] }),
  q(5, now + 3000, "trial.example", "allow", null, { answers: ["192.0.2.5"] }),
  q(6, now + 4000, "malware.example", "block", { step: 3, bundle: "b1", key: "malware.example", kind: "subs", stage: "query" }, { answers: ["0.0.0.0"] }),
  q(7, now + 5000, "sub.trial.example", "allow", null, { answers: ["192.0.2.6"], client: "192.0.2.11", device: null }),
  q(8, now + 6000, "tracker.example", "block", { step: 3, bundle: "b1", key: "tracker.example", kind: "exact", stage: "query" }, { answers: ["0.0.0.0"], client: "192.0.2.11", device: null }),
  q(9, now + 7000, "lookup.example", "allow", null, {
    answers: ["192.0.2.7"],
    lookups: [{ provider: "q9", verdict: "clean", cached: false, gen: "0000000000000001", ms: 23, timed_out: false, retry: false, reason: "not listed", detail: { server: "9.9.9.9" } }],
  }),
  { t: "allow", ts: ts(now + 8000), boot: "b-cap", seq: 10, action: "created", allow_id: "a-1", client: "192.0.2.10", device: "tablet", kind: "dns", target: "ads.example", expires_at: ts(Date.now() + 3600_000), via: "extension" },
  { t: "allow", ts: ts(now + 9000), boot: "b-cap", seq: 11, action: "created", allow_id: "a-2", client: "192.0.2.11", kind: "ip", target: "198.51.100.7", expires_at: ts(now + 9500), via: "extension" },
];
const body = zlib.gzipSync(Buffer.from(lines.map((l) => JSON.stringify(l) + "\n").join("")));
const posted = await req({ ...edgeOpts, method: "POST", path: "/v1/logs", headers: { "content-encoding": "gzip", "content-type": "application/jsonl", "content-length": String(body.length) } }, body);
if (posted.status !== 200) throw new Error(`POST /v1/logs: ${posted.status} ${posted.buf.toString()}`);
keep("POST /v1/logs", posted.json ?? posted.buf.toString());

// --- wave-5 reads --------------------------------------------------------------------------
const page = await waitFor("logged records", async () => {
  const p = await ok("GET", "/logs?limit=100");
  return p.items.length >= 8 ? p : null;
});
const idOf = (seq) => page.items.find((r) => r.seq === seq)?.id;
// Analysis runs in the background: wait for attribution and the wire check.
await waitFor("attribution of the block", async () => (await ok("GET", `/logs/${encodeURIComponent(idOf(2))}`)).attribution, 120_000);
await waitFor("the wire check", async () => (await ok("GET", `/logs/${encodeURIComponent(idOf(4))}`)).wire_check, 120_000);
await waitFor("the trial check", async () => (await ok("GET", `/logs/${encodeURIComponent(idOf(5))}`)).trial_check, 120_000);
await capture("/logs?limit=100", "/logs");
await capture("/logs?limit=3", "/logs?limit=3");
for (const seq of [2, 3, 4, 5, 6, 9]) await capture(`/logs/${encodeURIComponent(idOf(seq))}`, `/logs/{seq ${seq}}`);
keep("record ids", Object.fromEntries([2, 3, 4, 5, 6, 7, 8, 9].map((s) => [s, idOf(s)])));
for (const kind of ["blocked", "allowed", "clients"]) await capture(`/top?kind=${kind}&window=24h&limit=10`, `/top?kind=${kind}`);
// A second batch, after the log captures above (which keep the first batch's records alone).
const more = [
  // A MAC the edge logged as the device of the tablet's address (core lists it in the tablet's `macs`).
  q(12, now + 10000, "mac.example", "allow", null, { answers: ["192.0.2.8"], device: "02:aa:bb:cc:dd:01" }),
  // More copies for malware.example's security alert (its evidence pages).
  q(13, now + 11000, "malware.example", "block", { step: 3, bundle: "b1", key: "malware.example", kind: "subs", stage: "query" }, { answers: ["0.0.0.0"] }),
  q(14, now + 12000, "www.malware.example", "block", { step: 3, bundle: "b1", key: "malware.example", kind: "subs", stage: "query" }, { answers: ["0.0.0.0"] }),
  // A MAC no client names, logged at the address of a device that is keyed by its address
  // (192.0.2.11): core lists it in that device's `macs` but never as its `mac` (core c58ba80).
  q(15, now + 12500, "mac2.example", "allow", null, { answers: ["192.0.2.9"], client: "192.0.2.11", device: "02:aa:bb:cc:dd:02" }),
  // A device keyed by a client name no entry has now (renamed or deleted): no MAC, no client
  // (core 07acc1c; its address is no entry's either), so it can be added as a client.
  q(16, now + 12600, "laptop.example", "allow", null, { answers: ["192.0.2.20"], client: "192.0.2.12", device: "laptop", profile: "default" }),
  // A device keyed by the name of a client entry that lists no MACs: the entry's, without a MAC.
  q(17, now + 12700, "phone.example", "allow", null, { answers: ["192.0.2.21"], client: "192.0.2.13", device: "phone", profile: "default" }),
];
const body2 = zlib.gzipSync(Buffer.from(more.map((l) => JSON.stringify(l) + "\n").join("")));
const posted2 = await req({ ...edgeOpts, method: "POST", path: "/v1/logs", headers: { "content-encoding": "gzip", "content-type": "application/jsonl", "content-length": String(body2.length) } }, body2);
if (posted2.status !== 200) throw new Error(`POST /v1/logs: ${posted2.status} ${posted2.buf.toString()}`);
await waitFor("the second batch", async () => (await ok("GET", "/logs?limit=100")).items.length >= page.items.length + 6);
await capture("/devices");
await capture("/query-summary?device=tablet&window=24h", "/query-summary?device=tablet");
await capture("/query-summary?profile=p1&window=24h", "/query-summary?profile=p1");
await capture("/trial-results?profile=p1&bundle=trial-b&window=24h", "/trial-results");
for (const st of ["all", "active", "recent"]) await capture(`/temp-allows?state=${st}`, `/temp-allows?state=${st}`);
await capture("/temp-allows?limit=1", "/temp-allows?limit=1");
await capture("/dnssec/queue");
await capture("/dnssec/results");
await capture("/dnssec/results?outcome=bogus");
await capture("/extension");
console.log("seq 4:", JSON.stringify((await ok("GET", `/logs/${encodeURIComponent(idOf(4))}`))).slice(0, 600));
const alerts = await waitFor("alerts", async () => {
  const a = await ok("GET", "/alerts?limit=100");
  return a.items.some((x) => x.kind === "wire_mismatch") ? a : null;
}, 30_000).catch(async (e) => {
  console.log(String(e));
  return ok("GET", "/alerts?limit=100");
});
console.log("alerts:", alerts.items.map((a) => a.kind).join(", "));
keep("/alerts", alerts);
for (const a of alerts.items) {
  await capture(`/alerts/${a.id}`, `/alerts/{${a.kind}}`);
  await capture(`/alerts/${a.id}/evidence`, `/alerts/{${a.kind}}/evidence`);
}
// A second edge logs the tablet's block of malware.example with an older event time than the
// copies e1's records made: the alert is now one of several edges (`edge` null, core.md §9), and
// the copy is stored after them, so it comes first on the evidence's first page (newest stored
// first, not by event time).
const e2 = await fakeEdge("e2");
const postLogs = async (opts, recs) => {
  const gz = zlib.gzipSync(Buffer.from(recs.map((l) => JSON.stringify(l) + "\n").join("")));
  const r = await req({ ...opts, method: "POST", path: "/v1/logs", headers: { "content-encoding": "gzip", "content-type": "application/jsonl", "content-length": String(gz.length) } }, gz);
  if (r.status !== 200) throw new Error(`POST /v1/logs: ${r.status} ${r.buf.toString()}`);
};
await postLogs(e2.opts, [q(1, now + 500, "malware.example", "block", { step: 3, bundle: "b1", key: "malware.example", kind: "subs", stage: "query" }, { answers: ["0.0.0.0"], boot: "b-cap2", versions: e2.versions })]);
const several = await waitFor("an alert of several edges", async () => {
  for (const a of (await ok("GET", "/alerts?limit=100")).items) {
    if (a.kind !== "category_blocked" || a.edge !== null) continue;
    const ev = await ok("GET", `/alerts/${a.id}/evidence`);
    if (ev.total >= 4) return a;
  }
  return null;
}, 120_000);
keep("second edge", e2.id);
// Evidence a page at a time (api.md §7 cursors): that alert's four copies, two a page.
const paged = several;
await capture(`/alerts/${paged.id}`, "/alerts/{paged}");
await capture(`/alerts/${paged.id}/evidence`, "/alerts/{paged}/evidence");
const page1 = await capture(`/alerts/${paged.id}/evidence?limit=2`, "/alerts/{paged}/evidence?limit=2");
const page2 = await capture(`/alerts/${paged.id}/evidence?limit=2&cursor=${encodeURIComponent(page1.next_cursor)}`, "/alerts/{paged}/evidence?limit=2&cursor=1");
if (page2.next_cursor) await capture(`/alerts/${paged.id}/evidence?limit=2&cursor=${encodeURIComponent(page2.next_cursor)}`, "/alerts/{paged}/evidence?limit=2&cursor=2");
keep("evidence cursors", { first: page1.next_cursor, second: page2.next_cursor ?? null });
// A cursor from core 720be97 (the last copy's event time and row id): refused now.
const oldCursor = Buffer.from(`${page1.items[1]?.ts ?? ts(now)}\u001f2`).toString("base64url");
const old = await ui("GET", `/alerts/${paged.id}/evidence?limit=2&cursor=${oldCursor}`);
keep("/alerts/{paged}/evidence (old cursor)", { status: old.status, body: old.json, cursor: oldCursor });

// The edge's session (api.md §3): a hello, then heartbeats every few seconds so it stays online.
// `cert_roots` (api.md §3): the root behind each managed listener's certificate, once it has one.
let certRoots = {};
const hello = () => ({ type: "hello", data: { edge_version: identity.version, arch: "x86_64", os: "debian", kernel: "6.1", platform: "debian", boot: "b-cap", allowed_binds: ["*"], updates_enabled: false, have: {}, starts: 0, conditions: [], applied: {}, cert_roots: certRoots } });
let edgeWs = await wsConnect(EDGE, "/v1/session", {}, edgeOpts);
edgeWs.send(hello());
await edgeWs.next((f) => f.type === "welcome");
const started = Date.now();
let applied = {};
const heartbeat = () =>
  edgeWs.send({ type: "heartbeat", data: { ts: ts(Date.now()), boot: "b-cap", up_ms: Date.now() - started, metrics: { queries: 9, by_decision: { allow: 9 } }, have: {}, conditions: [], applied, cert_roots: certRoots } });
let beats = setInterval(heartbeat, 3000);

// A revoke the edge acknowledges in its heartbeat (api.md §4 `revoked_allows`): `revoked` until
// the edge's log reports the end.
const revoke = await ok("POST", `/edges/${edgeId}/allows/a-1/revoke`, {});
keep("POST /edges/{id}/allows/a-1/revoke", revoke);
await capture("/temp-allows?state=active", "/temp-allows?state=active (revoke pending)");
applied = { revoked_allows: revoke.request_id };
heartbeat();
await waitFor("the revoke acknowledged", async () => ((await ok("GET", "/temp-allows?state=recent")).items ?? []).some((a) => a.allow_id === "a-1" && a.state === "revoked"));
for (const st of ["all", "active", "recent"]) await capture(`/temp-allows?state=${st}`, `/temp-allows?state=${st} (revoked)`);
await capture("/query-summary?profile=p1&window=24h", "/query-summary?profile=p1 (revoked)");
await capture("/query-summary?device=tablet&window=24h", "/query-summary?device=tablet (revoked)");


// Lookup provider: create, status, Test now, flush.
const lp = await ui("POST", "/lookup-providers", { id: "q9", name: "q9", module: dns.id, category: "security", config: (out[`POST /lookup-modules/${dns.id}/presets/${preset?.id}`]?.body?.config) ?? {} });
keep("POST /lookup-providers", { status: lp.status, body: lp.json });
if (lp.status < 300) {
  await capture("/lookup-providers/q9");
  const first = await ui("GET", "/lookup-providers/q9/status");
  keep("/lookup-providers/q9/status (right after the create)", { status: first.status, body: first.json });
  // After its first self-test (it runs at the create; its calls fail here), when it ends in time.
  keep("/lookup-providers/q9/status", await waitFor("the provider's status after its self-test", async () => {
    const r = await ui("GET", "/lookup-providers/q9/status");
    return r.status === 200 && r.json?.last_self_test ? r.json : null;
  }, 90_000).catch(async () => (await ui("GET", "/lookup-providers/q9/status")).json));
  const t = await ui("POST", "/lookup-providers/q9/test", {});
  keep("POST /lookup-providers/q9/test", { status: t.status, body: t.json });
  const f = await ui("POST", "/lookup-providers/q9/flush", {});
  keep("POST /lookup-providers/q9/flush", { status: f.status, body: f.json });
  await capture("/lookup-providers/q9/status", "/lookup-providers/q9/status (after)");
  // A block by the sync lookup provider q9 (a security provider: p1 leaves alert_providers unset,
  // so it alerts on every security provider): category_blocked with the provider's verdict in
  // `details.providers` (core.md §9), where a feed's block names `feeds`.
  const gen = (await ok("GET", "/lookup-providers/q9/status")).cache_generation ?? "0000000000000001";
  await postLogs(edgeOpts, [
    q(18, now + 13000, "lookup-block.example", "block", { step: 4, kind: "lookup", provider: "q9", stage: "query" }, {
      answers: ["0.0.0.0"],
      lookups: [{ provider: "q9", verdict: "block", score: 0.97, cached: false, gen: String(gen), ms: 18, timed_out: false, retry: false, reason: "listed: malware", detail: { list: "malware", server: "9.9.9.9" } }],
    }),
  ]);
  const lookupAlert = await waitFor("the lookup block's alert", async () => (await ok("GET", "/alerts?limit=100")).items.find((a) => a.kind === "category_blocked" && Array.isArray(a.details?.providers)), 120_000);
  await capture(`/alerts/${lookupAlert.id}`, "/alerts/{lookup block}");
  await capture(`/alerts/${lookupAlert.id}/evidence`, "/alerts/{lookup block}/evidence");
  // The record itself: its lookup's score as a decimal (core 07acc1c: 0.97, not the f32's noise).
  const blockId = (await ok("GET", "/logs?limit=100")).items.find((r) => r.seq === 18)?.id;
  if (blockId) await capture(`/logs/${encodeURIComponent(blockId)}`, "/logs/{seq 18}");
}

// A burst (core a3eb6d5): blocks of malware.example on BURST devices raise as many
// category_blocked alerts at once (one per device and name), and one bulk delete removes them.
// Each sends at most one `alert` event a second, listing at most 64 alerts and saying the rest
// went unlisted (`alerts_truncated`).
const BURST = 100;
const burstFrom = uiEvents.frames.length;
await postLogs(
  edgeOpts,
  Array.from({ length: BURST }, (_, i) => q(100 + i, now + 14000 + i, "malware.example", "block", { step: 3, bundle: "b1", key: "malware.example", kind: "subs", stage: "query" }, { answers: ["0.0.0.0"], device: `burst-${i}` })),
);
const burstIds = await waitFor(
  "the burst's alerts",
  async () => {
    const ids = [];
    let cursor = null;
    do {
      const p = await ok("GET", `/alerts?kind=category_blocked&limit=500${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`);
      for (const a of p.items) if (a.dedupe_key.startsWith("category_blocked:burst-")) ids.push(a.id);
      cursor = p.next_cursor;
    } while (cursor);
    return ids.length >= BURST ? ids : null;
  },
  120_000,
);
const isTruncated = (f) => f.type === "alert" && f.data?.alerts_truncated === true;
await uiEvents.next(isTruncated, burstFrom).catch(() => console.log("the burst's raises sent no truncated alert event"));
keep("DELETE /alerts (burst)", await ok("DELETE", "/alerts", { ids: burstIds }));
await uiEvents.next((f) => isTruncated(f) && f.data.alerts.some((a) => a.deleted), burstFrom).catch(() => console.log("the bulk delete sent no truncated alert event"));

// Every `limit` is 1 to 500 (1 to 100 on /top), the backtest's `days` 1 to 60 and `k` 0.1 to 50;
// anything else is refused with 400 (core 07acc1c; it used to be clamped).
const limits = {};
for (const p of [
  "/top?kind=blocked&window=24h&limit=100",
  "/top?kind=blocked&window=24h&limit=101",
  "/top?kind=blocked&window=24h&limit=0",
  "/logs?limit=500",
  "/logs?limit=501",
  "/logs?limit=0",
  "/alerts?limit=501",
  `/alerts/${paged.id}/evidence?limit=501`,
  "/temp-allows?limit=501",
  "/dnssec/queue?limit=0",
  "/dnssec/results?limit=501",
  "/edges?limit=501",
  "/feeds/f-sec/runs?limit=501",
  "/bundles/b1/versions?limit=0",
  "/feed-providers/hagezi/backtest?days=60&k=0.1",
  "/feed-providers/hagezi/backtest?days=61",
  "/feed-providers/hagezi/backtest?days=0",
  "/feed-providers/hagezi/backtest?k=50.5",
  "/feed-providers/hagezi/backtest?k=0.05",
]) {
  const r = await ui("GET", p);
  limits[p] = { status: r.status, body: r.status === 200 ? (Array.isArray(r.json) ? r.json : { items: (r.json?.items ?? []).length }) : r.json };
}
keep("limits", limits);



// Metrics: every series the UI charts that core now records.
const series = ["feed_hits", "trial_would_block", "retro_hits", "wire_mismatch", "evidence_bytes", "queue_depth", "core_rss", "core_cpu_ms", "core_disk_used", "core_disk_free", "db_bytes", "job_ms.p50", "job_ms.p99", "dnssec_results", "dnssec_fallback", "dnssec_answers", "dnssec_coverage", "crosscheck", "rechecks", "recheck_blocks", "lookup_calls", "lookup_verdicts", "lookup_queue", "lookup_call_ms.p50"];
for (const s of series) {
  const r = await ui("GET", `/metrics?series=${encodeURIComponent(s)}&window=1h&edge=all`);
  keep(`/metrics?series=${s}`, { status: r.status, body: r.json });
}
// Would-blocks per edge (core counts them with the edge).
keep("trial edge", edgeId);
const perEdge = await ui("GET", `/metrics?series=trial_would_block&window=1h&edge=${encodeURIComponent(edgeId)}`);
keep("/metrics?series=trial_would_block&edge={edge}", { status: perEdge.status, body: perEdge.json });

// Config export and restore.
const exp = await ui("GET", "/config/export");
if (exp.status !== 200) throw new Error(`export ${exp.status} ${exp.buf.toString()}`);
fs.writeFileSync(path.join(work, "export.json"), exp.buf);
keep("GET /config/export headers", { "content-type": exp.headers["content-type"], "content-disposition": exp.headers["content-disposition"] });
const doc = JSON.parse(exp.buf.toString("utf8"));
keep("GET /config/export", doc);
const put = await ui("PUT", "/config/export", exp.buf);
keep("PUT /config/export", { status: put.status, body: put.json });
const other = { ...doc, configuration: { ...doc.configuration, settings: { ...doc.configuration.settings, "lanca.zones": ["example.arpa"] } } };
const zput = await ui("PUT", "/config/export", other);
keep("PUT /config/export (other zones)", { status: zput.status, body: zput.json });
const bad = await ui("PUT", "/config/export", Buffer.from("{\"format_version\": 1, \"configuration\": "));
keep("PUT /config/export (malformed)", { status: bad.status, body: bad.json });
const newer = await ui("PUT", "/config/export", { ...doc, format_version: 99 });
keep("PUT /config/export (newer)", { status: newer.status, body: newer.json });
const badref = { ...doc, configuration: { ...doc.configuration, profiles: [...doc.configuration.profiles, { ...doc.configuration.profiles.find((p) => p.id === "p1"), id: "p9", block: ["nope"] }] } };
const bref = await ui("PUT", "/config/export", badref);
keep("PUT /config/export (bad reference)", { status: bref.status, body: bref.json });
// After the restore the edge's records are gone: logs are emptied.

// The edge's session again (the restore may have ended it), for the rotation below.
clearInterval(beats);
edgeWs.close();
edgeWs = await wsConnect(EDGE, "/v1/session", {}, edgeOpts);
edgeWs.send(hello());
await edgeWs.next((f) => f.type === "welcome");
beats = setInterval(heartbeat, 3000);

// --- LAN CA rotation (core.md §11, security.md §2) ---------------------------------------------
// A managed DoT listener on the edge: its name must stay under lanca.zones.
await ok("POST", "/listeners", { id: "lan-dot", name: "lan-dot", proto: "dot", bind: "192.168.1.1:853", tls: { managed: "dns.home.arpa" }, edges: [edgeId] });
const fresh = await ok("GET", "/settings");
// A rotation names the root it replaces (`lanca.rotate_from`, core c58ba80).
const zones = async (key, z, from) => {
  const r = await ui("PUT", "/settings", { lanca: from === undefined ? { zones: z } : { zones: z, rotate_from: from } });
  keep(key, { status: r.status, body: r.json, sent: from === undefined ? { zones: z } : { zones: z, rotate_from: from } });
  return r;
};
await zones("PUT /settings lanca.zones (no rotate_from)", ["home.arpa", "lan.example"]);
await zones("PUT /settings lanca.zones (null rotate_from)", ["home.arpa", "lan.example"], null);
await zones("PUT /settings lanca.zones (stale rotate_from)", ["home.arpa", "lan.example"], "SHA256:" + "0".repeat(64));
await zones("PUT /settings lanca.zones (orphans)", ["lan.example"], fresh.lanca.fingerprint);
await zones("PUT /settings lanca.zones (public suffix)", ["com"], fresh.lanca.fingerprint);
// The edge asks for the listener's certificate (api.md §2 `POST /v1/csr`): the current root signs
// it, and the edge reports that root behind the listener (`cert_roots`) from then on.
const csr = async () => {
  const k = path.join(work, "listener.key");
  const c = path.join(work, "listener.csr");
  execFileSync("openssl", ["req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", k, "-subj", "/CN=lan-dot", "-out", c], { stdio: "ignore" });
  const b = Buffer.from(JSON.stringify({ csr_pem: fs.readFileSync(c, "utf8"), listener: "lan-dot" }));
  const r = await req({ ...edgeOpts, method: "POST", path: "/v1/csr", headers: { "content-type": "application/json", "content-length": String(b.length) } }, b);
  if (r.status !== 200) throw new Error(`POST /v1/csr: ${r.status} ${r.buf.toString().slice(0, 300)}`);
};
await csr();
certRoots = { "lan-dot": fresh.lanca.fingerprint };
heartbeat();
await sleep(1000);
const rotated = await zones("PUT /settings lanca.zones (rotation)", ["home.arpa", "lan.example"], fresh.lanca.fingerprint);
if (rotated.status !== 200) throw new Error(`rotation: ${rotated.status} ${rotated.buf.toString().slice(0, 300)}`);
const newRoot = rotated.json.lanca.fingerprint;
keep("/settings (rotating)", await waitFor("the previous root in use", async () => {
  const s = await ok("GET", "/settings");
  return s.lanca.previous[0]?.edges[0]?.online === true ? s : null;
}));
await zones("PUT /settings lanca.zones (previous root in use)", ["home.arpa"], newRoot);
// The old tab's rotation, sent again after this one: its root is no longer the current one.
await zones("PUT /settings lanca.zones (replaced root)", ["home.arpa", "lan.example", "other.example"], fresh.lanca.fingerprint);
// The edge goes offline: the previous root's user shows offline.
clearInterval(beats);
edgeWs.close();
keep("/settings (rotating, edge offline)", await waitFor("the edge offline", async () => {
  const s = await ok("GET", "/settings");
  return s.lanca.previous[0]?.edges[0]?.online === false ? s : null;
}));
// A certificate from the new root, reported in the edge's next hello, ends the previous root's use.
await csr();
certRoots = { "lan-dot": newRoot };
edgeWs = await wsConnect(EDGE, "/v1/session", {}, edgeOpts);
edgeWs.send(hello());
await edgeWs.next((f) => f.type === "welcome");
beats = setInterval(heartbeat, 3000);
keep("/settings (rotated)", await waitFor("the previous root dropped", async () => {
  const s = await ok("GET", "/settings");
  return s.lanca.previous.length === 0 ? s : null;
}));
await uiEvents.next((f) => f.type === "lanca" && f.data?.event === "previous_dropped").catch(() => null);
clearInterval(beats);
edgeWs.close();
await capture("/identity", "/identity (rotated)");
await capture("/settings");

// The UI events core sent (a few of each type; `restore` follows the restore above).
await uiEvents.next((f) => f.type === "restore").catch(() => null);
await sleep(1500);
const byType = {};
for (const f of uiEvents.frames) (byType[f.type] ??= []).push(f);
// With the first truncated `alert` and `feed_run` events (core a3eb6d5: the burst's), raised and deleted.
const truncated = (f) => f.data?.alerts_truncated === true || f.data?.runs_truncated === true;
const kept = (fs) => {
  const first = fs.slice(0, 4);
  const cut = [fs.find((f) => truncated(f) && !f.data.alerts?.some((a) => a.deleted)), fs.find((f) => truncated(f) && f.data.alerts?.some((a) => a.deleted))];
  return [...first, ...cut.filter((f, i) => f && !first.includes(f) && cut.indexOf(f) === i)];
};
keep("events", Object.fromEntries(Object.entries(byType).map(([t, fs]) => [t, kept(fs)])));
keep("event counts", Object.fromEntries(Object.entries(byType).map(([t, fs]) => [t, fs.length])));
uiEvents.close();

// --- a core whose clock isn't synchronised (README §2 Clocks) ---------------------------------
// `clock_synced` false and a rotation refused with 503. In a user and mount namespace, with
// systemd-timesyncd's flag hidden (a tmpfs over its directory) and a `timedatectl` that says no.
const W2 = 18965;
const data2 = path.join(work, "data-unsynced");
const fakeBin = path.join(work, "fakebin");
fs.mkdirSync(fakeBin, { recursive: true });
fs.writeFileSync(path.join(fakeBin, "timedatectl"), "#!/bin/sh\necho no\n", { mode: 0o755 });
execFileSync(bin, ["init", "--data-dir", data2, "--web-port", String(W2), "--edge-port", String(W2 + 1)], { stdio: "inherit" });
const env2 = { ...process.env, PATH: `${fakeBin}:${process.env.PATH}` };
delete env2.PICKET_CLOCK_SYNCED;
const log2 = fs.openSync(path.join(work, "core-unsynced.log"), "w");
core2 = spawn("unshare", ["-rm", "sh", "-c", 'mount -t tmpfs tmpfs /run/systemd/timesync 2>/dev/null; exec "$0" run --data-dir "$1"', bin, data2], { stdio: ["ignore", log2, log2], env: env2 });
const auth2 = "Basic " + Buffer.from(`admin:${fs.readFileSync(path.join(data2, "initial-password"), "utf8").trim()}`).toString("base64");
const ui2 = (method, p, body) => {
  const b = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
  const headers = { authorization: auth2, "x-picket-ui": "1", ...(b ? { "content-type": "application/json", "content-length": String(b.length) } : {}) };
  return req({ port: W2, method, path: `/api/ui/v1${p}`, headers }, b);
};
const unsynced = await waitFor("the unsynchronised core", async () => {
  const r = await ui2("GET", "/settings");
  return r.status === 200 ? r.json : null;
});
if (unsynced.lanca.clock_synced) console.log("the second core's clock counts as synchronised here: no 503 captured");
else {
  keep("/settings (clock not synchronised)", unsynced);
  const r = await ui2("PUT", "/settings", { lanca: { zones: ["home.arpa", "lan.example"], rotate_from: unsynced.lanca.fingerprint } });
  keep("PUT /settings lanca.zones (clock not synchronised)", { status: r.status, body: r.json });
}
fs.writeFileSync(outFile, JSON.stringify(out, null, 1) + "\n");
console.log(`captured ${Object.keys(out).length} responses into ${outFile}`);
stop();
process.exit(0);
