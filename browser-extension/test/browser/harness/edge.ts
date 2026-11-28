// A fake picket-edge for the browser tests: one HTTPS listener (the test CA's certificate for
// 127.0.0.1) with DoH (`/dns-query`, GET and POST) and the bypass API (`/v1/temporary-allows`,
// api.md §6). The browsers resolve every name through it (Chromium's secure DNS, Firefox's TRR),
// so it decides what each name answers, as a profile's block_response would:
//
// - a blocked name gets its block mode (nxdomain, nodata, refused, null_ip, custom_ip), with
//   EDE 15 `block=<id> …` (edge.md §4), and goes into this device's recent blocks;
// - the extension's probe (`X-Picket-Client: extension`) is answered from the recent blocks only
//   (edge.md §12): EDE 15 with `block=` on a hit, NOERROR without EDE on a miss; a PTR probe for
//   an IP in `firewall` gets NXDOMAIN with EDE 15 `cause=firewall` while no allow holds for it;
// - other `.test` names resolve to 127.0.0.1 (the local test servers); anything else is NXDOMAIN,
//   so nothing reaches the real network.
//
// A temporary allow lifts the block (and the firewall check for an IP) until it expires. Every
// request is logged for the tests to check.

import { createSocket, type Socket } from 'node:dgram';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';

import type { KeyPair } from './certs';
import {
  buildReply,
  EDE_BLOCKED,
  ipOfReverseName,
  parseQuery,
  RCODE_NOERROR,
  RCODE_NXDOMAIN,
  RCODE_REFUSED,
  TYPE_A,
  TYPE_AAAA,
  TYPE_PTR,
  type Answer,
  type Query,
} from './dns';

export type BlockMode =
  | { type: 'nxdomain' }
  | { type: 'nodata' }
  | { type: 'refused' }
  | { type: 'null_ip' }
  | { type: 'custom_ip'; ip: string };

export interface BlockRule {
  mode: BlockMode;
  bundle?: string;
  head?: string;
  lookup?: string;
  verdict?: string;
  /** Browser queries after an allow that still get the blocked answer (a stale cached answer). */
  staleAfterAllow?: number;
}

export interface AllowView {
  allow_id: string;
  kind: 'dns' | 'ip';
  target: string;
  subdomains?: boolean;
  expires_at: number;
  retry_after_s?: number;
}

export interface Hit {
  at: number;
  method: string;
  path: string;
  client: string | undefined;
  origin: string | undefined;
  cookie: string | undefined;
  /** DoH: the question. */
  name?: string;
  qtype?: number;
  /** DoH: the answer's rcode and whether it carried a block EDE. */
  rcode?: number;
  blocked?: boolean;
  /** PATCH: the parsed body. */
  body?: unknown;
  status?: number;
  /** The bypass API's JSON reply. */
  reply?: unknown;
}

interface RecentBlock {
  blockId: string;
  name: string;
  rule: BlockRule;
  /** When the name was last answered blocked (ms). */
  at: number;
}

/** An allow as the fake keeps it. */
type StoredAllow = AllowView & {
  /** Blocked answers still to give after the allow (`staleAfterAllow`). */
  stale: number;
  /** A DNS allow's block time (ms), for an edge-style `retry_after_s`. */
  blockAt?: number;
};

const B32 = 'abcdefghijklmnopqrstuvwxyz234567';
let idCounter = 0;
function newId(): string {
  idCounter += 1;
  let n = Date.now() * 1000 + idCounter;
  let s = '';
  for (let i = 0; i < 8; i++) {
    s = (B32[n % 32] ?? 'a') + s;
    n = Math.floor(n / 32);
  }
  return s;
}

/** EXTRA-TEXT value encoding (edge.md §4): bytes outside `A-Za-z0-9-._~` percent-encoded. */
function enc(v: string): string {
  return [...Buffer.from(v, 'utf8')]
    .map((b) => (/[A-Za-z0-9\-._~]/.test(String.fromCharCode(b)) ? String.fromCharCode(b) : `%${b.toString(16).toUpperCase().padStart(2, '0')}`))
    .join('');
}

/** EXTRA-TEXT in the edge's token order: `bundle=<id>@<head> block=<id>`, `lookup=<p> verdict=<v> block=<id>`. */
function extraText(b: RecentBlock): string {
  const t: string[] = [];
  if (b.rule.bundle !== undefined) {
    t.push(`bundle=${enc(b.rule.bundle)}${b.rule.head === undefined ? '' : `@${enc(b.rule.head)}`}`);
  }
  if (b.rule.lookup !== undefined) {
    t.push(`lookup=${enc(b.rule.lookup)}`);
  }
  if (b.rule.verdict !== undefined) {
    t.push(`verdict=${enc(b.rule.verdict)}`);
  }
  t.push(`block=${b.blockId}`);
  return t.join(' ');
}

/** EDE 4 *Forged Answer*, which the edge adds to sinkhole answers that carry records. */
const EDE_FORGED = 4;

const nameOf = (n: string): string => n.toLowerCase().replace(/\.$/, '');

export interface PatchReply {
  status: number;
  code: string;
  message: string;
  index?: number;
}

export class FakeEdge {
  readonly hits: Hit[] = [];
  /** Names blocked for this device, and their block response. */
  readonly blocks = new Map<string, BlockRule>();
  /** IPs Picket holds no grant for (a PTR probe answers `cause=firewall`). */
  readonly firewall = new Set<string>();
  /** The `retry_after_s` of DNS allows a PATCH creates or re-times (IP allows get 0, as on the edge). */
  retryAfterS = 1;
  /**
   * DNS allows get the edge's `retry_after_s` instead: block time + max(65 s, block TTL + 5 s) − now, at most expires_at − 5 s − now
   * (edge.md §12; apps/picket-edge bypass `retry_after`).
   */
  edgeRetry = false;
  /** TTL (and SOA minimum) of blocked answers: how long a browser may cache them. */
  blockTtl = 1;
  /** Error replies for the next PATCHes, in order. */
  readonly patchErrors: PatchReply[] = [];
  /** Called when allows change (the IP gates follow them). */
  onAllowsChanged: () => void = () => undefined;

  private readonly recent = new Map<string, RecentBlock>();
  private allows: StoredAllow[] = [];
  private server!: Server;
  private port = 0;
  private native: Socket | null = null;

  constructor(private readonly cert: KeyPair) {}

  get origin(): string {
    return `https://127.0.0.1:${String(this.port)}`;
  }

  get dohUrl(): string {
    return `${this.origin}/dns-query`;
  }

  async start(): Promise<this> {
    this.server = createServer({ key: this.cert.key, cert: this.cert.chain }, (req, res) => {
      this.handle(req, res).catch((e: unknown) => {
        res.writeHead(500);
        res.end(String(e));
      });
    });
    await new Promise<void>((resolve) => this.server.listen(0, '127.0.0.1', resolve));
    this.port = (this.server.address() as AddressInfo).port;
    return this;
  }

  /**
   * Also answers plain DNS over UDP on `host`:53, as a LAN resolver would, for a browser that
   * resolves natively (the system resolver, `/etc/resolv.conf`) instead of over DoH. Its queries
   * count as the browser's lookups (`method` `UDP`). Needs the right to bind port 53.
   */
  async startNative(host: string): Promise<void> {
    const sock = createSocket('udp4');
    sock.on('message', (msg, from) => {
      const hit: Hit = { at: Date.now(), method: 'UDP', path: '/dns-query', client: undefined, origin: undefined, cookie: undefined };
      let q: Query;
      try {
        q = parseQuery(msg);
      } catch {
        return;
      }
      hit.name = q.name;
      hit.qtype = q.qtype;
      const { answer, blocked } = this.resolve(q, false);
      hit.rcode = answer.rcode;
      hit.blocked = blocked;
      this.hits.push(hit);
      sock.send(buildReply(q, answer), from.port, from.address);
    });
    await new Promise<void>((resolve, reject) => {
      sock.once('error', reject);
      sock.bind(53, host, () => {
        sock.off('error', reject);
        resolve();
      });
    });
    this.native = sock;
  }

  async close(): Promise<void> {
    const native = this.native;
    if (native !== null) {
      await new Promise<void>((resolve) => native.close(() => { resolve(); }));
    }
    this.server.closeAllConnections();
    await new Promise<void>((resolve) => this.server.close(() => { resolve(); }));
  }

  block(name: string, rule: BlockRule): void {
    this.blocks.set(nameOf(name), rule);
  }

  /** The device's active allows (by this machine's clock: the edge's). */
  activeAllows(): AllowView[] {
    const now = Math.floor(Date.now() / 1000);
    return this.allows
      .filter((a) => a.expires_at > now)
      .map((a) => ({ allow_id: a.allow_id, kind: a.kind, target: a.target, expires_at: a.expires_at, ...(a.subdomains === undefined ? {} : { subdomains: a.subdomains }) }));
  }

  /** Adds an allow directly (an allow made elsewhere, e.g. in an earlier session). */
  addAllow(a: Omit<AllowView, 'allow_id'>): AllowView {
    const allow = { ...a, allow_id: newId(), stale: 0 };
    this.allows.push(allow);
    this.onAllowsChanged();
    return { ...a, allow_id: allow.allow_id };
  }

  /** Ends the active allows for `target` now (as their expiry would). */
  endAllows(target: string): void {
    const now = Math.floor(Date.now() / 1000);
    for (const a of this.allows) {
      if (a.target === target && a.expires_at > now) {
        a.expires_at = now;
      }
    }
    this.onAllowsChanged();
  }

  ipAllowed(ip: string): boolean {
    return this.activeAllows().some((a) => a.kind === 'ip' && a.target === ip);
  }

  /** The DoH requests the extension's probe made (`X-Picket-Client: extension`). */
  probes(): Hit[] {
    return this.hits.filter((h) => h.path === '/dns-query' && h.client === 'extension');
  }

  /** The DoH queries the browser made to resolve names. */
  lookups(name?: string): Hit[] {
    return this.hits.filter((h) => h.path === '/dns-query' && h.client === undefined && (name === undefined || h.name === nameOf(name)));
  }

  apiCalls(method?: string): Hit[] {
    return this.hits.filter((h) => h.path === '/v1/temporary-allows' && (method === undefined || h.method === method));
  }

  private allowFor(name: string): StoredAllow | undefined {
    const now = Math.floor(Date.now() / 1000);
    return this.allows.find(
      (a) => a.kind === 'dns' && a.expires_at > now && (a.target === name || (a.subdomains === true && name.endsWith(`.${a.target}`))),
    );
  }

  private ruleFor(name: string): BlockRule | undefined {
    return this.blocks.get(name);
  }

  /**
   * The answer a block mode gives to a query of `qtype`, with the block's EDE 15, plus EDE 4 when
   * it carries records (as the edge's `write_block`); a sinkhole answers NODATA for other types.
   */
  private blockedAnswer(b: RecentBlock, qtype: number): Answer {
    const ede = [{ code: EDE_BLOCKED, text: extraText(b) }];
    const neg = { negativeTtl: this.blockTtl, ttl: this.blockTtl, ede };
    const sinkhole = (a: string[], aaaa: string[]): Answer => {
      const records = (qtype === TYPE_A && a.length > 0) || (qtype === TYPE_AAAA && aaaa.length > 0);
      return records ? { rcode: RCODE_NOERROR, a, aaaa, ttl: this.blockTtl, ede: [...ede, { code: EDE_FORGED, text: '' }] } : { rcode: RCODE_NOERROR, ...neg };
    };
    switch (b.rule.mode.type) {
      case 'nxdomain':
        return { rcode: RCODE_NXDOMAIN, ...neg };
      case 'nodata':
        return { rcode: RCODE_NOERROR, ...neg };
      case 'refused':
        return { rcode: RCODE_REFUSED, ttl: this.blockTtl, ede };
      case 'null_ip':
        return sinkhole(['0.0.0.0'], ['::']);
      case 'custom_ip':
        return sinkhole([b.rule.mode.ip], []);
    }
  }

  private resolve(q: Query, probe: boolean): { answer: Answer; blocked: boolean } {
    if (probe && q.qtype === TYPE_PTR) {
      const ip = ipOfReverseName(q.name);
      if (ip !== null && this.firewall.has(ip) && !this.ipAllowed(ip)) {
        return { answer: { rcode: RCODE_NXDOMAIN, negativeTtl: 0, ede: [{ code: EDE_BLOCKED, text: 'cause=firewall' }] }, blocked: true };
      }
      return { answer: { rcode: RCODE_NOERROR, negativeTtl: 0 }, blocked: false };
    }
    // Chromium asks HTTPS records of `_<port>._https.<name>`: the name's block applies.
    const name = q.name.replace(/^_\d+\._https\./, '');
    if (probe) {
      const hit = this.recent.get(name);
      if (hit !== undefined && this.allowFor(name) === undefined) {
        return { answer: this.blockedAnswer(hit, q.qtype), blocked: true };
      }
      return { answer: { rcode: RCODE_NOERROR, negativeTtl: 0 }, blocked: false };
    }
    const rule = this.ruleFor(name);
    if (rule !== undefined) {
      const allow = this.allowFor(name);
      if (allow === undefined || allow.stale > 0) {
        // One stale answer per resolution: counted on its A query.
        if (allow !== undefined && q.qtype === TYPE_A) {
          allow.stale -= 1;
        }
        const b: RecentBlock = { blockId: this.recent.get(name)?.blockId ?? newId(), name, rule, at: Date.now() };
        this.recent.set(name, b);
        return { answer: this.blockedAnswer(b, q.qtype), blocked: true };
      }
    }
    if (name.endsWith('.test')) {
      return { answer: { rcode: RCODE_NOERROR, a: ['127.0.0.1'], negativeTtl: 1, ttl: 1 }, blocked: false };
    }
    // Short-lived too: a browser that appends a search domain (`<name>.localdomain`) keeps the
    // last answer of its search, this one.
    return { answer: { rcode: RCODE_NXDOMAIN, negativeTtl: 1 }, blocked: false };
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const chunks: Buffer[] = [];
    for await (const c of req) {
      chunks.push(c as Buffer);
    }
    const body = Buffer.concat(chunks);
    const url = new URL(req.url ?? '/', this.origin);
    const header = (n: string): string | undefined => {
      const v = req.headers[n];
      return Array.isArray(v) ? v.join(', ') : v;
    };
    const hit: Hit = {
      at: Date.now(),
      method: req.method ?? '',
      path: url.pathname,
      client: header('x-picket-client'),
      origin: header('origin'),
      cookie: header('cookie'),
    };
    this.hits.push(hit);
    if (url.pathname === '/dns-query') {
      const raw = req.method === 'POST' ? body : Buffer.from(url.searchParams.get('dns') ?? '', 'base64url');
      let q: Query;
      try {
        q = parseQuery(raw);
      } catch {
        res.writeHead(400);
        res.end();
        return;
      }
      hit.name = q.name;
      hit.qtype = q.qtype;
      const { answer, blocked } = this.resolve(q, hit.client === 'extension');
      hit.rcode = answer.rcode;
      hit.blocked = blocked;
      res.writeHead(200, { 'content-type': 'application/dns-message', 'cache-control': 'no-store' });
      res.end(buildReply(q, answer));
      return;
    }
    if (url.pathname === '/v1/temporary-allows') {
      this.api(req.method ?? '', hit, body, res);
      return;
    }
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end('{"error":{"code":"not_found","message":"no such path"}}');
  }

  private json(res: ServerResponse, hit: Hit, status: number, value: unknown): void {
    hit.status = status;
    hit.reply = value;
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify(value));
  }

  private error(res: ServerResponse, hit: Hit, e: PatchReply): void {
    this.json(res, hit, e.status, { error: { code: e.code, message: e.message, ...(e.index === undefined ? {} : { index: e.index }) } });
  }

  private api(method: string, hit: Hit, body: Buffer, res: ServerResponse): void {
    // As the edge (apps/picket-edge bypass): no preflight, the extension header, and an
    // extension Origin when there is one.
    if (method === 'OPTIONS') {
      this.error(res, hit, { status: 403, code: 'forbidden', message: 'preflight refused' });
      return;
    }
    if (hit.client?.toLowerCase() !== 'extension') {
      this.error(res, hit, { status: 403, code: 'forbidden', message: 'X-Picket-Client: extension is required' });
      return;
    }
    const origin = hit.origin?.toLowerCase();
    if (origin !== undefined && !origin.startsWith('chrome-extension://') && !origin.startsWith('moz-extension://')) {
      this.error(res, hit, { status: 403, code: 'forbidden', message: 'origin refused' });
      return;
    }
    if (method === 'GET') {
      this.json(res, hit, 200, this.activeAllows());
      return;
    }
    if (method !== 'PATCH') {
      this.error(res, hit, { status: 405, code: 'method', message: 'method not allowed' });
      return;
    }
    let entries: unknown;
    try {
      entries = JSON.parse(body.toString('utf8'));
    } catch {
      this.error(res, hit, { status: 400, code: 'invalid', message: 'not JSON' });
      return;
    }
    hit.body = entries;
    const queued = this.patchErrors.shift();
    if (queued !== undefined) {
      this.error(res, hit, queued);
      return;
    }
    if (!Array.isArray(entries) || entries.length === 0) {
      this.error(res, hit, { status: 400, code: 'invalid', message: 'expected a non-empty array' });
      return;
    }
    const now = Math.floor(Date.now() / 1000);
    // All or nothing: every entry is checked before any is applied.
    const changes: (() => AllowView | null)[] = [];
    for (const [index, raw] of (entries as unknown[]).entries()) {
      const e = raw as { block_id?: unknown; ip?: unknown; allow_id?: unknown; expires_at?: unknown; subdomains?: unknown };
      if (typeof e.expires_at !== 'number' || !Number.isSafeInteger(e.expires_at)) {
        this.error(res, hit, { status: 400, code: 'invalid', message: 'expires_at must be Unix seconds', index });
        return;
      }
      const expires = e.expires_at;
      if (typeof e.block_id === 'string') {
        const b = [...this.recent.values()].find((r) => r.blockId === e.block_id);
        if (b === undefined) {
          this.error(res, hit, { status: 409, code: 'no_block', message: 'no such recent block', index });
          return;
        }
        const subdomains = e.subdomains === true;
        changes.push(() => this.upsert('dns', b.name, expires, now, subdomains ? true : undefined, b.rule.staleAfterAllow ?? 0, b.at));
      } else if (typeof e.ip === 'string') {
        const ip = e.ip;
        if (!this.firewall.has(ip)) {
          this.error(res, hit, { status: 409, code: 'not_blocked', message: 'Picket does not block this IP', index });
          return;
        }
        changes.push(() => this.upsert('ip', ip, expires, now, undefined, 0));
      } else if (typeof e.allow_id === 'string') {
        const a = this.allows.find((x) => x.allow_id === e.allow_id && x.expires_at > now);
        if (a === undefined) {
          this.error(res, hit, { status: 409, code: 'not_found', message: 'no such active allow', index });
          return;
        }
        changes.push(() => {
          a.expires_at = expires;
          return expires > now ? { ...a } : null;
        });
      } else {
        this.error(res, hit, { status: 400, code: 'invalid', message: 'an entry names block_id, ip or allow_id', index });
        return;
      }
    }
    const touched = new Set(changes.map((c) => c()).filter((a) => a !== null).map((a) => a.allow_id));
    this.onAllowsChanged();
    this.json(
      res,
      hit,
      200,
      this.activeAllows().map((a) => (touched.has(a.allow_id) ? { ...a, retry_after_s: this.retryAfter(a.allow_id) } : a)),
    );
  }

  /** `retry_after_s` for an allow just created or re-timed: 0 for an IP allow (as the edge). */
  private retryAfter(id: string): number {
    const a = this.allows.find((x) => x.allow_id === id);
    if (a === undefined || a.kind === 'ip') {
      return 0;
    }
    if (!this.edgeRetry || a.blockAt === undefined) {
      return this.retryAfterS;
    }
    // As the edge: never later than 5 s before the allow ends (expires_at is Unix seconds).
    const end = Math.min(a.blockAt + Math.max(65, this.blockTtl + 5) * 1000, (a.expires_at - 5) * 1000);
    return Math.max(0, Math.trunc((end - Date.now()) / 1000));
  }

  private upsert(kind: 'dns' | 'ip', target: string, expires: number, now: number, subdomains: true | undefined, stale: number, blockAt?: number): AllowView | null {
    let a = this.allows.find((x) => x.kind === kind && x.target === target && x.expires_at > now);
    if (expires <= now) {
      if (a !== undefined) {
        a.expires_at = expires;
      }
      return null;
    }
    if (a === undefined) {
      a = { allow_id: newId(), kind, target, expires_at: expires, stale };
      this.allows.push(a);
    } else {
      a.expires_at = expires;
    }
    if (blockAt !== undefined) {
      a.blockAt = blockAt;
    }
    if (subdomains !== undefined) {
      a.subdomains = subdomains;
    }
    return a;
  }
}
