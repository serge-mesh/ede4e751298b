// The local servers the test pages load from, standing in for the sites and for what a block
// sends a browser to (browser-extension.md §5):
//
// - `web`: plain HTTP on 127.0.0.1 for every `.test` name that resolves (pages, a page with
//   sub-resources, a pixel);
// - custom_ip targets on 127.0.0.1: one that resets each connection, one that closes it without
//   a reply, one whose TLS handshake fails, one with a certificate for another name, one with a
//   certificate nobody trusts, and a port nobody listens on;
// - on a local non-loopback IPv4 (the extension never probes loopback: `isProbeableIp`): a port
//   nobody listens on, a server that resets connections right after accepting them, one that
//   closes them, one with an untrusted certificate, and the "gate", which behaves like UniFi's
//   Block All policy with Picket's check: while the edge holds no IP allow for the address it
//   refuses new connections (a reject: RST to the SYN); an allow opens it; when the allow ends,
//   connections still open are reset and new ones refused again.

import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createServer as createHttp, type IncomingMessage, type ServerResponse } from 'node:http';
import { createServer as createHttps } from 'node:https';
import { connect, createServer as createTcp, type AddressInfo, type Server, type Socket } from 'node:net';
import { networkInterfaces } from 'node:os';

import type { TestCerts } from './certs';

/** A 1×1 transparent PNG. */
const PIXEL = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64');

/** The first non-loopback IPv4 address of this machine, or null. */
export function localIpv4(): string | null {
  for (const list of Object.values(networkInterfaces())) {
    for (const a of list ?? []) {
      // Link-local isn't probed by the extension either.
      if (a.family === 'IPv4' && !a.internal && !a.address.startsWith('169.254.')) {
        return a.address;
      }
    }
  }
  return null;
}

const escapeHtml = (s: string): string => s.replace(/[&<>"']/g, (c) => `&#${String(c.charCodeAt(0))};`);

function page(res: ServerResponse, title: string, body: string): void {
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
  res.end(`<!doctype html><html><head><meta charset="utf-8"><title>${escapeHtml(title)}</title></head><body>${body}</body></html>`);
}

/** The test sites' pages; `host` is the Host header (name:port). */
function site(req: IncomingMessage, res: ServerResponse): void {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
  if (url.pathname === '/pixel.png') {
    res.writeHead(200, { 'content-type': 'image/png', 'cache-control': 'no-store' });
    res.end(PIXEL);
    return;
  }
  if (url.pathname === '/loop') {
    res.writeHead(302, { location: '/loop', 'cache-control': 'no-store' });
    res.end();
    return;
  }
  if (url.pathname === '/slow') {
    // Answers after 3 s: a load still in flight when an allow ends.
    setTimeout(() => {
      page(res, `Loaded ${url.hostname}`, `<h1 id="loaded">${escapeHtml(url.hostname + url.pathname)}</h1>`);
    }, 3000);
    return;
  }
  if (url.pathname === '/subresources') {
    // `?src=<url>&src=<url>`: one image per URL.
    const imgs = url.searchParams.getAll('src').map((s) => `<img src="${escapeHtml(s)}" alt="">`);
    page(res, `Sub-resources on ${url.hostname}`, `<h1 id="loaded">${escapeHtml(url.hostname)}</h1>${imgs.join('')}`);
    return;
  }
  page(res, `Loaded ${url.hostname}`, `<h1 id="loaded">${escapeHtml(url.hostname + url.pathname)}</h1>`);
}

async function listen(server: Server, host: string, port = 0): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      resolve();
    });
  });
  return (server.address() as AddressInfo).port;
}

/** A port on `host` that nobody listens on (bound, then released). */
async function freePort(host: string): Promise<number> {
  const s = createTcp();
  const port = await listen(s, host);
  await new Promise<void>((resolve) => s.close(() => { resolve(); }));
  return port;
}

/**
 * A free port below the kernel's ephemeral range, for a listener that closes and opens again:
 * a port from that range (`listen(0)`) can meanwhile become the source port of a connection.
 */
async function stablePort(host: string): Promise<number> {
  let low = 32768;
  try {
    low = Number(readFileSync('/proc/sys/net/ipv4/ip_local_port_range', 'utf8').trim().split(/\s+/)[0]) || low;
  } catch {
    // Not Linux: the usual start of the range.
  }
  const min = 10_000;
  const span = Math.max(1000, low - min);
  for (let i = 0; i < 100; i++) {
    const port = min + Math.floor(Math.random() * span);
    const s = createTcp();
    const ok = await listen(s, host, port).then(
      () => true,
      () => false,
    );
    if (ok) {
      await new Promise<void>((resolve) => s.close(() => { resolve(); }));
      return port;
    }
  }
  throw new Error(`no free port below ${String(low)} on ${host}`);
}

/** Resets every connection (RST, no data): a firewall reject with a TCP reset, or a custom_ip that resets. */
function resetter(): Server {
  return createTcp((sock: Socket) => {
    sock.resetAndDestroy();
  });
}

/** Accepts, then closes without a byte. */
function closer(): Server {
  return createTcp((sock: Socket) => {
    sock.end();
  });
}

/** Reads the TLS ClientHello and answers with a fatal handshake_failure alert. */
function tlsAborter(): Server {
  return createTcp((sock: Socket) => {
    sock.once('data', () => {
      sock.end(Buffer.from([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]));
    });
    sock.on('error', () => undefined);
  });
}

/**
 * A port whose SYNs go unanswered, as at a host that silently drops connections: a listener in a
 * stopped process, its accept queue filled first, so the kernel drops further SYNs.
 */
export async function startDropper(host: string): Promise<{ port: number; stop(): void }> {
  const child = spawn(
    process.execPath,
    [
      '-e',
      `const s = require('node:net').createServer(); s.listen({ port: 0, host: ${JSON.stringify(host)}, backlog: 1 }, () => { process.stdout.write(String(s.address().port) + '\\n'); process.kill(process.pid, 'SIGSTOP'); });`,
    ],
    { stdio: ['ignore', 'pipe', 'ignore'] },
  );
  let port: number;
  try {
    port = await new Promise<number>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error('the dropping listener did not start'));
      }, 10_000);
      child.stdout.once('data', (d: Buffer) => {
        clearTimeout(timer);
        resolve(Number(d.toString().trim()));
      });
      child.once('error', (e) => {
        clearTimeout(timer);
        reject(e);
      });
      child.once('exit', (code) => {
        clearTimeout(timer);
        reject(new Error(`the dropping listener on ${host} exited (${String(code)})`));
      });
    });
  } catch (e) {
    // SIGKILL ends a stopped process too.
    child.kill('SIGKILL');
    throw e;
  }
  // Fill the accept queue (backlog + 1 on Linux), and keep those connections open.
  const fillers: Socket[] = [];
  for (let i = 0; i < 4; i++) {
    const s = connect(port, host);
    s.on('error', () => undefined);
    fillers.push(s);
  }
  await new Promise((r) => setTimeout(r, 300));
  return {
    port,
    stop: () => {
      for (const s of fillers) {
        s.destroy();
      }
      child.kill('SIGKILL');
    },
  };
}

/** Starts a dropper on each host, in order; if one fails, the ones started are stopped. */
export async function startDroppers(hosts: readonly string[]): Promise<{ port: number; stop(): void }[]> {
  const started: { port: number; stop(): void }[] = [];
  try {
    for (const h of hosts) {
      started.push(await startDropper(h));
    }
    return started;
  } catch (e) {
    for (const d of started) {
      d.stop();
    }
    throw e;
  }
}

export interface Endpoints {
  web: number;
  reset: number;
  close: number;
  tlsAbort: number;
  tlsWrongName: number;
  tlsUntrusted: number;
  /** Nobody listens. */
  refused: number;
}

export interface IpEndpoints {
  ip: string;
  refused: number;
  reset: number;
  close: number;
  tlsUntrusted: number;
  /** Refuses connections until the edge allows the IP, then serves pages (see the header). */
  gate: number;
}

/** The firewall in front of a site at an IP literal: open only while an IP allow holds. */
class Gate {
  private readonly server = createHttp(site);
  private readonly sockets = new Set<Socket>();
  private listening = false;
  private change: Promise<void> = Promise.resolve();

  constructor(
    readonly ip: string,
    readonly port: number,
  ) {
    this.server.on('connection', (sock: Socket) => {
      this.sockets.add(sock);
      sock.on('error', () => undefined);
      sock.on('close', () => this.sockets.delete(sock));
    });
  }

  /** Opens or shuts the gate (changes run in order). */
  set(open: boolean): Promise<void> {
    const next = this.change.then(async () => {
      if (open && !this.listening) {
        await listen(this.server, this.ip, this.port);
        this.listening = true;
      } else if (!open && this.listening) {
        this.listening = false;
        const closed = new Promise<void>((resolve) => this.server.close(() => { resolve(); }));
        // Connections still open are reset, as the firewall drops their flow with a reset.
        for (const s of this.sockets) {
          s.resetAndDestroy();
        }
        await closed;
      }
    });
    // A failed change fails its caller; later changes still run.
    this.change = next.catch(() => undefined);
    return next;
  }
}

export class Targets {
  readonly local: Endpoints = { web: 0, reset: 0, close: 0, tlsAbort: 0, tlsWrongName: 0, tlsUntrusted: 0, refused: 0 };
  ipTargets: IpEndpoints | null = null;
  private readonly servers: Server[] = [];
  private readonly sockets = new Set<Socket>();
  private gate: Gate | null = null;
  private gateTimer: ReturnType<typeof setInterval> | undefined;

  constructor(
    private readonly certs: TestCerts,
    /** Whether the edge holds an IP allow for `ip` (the gate serves only then). */
    private readonly ipAllowed: (ip: string) => boolean,
  ) {}

  private track(s: Server): Server {
    s.on('connection', (sock: Socket) => {
      this.sockets.add(sock);
      sock.on('error', () => undefined);
      sock.on('close', () => this.sockets.delete(sock));
    });
    this.servers.push(s);
    return s;
  }

  async start(): Promise<this> {
    const lo = '127.0.0.1';
    const l = this.local;
    l.web = await listen(this.track(createHttp(site)), lo);
    l.reset = await listen(this.track(resetter()), lo);
    l.close = await listen(this.track(closer()), lo);
    l.tlsAbort = await listen(this.track(tlsAborter()), lo);
    l.tlsWrongName = await listen(this.track(createHttps({ key: this.certs.wrongName.key, cert: this.certs.wrongName.chain }, site)), lo);
    l.tlsUntrusted = await listen(this.track(createHttps({ key: this.certs.untrusted.key, cert: this.certs.untrusted.chain }, site)), lo);
    l.refused = await freePort(lo);
    const ip = localIpv4();
    if (ip !== null) {
      this.gate = new Gate(ip, await stablePort(ip));
      this.ipTargets = {
        ip,
        refused: await freePort(ip),
        reset: await listen(this.track(resetter()), ip),
        close: await listen(this.track(closer()), ip),
        tlsUntrusted: await listen(this.track(createHttps({ key: this.certs.untrusted.key, cert: this.certs.untrusted.chain }, site)), ip),
        gate: this.gate.port,
      };
      await this.syncGate();
      // Allows also end by time.
      this.gateTimer = setInterval(() => {
        void this.syncGate();
      }, 100);
    }
    return this;
  }

  /** Opens or shuts the gate as the edge's IP allows say (the edge calls it when they change). */
  syncGate(): Promise<void> {
    return this.gate === null ? Promise.resolve() : this.gate.set(this.ipAllowed(this.gate.ip));
  }

  /** `http://<name>:<web port><path>`. */
  url(name: string, path = '/'): string {
    return `http://${name}:${String(this.local.web)}${path}`;
  }

  async close(): Promise<void> {
    clearInterval(this.gateTimer);
    await this.gate?.set(false);
    for (const s of this.sockets) {
      s.destroy();
    }
    await Promise.all(this.servers.map((s) => new Promise<void>((resolve) => s.close(() => { resolve(); }))));
  }
}
