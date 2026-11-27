// Which `details.error` each browser reports for each kind of block (browser-extension.md §5;
// spec issue #335): every block_response type, custom_ip targets whose TLS fails or that reset,
// close or silently drop connections, and firewall refusals on IP-literal URLs. Page loads are
// read from webNavigation.onErrorOccurred, sub-resources from webRequest.onErrorOccurred, in an
// extension page; each value is then checked against src/shared/block-errors.ts. The extension
// isn't set up for page loads, so it doesn't act on them.
//
// The observed values are written to test-results/block-errors-<browser>-<what>.json and listed
// in the README. A silently dropped connection takes Chromium over two minutes to fail, so that
// case runs on Chromium only with PICKET_BROWSER_SLOW=1.

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { isBlockCandidate } from '../../src/shared/block-errors';
import type { Host } from '../../src/shared/host';
import type { BrowserKind, ExtGlobal } from './harness/browsers';
import type { FakeEdge } from './harness/edge';
import { expect, setUp, test, type Session, type Tab } from './harness/fixtures';
import { startDroppers, type Targets } from './harness/targets';
import { scaled } from './harness/time';

interface Case {
  what: string;
  url: string;
  host: Host['kind'];
  /** Whether the extension must probe the failure; per browser where they differ; null: only recorded. */
  candidate: boolean | Record<BrowserKind, boolean | null> | null;
  /** Browsers that can't show this case in this harness, and why. */
  notOn?: Partial<Record<BrowserKind, string>>;
  /** Run about a second after the load starts. */
  during?: () => void;
}

interface Observed {
  what: string;
  url: string;
  host: Host['kind'];
  error: string | null;
  candidate: boolean | null;
  probed: boolean | null;
  note?: string;
}

const SLOW = process.env.PICKET_BROWSER_SLOW === '1';

/** Chromium trusts the test CA by key, which also lifts a wrong name in a chain holding that key. */
const SPKI_NOTE = 'not shown: --ignore-certificate-errors-spki-list ignores every certificate error of a chain holding the trusted key';

/** Blocks the names the cases use, each with its block_response, at the edge. */
function blockAll(edge: FakeEdge): void {
  const cip = { type: 'custom_ip', ip: '127.0.0.1' } as const;
  edge.block('nxdomain.test', { mode: { type: 'nxdomain' } });
  edge.block('nodata.test', { mode: { type: 'nodata' } });
  edge.block('refused.test', { mode: { type: 'refused' } });
  edge.block('nullip.test', { mode: { type: 'null_ip' } });
  for (const n of ['reset', 'close', 'portclosed', 'tlsabort', 'tlsname', 'tlsuntrusted', 'drop']) {
    edge.block(`${n}.test`, { mode: cip });
  }
}

function nameCases(t: Targets): Case[] {
  const l = t.local;
  const port = (p: number): string => String(p);
  return [
    { what: 'nxdomain', url: `http://nxdomain.test:${port(l.web)}/`, host: 'name', candidate: true },
    { what: 'nodata', url: `http://nodata.test:${port(l.web)}/`, host: 'name', candidate: true },
    { what: 'refused (DNS rcode)', url: `http://refused.test:${port(l.web)}/`, host: 'name', candidate: true },
    // 0.0.0.0 and :: reach this host, where nobody listens on the port.
    { what: 'null_ip', url: `http://nullip.test:${port(l.refused)}/`, host: 'name', candidate: true },
    { what: 'custom_ip: resets after accepting', url: `http://reset.test:${port(l.reset)}/`, host: 'name', candidate: true },
    { what: 'custom_ip: closes without a reply', url: `http://close.test:${port(l.close)}/`, host: 'name', candidate: true },
    { what: 'custom_ip: connection refused', url: `http://portclosed.test:${port(l.refused)}/`, host: 'name', candidate: true },
    { what: 'custom_ip: TLS handshake failure', url: `https://tlsabort.test:${port(l.tlsAbort)}/`, host: 'name', candidate: true },
    {
      what: 'custom_ip: certificate for another name',
      url: `https://tlsname.test:${port(l.tlsWrongName)}/`,
      host: 'name',
      candidate: true,
      notOn: { chromium: SPKI_NOTE },
    },
    { what: 'custom_ip: untrusted certificate', url: `https://tlsuntrusted.test:${port(l.tlsUntrusted)}/`, host: 'name', candidate: true },
  ];
}

function ipCases(t: Targets, edge: FakeEdge): Case[] {
  const ip = t.ipTargets;
  if (ip === null) {
    return [];
  }
  const port = (p: number): string => String(p);
  return [
    { what: 'IP literal: firewall reject (new connection)', url: `http://${ip.ip}:${port(ip.gate)}/`, host: 'ip', candidate: true },
    // Recorded only: Chromium's error depends on when the reset arrives, and a reset can't be
    // told from a firewall's (the in-flight case below).
    { what: 'IP literal: host resets after accepting', url: `http://${ip.ip}:${port(ip.reset)}/`, host: 'ip', candidate: null },
    // Firefox reports this as NS_ERROR_NET_RESET, like a reset: probed there.
    { what: 'IP literal: host closes without a reply', url: `http://${ip.ip}:${port(ip.close)}/`, host: 'ip', candidate: { chromium: false, firefox: true } },
    { what: 'IP literal: untrusted certificate', url: `https://${ip.ip}:${port(ip.tlsUntrusted)}/`, host: 'ip', candidate: false },
    {
      what: 'IP literal: allow ends mid-load (reset, retried)',
      url: `http://${ip.ip}:${port(ip.gate)}/slow`,
      host: 'ip',
      candidate: true,
      during: () => {
        edge.endAllows(ip.ip);
      },
    },
  ];
}

const endOf = (tabId: number, url: string, since: number) => (e: { tabId: number; frameId: number; url: string; at: number; event: string }) =>
  e.tabId === tabId && e.frameId === 0 && e.url === url && e.at >= since && (e.event === 'onErrorOccurred' || e.event === 'onCompleted');

function expected(c: Case, kind: BrowserKind): boolean | null {
  return c.candidate === null || typeof c.candidate === 'boolean' ? c.candidate : c.candidate[kind];
}

/** Loads each case in `tab` and records the error webNavigation reported (null: it loaded). */
async function loadAll(ext: Session, tab: Tab, list: Case[], timeoutMs = scaled(30_000)): Promise<Observed[]> {
  const out: Observed[] = [];
  for (const c of list) {
    const note = c.notOn?.[ext.kind];
    if (note !== undefined) {
      out.push({ what: c.what, url: c.url, host: c.host, error: null, candidate: null, probed: null, note });
      continue;
    }
    const since = Date.now();
    // Not awaited first: Chromium's goto returns only once a response commits.
    const started = tab.goto(c.url);
    if (c.during !== undefined) {
      await new Promise((r) => setTimeout(r, 1000));
      c.during();
    }
    await started;
    await expect
      .poll(async () => (await ext.navEvents()).some(endOf(tab.id, c.url, since)), { timeout: timeoutMs, message: `the load of ${c.url} (${c.what}) to end` })
      .toBe(true);
    const ended = (await ext.navEvents()).find(endOf(tab.id, c.url, since));
    const error = ended?.event === 'onErrorOccurred' ? (ended.error ?? '(none)') : null;
    out.push({ what: c.what, url: c.url, host: c.host, error, candidate: expected(c, ext.kind), probed: error === null ? null : isBlockCandidate(error, c.host) });
  }
  return out;
}

function report(ext: Session, name: string, rows: Observed[]): void {
  mkdirSync('test-results', { recursive: true });
  writeFileSync(path.join('test-results', `block-errors-${ext.kind}-${name}.json`), `${JSON.stringify({ browser: `${ext.kind} ${ext.version}`, rows }, null, 2)}\n`);
  const line = (r: Observed): string =>
    `  ${r.what.padEnd(46)} ${(r.note ?? r.error ?? '(loaded)').padEnd(44)} ${r.probed === null ? '' : r.probed ? 'probed' : 'not probed'}`;
  console.log(`\n${ext.kind} ${ext.version}, ${name}:\n${rows.map(line).join('\n')}`);
}

function expectClassified(rows: Observed[]): void {
  for (const r of rows) {
    if (r.note !== undefined) {
      continue;
    }
    expect(r.error, `${r.what} should fail`).not.toBeNull();
    if (r.candidate !== null) {
      expect(r.probed, `${r.what}: ${String(r.error)} is ${r.candidate ? '' : 'not '}a block candidate`).toBe(r.candidate);
    }
  }
}

test.describe('details.error per block type', () => {
  test('page loads (webNavigation)', async ({ ext, edge, targets }) => {
    blockAll(edge);
    const ip = targets.ipTargets?.ip;
    if (ip !== undefined) {
      // The gate's IP: refused until allowed. The in-flight case allows it, then ends the allow.
      edge.firewall.add(ip);
    }
    const tab = await ext.newTab();
    const list = [...nameCases(targets), ...ipCases(targets, edge)];
    const rows: Observed[] = [];
    for (const c of list) {
      if (c.during !== undefined && ip !== undefined) {
        edge.addAllow({ kind: 'ip', target: ip, expires_at: Math.floor(Date.now() / 1000) + 600 });
        await targets.syncGate();
      }
      rows.push(...(await loadAll(ext, tab, [c])));
    }
    report(ext, 'page-loads', rows);
    expectClassified(rows);
  });

  test('sub-resources (webRequest)', async ({ ext, edge, targets }) => {
    // Detection needs its optional permissions, granted in the options page.
    await setUp(ext, edge, { detection: true });
    blockAll(edge);
    const ip = targets.ipTargets?.ip;
    if (ip !== undefined) {
      edge.firewall.add(ip);
    }
    const list = [...nameCases(targets), ...ipCases(targets, edge)].filter((c) => c.during === undefined && c.notOn?.[ext.kind] === undefined);
    const src = (c: Case): string => `${c.url}pixel.png`;
    const tab = await ext.newTab();
    await tab.goto(targets.url('site.test', `/subresources?${list.map((c) => `src=${encodeURIComponent(src(c))}`).join('&')}`));
    const errorsOf = (): Promise<{ url: string; error: string }[]> => ext.observer.run(() => (globalThis as unknown as ExtGlobal).picketRequestErrors ?? [], null);
    await expect
      .poll(async () => {
        const got = await errorsOf();
        return list.filter((c) => !got.some((e) => e.url === src(c))).map((c) => c.what);
      }, { timeout: scaled(30_000), message: 'every sub-resource to fail' })
      .toEqual([]);
    const errors = await errorsOf();
    const rows = list.map((c): Observed => {
      const error = errors.find((e) => e.url === src(c))?.error ?? null;
      return { what: c.what, url: c.url, host: c.host, error, candidate: expected(c, ext.kind), probed: error === null ? null : isBlockCandidate(error, c.host) };
    });
    report(ext, 'sub-resources', rows);
    expectClassified(rows);
  });

  test.describe('Firefox with HTTPS-First', () => {
    // Playwright turns HTTPS-First off; Firefox has it on for typed http: URLs.
    test.use({ firefoxPrefs: { 'dom.security.https_first': true } });
    test('page loads (webNavigation)', async ({ ext, edge, targets, kind }) => {
      test.skip(kind !== 'firefox', 'a Firefox setting');
      blockAll(edge);
      const tab = await ext.newTab();
      const rows = await loadAll(ext, tab, nameCases(targets).filter((c) => c.url.startsWith('http:')));
      report(ext, 'page-loads-https-first', rows);
      expectClassified(rows);
    });
  });

  test.describe('silently dropped connections', () => {
    // Firefox gives up connecting after this many seconds (default 90).
    test.use({ firefoxPrefs: { 'network.http.connection-timeout': 5 } });
    test('page loads (webNavigation)', async ({ ext, edge, targets, kind }) => {
      test.skip(kind === 'chromium' && !SLOW, 'Chromium takes over two minutes to time out a connection (PICKET_BROWSER_SLOW=1 runs it)');
      test.setTimeout(scaled(600_000));
      blockAll(edge);
      const ipt = targets.ipTargets;
      const droppers = await startDroppers(ipt === null ? ['127.0.0.1'] : ['127.0.0.1', ipt.ip]);
      const [lo, ip] = droppers;
      try {
        if (lo === undefined) {
          throw new Error('no dropper');
        }
        const list: Case[] = [{ what: 'custom_ip: drops connections', url: `http://drop.test:${String(lo.port)}/`, host: 'name', candidate: true }];
        if (ip !== undefined && ipt !== null) {
          list.push({ what: 'IP literal: firewall drop', url: `http://${ipt.ip}:${String(ip.port)}/`, host: 'ip', candidate: true });
        }
        const tab = await ext.newTab();
        const rows = await loadAll(ext, tab, list, 300_000);
        report(ext, 'page-loads-dropped', rows);
        expectClassified(rows);
      } finally {
        for (const d of droppers) {
          d.stop();
        }
      }
    });
  });
});
