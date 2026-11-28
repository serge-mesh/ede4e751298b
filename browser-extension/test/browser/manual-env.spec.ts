// A long-running environment for checking the extension by hand in real browsers (issue #43):
// the fake edge (DoH and the bypass API over HTTPS with the test CA), the local sites and block
// targets, kept up until the run is stopped. Runs only with PICKET_MANUAL_ENV=<file>, where it
// writes the URLs, the CA and a control port, as JSON:
//
//   PICKET_MANUAL_ENV=/tmp/env.json npx playwright test manual-env --project=chromium
//
// The control port answers GET /hits (the edge's requests), GET /allows, and
// GET /block?name=…&mode=nxdomain|null_ip|custom_ip, /ttl?s=…, /edge-retry?on=1.

import { writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';

import type { BlockMode } from './harness/edge';
import { test } from './harness/fixtures';

const out = process.env.PICKET_MANUAL_ENV;

test.skip(out === undefined, 'manual environment only (PICKET_MANUAL_ENV)');

test('manual environment', async ({ certs, edge, targets }) => {
  test.setTimeout(0);
  edge.blockTtl = 10;
  edge.edgeRetry = true;
  edge.block('ads.test', { mode: { type: 'nxdomain' }, bundle: 'ads & trackers', head: '42' });
  edge.block('tracker.test', { mode: { type: 'nxdomain' }, bundle: 'trackers' });
  const ipt = targets.ipTargets;
  if (ipt !== null) {
    edge.firewall.add(ipt.ip);
  }
  const control = createServer((req, res) => {
    const u = new URL(req.url ?? '/', 'http://x');
    const reply = (v: unknown): void => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(v, null, 1));
    };
    switch (u.pathname) {
      case '/hits':
        reply(edge.hits);
        break;
      case '/allows':
        reply(edge.activeAllows());
        break;
      case '/ttl':
        edge.blockTtl = Number(u.searchParams.get('s') ?? '10');
        reply({ blockTtl: edge.blockTtl });
        break;
      case '/edge-retry':
        edge.edgeRetry = u.searchParams.get('on') === '1';
        reply({ edgeRetry: edge.edgeRetry });
        break;
      case '/block': {
        const name = u.searchParams.get('name') ?? '';
        const type = u.searchParams.get('mode') ?? 'nxdomain';
        const mode = (type === 'custom_ip' ? { type, ip: u.searchParams.get('ip') ?? '127.0.0.2' } : { type }) as BlockMode;
        edge.block(name, { mode, bundle: u.searchParams.get('bundle') ?? 'manual' });
        reply({ blocked: name, mode });
        break;
      }
      default:
        res.writeHead(404);
        res.end();
    }
  });
  await new Promise<void>((resolve) => control.listen(0, '127.0.0.1', resolve));
  const subs = [targets.url('tracker.test', '/pixel.png'), targets.url('cdn.test', '/pixel.png')];
  if (ipt !== null) {
    subs.push(`http://${ipt.ip}:${String(ipt.gate)}/pixel.png`);
  }
  if (out === undefined) {
    return;
  }
  writeFileSync(
    out,
    JSON.stringify(
      {
        edge: edge.origin,
        doh: edge.dohUrl,
        caPem: path.join(certs.dir, 'ca.pem'),
        caDerBase64: certs.caDerBase64,
        caSpki: certs.caSpki,
        control: `http://127.0.0.1:${String((control.address() as AddressInfo).port)}`,
        site: targets.url('site.test', '/'),
        blocked: targets.url('ads.test', '/page?q=1'),
        subresources: targets.url('site.test', `/subresources?${subs.map((s) => `src=${encodeURIComponent(s)}`).join('&')}`),
        wrongName: `https://wrong.test:${String(targets.local.tlsWrongName)}/`,
        local: targets.local,
        ip: ipt,
      },
      null,
      1,
    ),
  );
  await new Promise(() => undefined);
});
