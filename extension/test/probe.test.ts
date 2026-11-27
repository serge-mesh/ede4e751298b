import { describe, expect, it, vi } from 'vitest';

import { EdgeClient, type FetchLike } from '../src/background/edge-client';
import { probeTarget, probeUrl } from '../src/background/probe';
import { QTYPE_A, QTYPE_PTR } from '../src/shared/dns';
import { dnsResponse, qname, qtype, queryOf, reply, type ReplyOptions } from './dns-writer';

const ORIGIN = 'https://dns.home.arpa:9853';

function edge(answer: (name: string, type: number) => ReplyOptions | Response) {
  const fetch = vi.fn<FetchLike>(async (url) => {
    const q = queryOf(url);
    const a = answer(qname(q), qtype(q));
    return a instanceof Response ? a : dnsResponse(reply(q, a));
  });
  return { fetch, client: new EdgeClient({ origin: ORIGIN, fetch }) };
}

describe('probeUrl', () => {
  it('reports a DNS block from the ring with its EDE details', async () => {
    const { client, fetch } = edge(() => ({
      answers: [{ type: 1, rdata: [0, 0, 0, 0] }],
      ede: [{ code: 15, text: 'bundle=block-common@3f2a9c0d11aa22bb block=abcdefgh' }, { code: 4, text: '' }],
    }));
    expect(await probeUrl(client, 'https://Ads.Example.com/page?x=1')).toEqual({
      kind: 'dns',
      url: 'https://Ads.Example.com/page?x=1',
      name: 'ads.example.com',
      blockId: 'abcdefgh',
      bundle: 'block-common',
      head: '3f2a9c0d11aa22bb',
    });
    expect(qname(queryOf(fetch.mock.calls[0]?.[0] ?? ''))).toBe('ads.example.com');
  });

  it('reports a lookup block', async () => {
    const { client } = edge(() => ({ rcode: 3, ede: [{ code: 15, text: 'lookup=quad9 verdict=block block=qrstuvwx' }] }));
    expect(await probeUrl(client, 'http://bad.example/')).toMatchObject({ kind: 'dns', lookup: 'quad9', verdict: 'block', blockId: 'qrstuvwx' });
  });

  it('is nothing on a miss (NOERROR, no EDE) or when the edge fails', async () => {
    expect(await probeUrl(edge(() => ({})).client, 'https://fine.example/')).toBeNull();
    expect(await probeUrl(edge(() => new Response('', { status: 503 })).client, 'https://x.example/')).toBeNull();
    expect(await probeUrl(edge(() => ({ ede: [{ code: 18, text: 'not permitted from this address' }], rcode: 5 })).client, 'https://x.example/')).toBeNull();
  });

  it("asks an IP literal's reverse name and reports a firewall block", async () => {
    const { client, fetch } = edge((name, type) => {
      expect(type).toBe(QTYPE_PTR);
      return name === '100.100.100.100.in-addr.arpa' ? { rcode: 3, ede: [{ code: 15, text: 'cause=firewall' }] } : { rcode: 3 };
    });
    expect(await probeUrl(client, 'https://100.100.100.100/test')).toEqual({ kind: 'ip', url: 'https://100.100.100.100/test', ip: '100.100.100.100' });
    expect(await probeUrl(client, 'https://1.2.3.4/')).toBeNull();
    const v6 = await probeUrl(client, 'https://[2001:db8::1]/');
    expect(v6).toBeNull();
    expect(qname(queryOf(fetch.mock.calls[2]?.[0] ?? ''))).toMatch(/^1\.0\.0\.0\..*\.8\.b\.d\.0\.1\.0\.0\.2\.ip6\.arpa$/);
  });

  it('never probes an IP no firewall block can be about (a local server that is down is no block)', async () => {
    const { client, fetch } = edge(() => ({ rcode: 3, ede: [{ code: 15, text: 'cause=firewall' }] }));
    for (const u of [
      'http://127.0.0.1:3000/',
      'http://127.8.9.10/',
      'http://0.0.0.0:8000/',
      'http://169.254.1.1/',
      'http://224.0.0.251/',
      'http://255.255.255.255/',
      'http://[::1]:8080/',
      'http://[::]/',
      'http://[::ffff:127.0.0.1]/',
      'http://[fe80::1]/',
      'http://[ff02::1]/',
    ]) {
      expect(await probeUrl(client, u), u).toBeNull();
    }
    expect(fetch).not.toHaveBeenCalled();
    // Private and public unicast addresses are probed.
    expect(await probeUrl(client, 'http://192.168.1.20/')).toMatchObject({ kind: 'ip', ip: '192.168.1.20' });
    expect(await probeUrl(client, 'http://[2001:db8::1]/')).toMatchObject({ kind: 'ip', ip: '2001:db8::1' });
    expect(await probeUrl(client, 'http://[::ffff:100.100.100.100]/')).toMatchObject({ kind: 'ip', ip: '100.100.100.100' });
  });

  it('never probes the edge itself or non-web URLs', async () => {
    const { client, fetch } = edge(() => ({}));
    expect(await probeUrl(client, 'https://dns.home.arpa:9853/v1/temporary-allows')).toBeNull();
    expect(await probeUrl(client, 'file:///x')).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
    expect(probeTarget('https://dns.home.arpa/', ORIGIN)).toBeNull();
    expect(probeTarget('https://other.home.arpa/', ORIGIN)).toEqual({ kind: 'name', name: 'other.home.arpa' });
    expect(QTYPE_A).toBe(1);
  });
});
