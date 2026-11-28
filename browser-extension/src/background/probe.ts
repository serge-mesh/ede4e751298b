// The DoH probe (browser-extension.md §3 step 2; edge.md §12): asks the edge whether a failed
// load was a Picket block. A host name's probe gets EDE 15 with `block=<id>` from the device's
// recent-blocks ring, or NOERROR without EDE on a miss; an IP literal's PTR probe for its
// reverse name gets NXDOMAIN with EDE 15 `cause=firewall` when Picket holds no grant for it.

import type { BlockInfo } from '../shared/block-info';
import { QTYPE_A, QTYPE_PTR } from '../shared/dns';
import { dnsBlockOf, isFirewallBlock } from '../shared/ede';
import { hostOf, isProbeableIp, reverseName, type Host } from '../shared/host';
import type { EdgeClient } from './edge-client';

/**
 * The host a URL's block would be about; null for the edge itself (whose failures aren't blocks)
 * and for IPs no firewall block can be about (`isProbeableIp`: loopback, link-local, multicast,
 * unspecified), so a local server that is down never gets a false firewall block page.
 */
export function probeTarget(url: string, edgeOrigin: string): Host | null {
  const host = hostOf(url);
  if (host === null || (host.kind === 'ip' && !isProbeableIp(host))) {
    return null;
  }
  const edge = hostOf(edgeOrigin);
  if (edge !== null && JSON.stringify(edge) === JSON.stringify(host)) {
    return null;
  }
  return host;
}

/** Probes the edge about a failed load of `url`; the block it reports, or null. */
export async function probeUrl(client: EdgeClient, url: string): Promise<BlockInfo | null> {
  const host = probeTarget(url, client.origin);
  if (host === null) {
    return null;
  }
  if (host.kind === 'ip') {
    const r = await client.probe(reverseName(host), QTYPE_PTR);
    return r.ok && isFirewallBlock(r.value) ? { kind: 'ip', url, ip: host.ip } : null;
  }
  const r = await client.probe(host.name, QTYPE_A);
  if (!r.ok) {
    return null;
  }
  const block = dnsBlockOf(r.value);
  return block === null ? null : { kind: 'dns', url, name: host.name, ...block };
}
