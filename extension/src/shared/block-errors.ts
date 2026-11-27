// Which load failures may be a Picket block (browser-extension.md §3 step 1, §5), by the kind of
// host the URL names.
//
// Only an error some block mode produces triggers the DoH probe. The lists cover every
// `block_response.type` (null_ip, nxdomain, nodata, refused, custom_ip hosts that fail TLS, reset,
// close or silently drop connections) and a firewall refusal on an IP-literal URL. The browser
// tests (test/browser/errors.spec.ts, browser-extension.md §5) check each value a real browser
// reports against them; a change goes here and nowhere else.
//
// - **Host names:** the probe's EDE decides (the edge answers from this device's recent blocks),
//   so a candidate that isn't a block costs one probe and nothing else.
// - **IP literals:** the PTR probe only says that Picket holds no grant for the IP (edge.md §12),
//   not that it refused this connection, so the error must be one a refusal can cause: refused,
//   reset, timed out, unreachable. A TLS or certificate error, or an empty or closed response,
//   needs a completed TCP connection, so the refusal of a new one never causes it (e.g. a LAN
//   appliance's self-signed certificate at `https://192.168.10.5:8006/`). A reset stays in, for
//   open connections too: UniFi's required Block All rejects every connection state, and Picket
//   decides only what it would (edge-unifi.md §4), so an IP allow that ends can reset a
//   connection still open to that IP; §5 lists "a firewall reset on an IP-literal URL".
//
// Brave (Chromium) reports `net::ERR_*` names in webNavigation and webRequest. Firefox reports
// `Error code <nsresult>` in webNavigation; in webRequest it reports `NS_ERROR_*` names, except
// for security-module errors (NSS, mozilla::pkix: every TLS and certificate failure), which come
// as their localized message ("Peer’s Certificate issuer is not recognized.").
//
// Seen in the browser tests (Chromium 159, Firefox 159; README "Real-browser tests"):
// - nxdomain, nodata and refused: `net::ERR_NAME_NOT_RESOLVED`; Firefox NS_ERROR_UNKNOWN_HOST.
// - null_ip: `net::ERR_CONNECTION_REFUSED`; Firefox NS_ERROR_CONNECTION_REFUSED.
// - custom_ip that resets or closes right after accepting: `net::ERR_CONNECTION_RESET`,
//   `net::ERR_EMPTY_RESPONSE` or, when the reset or close comes before Chromium has read the
//   connection's peer address, `net::ERR_SOCKET_NOT_CONNECTED`; Firefox NS_ERROR_NET_RESET for
//   both (a close without a reply too, which on an IP literal is therefore probed like a reset).
// - custom_ip TLS failures: `net::ERR_SSL_*`, `net::ERR_CERT_*`; Firefox security-module codes.
// - silent drop: `net::ERR_CONNECTION_TIMED_OUT`; Firefox NS_ERROR_NET_TIMEOUT.
// - firewall reject of a new connection: `net::ERR_CONNECTION_REFUSED`; NS_ERROR_CONNECTION_REFUSED.
//   A load in flight when its IP allow ends is reset; both browsers then retry it on a new
//   connection, which the firewall refuses, so it fails as refused too.

import type { Host } from './host';

/** Chromium errors a refused or dropped connection causes (any host). */
const CHROMIUM_CONNECT_ERRORS: readonly string[] = [
  'net::ERR_CONNECTION_REFUSED',
  // Also an IP literal's: an allow that ends can reset an open connection (see the header).
  'net::ERR_CONNECTION_RESET',
  'net::ERR_CONNECTION_FAILED',
  'net::ERR_CONNECTION_TIMED_OUT',
  'net::ERR_TIMED_OUT',
  'net::ERR_ADDRESS_UNREACHABLE',
  // EACCES on connect: Linux reports an ICMPv6 administratively-prohibited reject so.
  'net::ERR_NETWORK_ACCESS_DENIED',
];

/** Chromium errors a block of a host name can cause. */
export const CHROMIUM_NAME_ERRORS: ReadonlySet<string> = new Set([
  ...CHROMIUM_CONNECT_ERRORS,
  // nxdomain, nodata, refused: the name doesn't resolve.
  'net::ERR_NAME_NOT_RESOLVED',
  'net::ERR_NAME_RESOLUTION_FAILED',
  // null_ip: 0.0.0.0 / :: are refused as targets, or reach a closed local port.
  'net::ERR_ADDRESS_INVALID',
  'net::ERR_BLOCKED_BY_PRIVATE_NETWORK_ACCESS_CHECKS',
  'net::ERR_BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS',
  // custom_ip: a host that accepts the connection, then closes it or sends nothing.
  'net::ERR_CONNECTION_CLOSED',
  'net::ERR_EMPTY_RESPONSE',
  // custom_ip: a host that resets or closes the connection before Chromium has read its peer
  // address (seen for both in the browser tests). Not for IP literals: the connection completed.
  'net::ERR_SOCKET_NOT_CONNECTED',
]);

/** Chromium errors a firewall refusal of an IP literal can cause. */
export const CHROMIUM_IP_ERRORS: ReadonlySet<string> = new Set(CHROMIUM_CONNECT_ERRORS);

/** Chromium error prefixes a block of a host name can cause: TLS failures at a custom_ip host. */
export const CHROMIUM_NAME_PREFIXES: readonly string[] = ['net::ERR_CERT_', 'net::ERR_SSL_'];

/** An nsresult in Necko's module (NS_ERROR_MODULE_NETWORK). */
const necko = (code: number): number => (0x804b0000 + code) >>> 0;

/**
 * Firefox network errors a refused or dropped connection causes (any host), by name and nsresult.
 * Necko reports unreachable hosts and networks, and EACCES, as NS_ERROR_CONNECTION_REFUSED.
 */
const FIREFOX_CONNECT_ERRORS: readonly (readonly [string, number])[] = [
  ['NS_ERROR_CONNECTION_REFUSED', necko(13)], // null_ip, firewall reject
  ['NS_ERROR_NET_TIMEOUT', necko(14)], // silent drop
  ['NS_ERROR_NET_RESET', necko(20)], // an ended IP allow can reset an open connection (see the header)
  ['NS_ERROR_NET_TIMEOUT_EXTERNAL', necko(85)],
];

/** Firefox network errors a block of a host name can cause, by name and nsresult. */
export const FIREFOX_NAME_ERRORS: ReadonlyMap<string, number> = new Map([
  ...FIREFOX_CONNECT_ERRORS,
  ['NS_ERROR_UNKNOWN_HOST', necko(30)], // nxdomain, nodata, refused
  // custom_ip: a host that accepts the connection, then closes it or sends nothing.
  ['NS_ERROR_NET_EMPTY_RESPONSE', necko(36)],
  ['NS_ERROR_NET_INTERRUPT', necko(71)],
]);

/** Firefox network errors a firewall refusal of an IP literal can cause. */
export const FIREFOX_IP_ERRORS: ReadonlyMap<string, number> = new Map(FIREFOX_CONNECT_ERRORS);

/** Firefox security-module nsresults (NSS and mozilla::pkix): TLS failures at a custom_ip host. */
const SECURITY_MODULE_BASE = 0x805a0000;
const FIREFOX_TLS_PREFIXES: readonly string[] = ['SEC_ERROR_', 'SSL_ERROR_', 'MOZILLA_PKIX_ERROR_'];
const FIREFOX_NAME_CODES: ReadonlySet<number> = new Set(FIREFOX_NAME_ERRORS.values());
const FIREFOX_IP_CODES: ReadonlySet<number> = new Set(FIREFOX_IP_ERRORS.values());

/**
 * True for a Firefox webRequest error that is a security-module error's localized message (a TLS
 * or certificate failure): Firefox names every other error (`NS_ERROR_*`, `NS_BINDING_*`), and
 * webNavigation gives codes. English Firefox only (Picket supports English browsers): its
 * messages are sentences, so they hold a space.
 */
function isSecurityMessage(error: string): boolean {
  return /\s/.test(error) && !error.startsWith('Error code') && !/^[A-Z][A-Z0-9_]*$/.test(error);
}

/** True when a load failure's `details.error` may come from a Picket block of a host of this kind. */
export function isBlockCandidate(error: unknown, host: Host['kind']): boolean {
  if (typeof error !== 'string' || error.length === 0 || error.length > 200) {
    return false;
  }
  const name = host === 'name';
  if (error.startsWith('net::')) {
    return name ? CHROMIUM_NAME_ERRORS.has(error) || CHROMIUM_NAME_PREFIXES.some((p) => error.startsWith(p)) : CHROMIUM_IP_ERRORS.has(error);
  }
  const numeric = /^Error code (\d{1,10})$/.exec(error);
  if (numeric !== null) {
    const code = Number(numeric[1]);
    if (!name) {
      return FIREFOX_IP_CODES.has(code);
    }
    return FIREFOX_NAME_CODES.has(code) || (code >= SECURITY_MODULE_BASE && code < SECURITY_MODULE_BASE + 0x10000);
  }
  if (!name) {
    return FIREFOX_IP_ERRORS.has(error);
  }
  return FIREFOX_NAME_ERRORS.has(error) || FIREFOX_TLS_PREFIXES.some((p) => error.startsWith(p)) || isSecurityMessage(error);
}
