import { describe, expect, it } from 'vitest';

import { isBlockCandidate } from '../src/shared/block-errors';

describe('isBlockCandidate', () => {
  it('takes the Chromium errors block modes produce for a host name', () => {
    for (const e of [
      'net::ERR_NAME_NOT_RESOLVED',
      'net::ERR_CONNECTION_REFUSED',
      'net::ERR_ADDRESS_INVALID',
      'net::ERR_CONNECTION_RESET',
      'net::ERR_CONNECTION_TIMED_OUT',
      'net::ERR_CONNECTION_CLOSED',
      'net::ERR_EMPTY_RESPONSE',
      'net::ERR_CERT_COMMON_NAME_INVALID',
      'net::ERR_CERT_AUTHORITY_INVALID',
      'net::ERR_SSL_PROTOCOL_ERROR',
      // Seen in the browser tests: a custom_ip host that resets or closes right after accepting.
      'net::ERR_SOCKET_NOT_CONNECTED',
      'net::ERR_SSL_VERSION_OR_CIPHER_MISMATCH',
    ]) {
      expect(isBlockCandidate(e, 'name'), e).toBe(true);
    }
  });

  it('takes Firefox webRequest TLS failures, which come as localized messages, for a host name only', () => {
    // As English Firefox 159 reports them in the browser tests (security-module errors go
    // through nsINSSErrorsService). English only: Picket supports English browsers.
    for (const e of [
      'Peer’s Certificate issuer is not recognized.',
      'Unable to communicate securely with peer: requested domain name does not match the server’s certificate.',
      'Cannot communicate securely with peer: no common encryption algorithm(s).',
    ]) {
      expect(isBlockCandidate(e, 'name'), e).toBe(true);
      expect(isBlockCandidate(e, 'ip'), e).toBe(false);
    }
  });

  it('takes the Firefox errors for a host name, as webNavigation codes and webRequest names', () => {
    for (const e of [
      'Error code 2152398878', // NS_ERROR_UNKNOWN_HOST
      'Error code 2152398861', // NS_ERROR_CONNECTION_REFUSED
      'Error code 2152398862', // NS_ERROR_NET_TIMEOUT
      'Error code 2152398868', // NS_ERROR_NET_RESET
      'Error code 2152398884', // NS_ERROR_NET_EMPTY_RESPONSE
      'Error code 2153394164', // SSL_ERROR_BAD_CERT_DOMAIN
      'Error code 2153390067', // SEC_ERROR_UNKNOWN_ISSUER
      'NS_ERROR_UNKNOWN_HOST',
      'NS_ERROR_CONNECTION_REFUSED',
      'NS_ERROR_NET_INTERRUPT',
      'SEC_ERROR_UNKNOWN_ISSUER',
      'SSL_ERROR_BAD_CERT_DOMAIN',
      'MOZILLA_PKIX_ERROR_SELF_SIGNED_CERT',
    ]) {
      expect(isBlockCandidate(e, 'name'), e).toBe(true);
    }
  });

  it('takes only connect-level errors for an IP literal: a firewall refusal never completes a connection', () => {
    for (const e of [
      'net::ERR_CONNECTION_REFUSED',
      'net::ERR_CONNECTION_RESET',
      'net::ERR_CONNECTION_FAILED',
      'net::ERR_CONNECTION_TIMED_OUT',
      'net::ERR_TIMED_OUT',
      'net::ERR_ADDRESS_UNREACHABLE',
      'net::ERR_NETWORK_ACCESS_DENIED',
      'Error code 2152398861', // NS_ERROR_CONNECTION_REFUSED (also unreachable hosts and networks)
      'Error code 2152398862', // NS_ERROR_NET_TIMEOUT
      'Error code 2152398868', // NS_ERROR_NET_RESET
      'NS_ERROR_CONNECTION_REFUSED',
      'NS_ERROR_NET_TIMEOUT',
    ]) {
      expect(isBlockCandidate(e, 'ip'), e).toBe(true);
    }
    // Recheck R7: a LAN appliance's self-signed certificate (https://192.168.10.5:8006/) is no block.
    for (const e of [
      'net::ERR_CERT_AUTHORITY_INVALID',
      'net::ERR_CERT_COMMON_NAME_INVALID',
      'net::ERR_SSL_PROTOCOL_ERROR',
      'net::ERR_EMPTY_RESPONSE',
      'net::ERR_CONNECTION_CLOSED',
      'net::ERR_NAME_NOT_RESOLVED',
      'net::ERR_ADDRESS_INVALID',
      'net::ERR_BLOCKED_BY_PRIVATE_NETWORK_ACCESS_CHECKS',
      'Error code 2153390067', // SEC_ERROR_UNKNOWN_ISSUER
      'Error code 2153394164', // SSL_ERROR_BAD_CERT_DOMAIN
      'Error code 2152398884', // NS_ERROR_NET_EMPTY_RESPONSE
      'Error code 2152398919', // NS_ERROR_NET_INTERRUPT
      'Error code 2152398878', // NS_ERROR_UNKNOWN_HOST
      'SEC_ERROR_UNKNOWN_ISSUER',
      'SSL_ERROR_BAD_CERT_DOMAIN',
      'MOZILLA_PKIX_ERROR_SELF_SIGNED_CERT',
      'NS_ERROR_NET_EMPTY_RESPONSE',
      'NS_ERROR_NET_INTERRUPT',
      // A completed connection the host reset or closed before Chromium read its peer address.
      'net::ERR_SOCKET_NOT_CONNECTED',
    ]) {
      expect(isBlockCandidate(e, 'ip'), e).toBe(false);
    }
  });

  it('ignores failures no block causes', () => {
    for (const e of [
      'net::ERR_ABORTED',
      'net::ERR_BLOCKED_BY_CLIENT',
      'net::ERR_INTERNET_DISCONNECTED',
      'net::ERR_TOO_MANY_REDIRECTS',
      'net::ERR_UNSAFE_PORT',
      'Error code 2152398850', // NS_BINDING_ABORTED
      'Error code 2152398864', // NS_ERROR_OFFLINE
      'NS_BINDING_ABORTED',
      'NS_ERROR_ABORT',
      'NS_ERROR_TRACKING_URI',
      'NS_ERROR_SOMETHING_NEW',
      'Error code x',
      'Error code 12 34',
      '',
      'x'.repeat(300),
      undefined,
      42,
    ]) {
      expect(isBlockCandidate(e, 'name'), String(e)).toBe(false);
      expect(isBlockCandidate(e, 'ip'), String(e)).toBe(false);
    }
  });
});
