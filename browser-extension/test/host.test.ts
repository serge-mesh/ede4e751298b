import { describe, expect, it } from 'vitest';

import { canonicalIp, hostOf, ipv6Groups, ipv6Text, isProbeableIp, printable, reverseName, type Host } from '../src/shared/host';

describe('hostOf', () => {
  it('reads names, lowercased, without the trailing dot', () => {
    expect(hostOf('https://Ads.Example.com./x?y')).toEqual({ kind: 'name', name: 'ads.example.com' });
    expect(hostOf('http://xn--bcher-kva.example/')).toEqual({ kind: 'name', name: 'xn--bcher-kva.example' });
    expect(hostOf('https://bücher.example/')).toEqual({ kind: 'name', name: 'xn--bcher-kva.example' });
  });

  it('reads IPv4 and IPv6 literals; IPv4-mapped IPv6 is the IPv4 address', () => {
    expect(hostOf('https://100.100.100.100/test')).toEqual({ kind: 'ip', version: 4, ip: '100.100.100.100' });
    expect(hostOf('http://0x7f.1/')).toEqual({ kind: 'ip', version: 4, ip: '127.0.0.1' });
    expect(hostOf('https://[2001:DB8:0:0:0:0:0:1]:8443/')).toEqual({ kind: 'ip', version: 6, ip: '2001:db8::1' });
    expect(hostOf('https://[::ffff:192.0.2.1]/')).toEqual({ kind: 'ip', version: 4, ip: '192.0.2.1' });
  });

  it('ignores other schemes and bad URLs', () => {
    for (const u of ['file:///etc/passwd', 'about:blank', 'chrome://settings', 'not a url', 'ftp://x.example/']) {
      expect(hostOf(u), u).toBeNull();
    }
  });
});

describe('IPv6', () => {
  it('parses and prints RFC 5952 text', () => {
    expect(ipv6Groups('::')).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
    expect(ipv6Groups('1::')).toEqual([1, 0, 0, 0, 0, 0, 0, 0]);
    expect(ipv6Groups('::1.2.3.4')).toEqual([0, 0, 0, 0, 0, 0, 0x102, 0x304]);
    expect(ipv6Groups('1:2:3:4:5:6:7:8:9')).toBeNull();
    expect(ipv6Groups('1::2::3')).toBeNull();
    expect(ipv6Groups('12345::')).toBeNull();
    expect(ipv6Text([0x2001, 0xdb8, 0, 0, 1, 0, 0, 1])).toBe('2001:db8::1:0:0:1');
    expect(ipv6Text([0x2001, 0xdb8, 0, 1, 1, 1, 1, 1])).toBe('2001:db8:0:1:1:1:1:1');
    expect(ipv6Text([0, 0, 0, 0, 0, 0, 0, 1])).toBe('::1');
  });
});

describe('isProbeableIp', () => {
  const ip = (text: string) => hostOf(`http://${text}/`) as Extract<Host, { kind: 'ip' }>;
  it('leaves out loopback, unspecified, link-local, multicast and broadcast, v4 and v6', () => {
    for (const t of ['127.0.0.1', '127.255.0.9', '0.0.0.0', '0.1.2.3', '169.254.10.20', '224.0.0.1', '239.255.255.250', '240.0.0.1', '255.255.255.255', '[::]', '[::1]', '[::ffff:127.0.0.1]', '[::ffff:169.254.0.1]', '[::7f00:1]', '[fe80::1]', '[febf::1]', '[ff02::fb]']) {
      expect(isProbeableIp(ip(t)), t).toBe(false);
    }
  });
  it('keeps unicast addresses, private ones included', () => {
    for (const t of ['100.100.100.100', '10.0.0.1', '192.168.1.1', '169.253.1.1', '223.255.255.255', '1.1.1.1', '[2001:db8::1]', '[fd00::1]', '[fec0::1]', '[::ffff:10.0.0.1]', '[64:ff9b::1]']) {
      expect(isProbeableIp(ip(t)), t).toBe(true);
    }
  });
});

describe('canonicalIp', () => {
  it('prints IPs as the edge does', () => {
    expect(canonicalIp('2001:0DB8:0:0:0:0:0:1')).toBe('2001:db8::1');
    expect(canonicalIp('::ffff:192.0.2.1')).toBe('192.0.2.1');
    expect(canonicalIp('100.100.100.100')).toBe('100.100.100.100');
    expect(canonicalIp('ads.example')).toBeNull();
    expect(canonicalIp('1.2.3.4]/x')).toBeNull();
  });
});

describe('reverseName', () => {
  it('names the IP as the edge reads it (edge bypass reverse_ip)', () => {
    expect(reverseName({ kind: 'ip', version: 4, ip: '100.100.100.1' })).toBe('1.100.100.100.in-addr.arpa');
    const nibbles = '20010db8000000000000000000000001'.split('').reverse().join('.');
    expect(reverseName({ kind: 'ip', version: 6, ip: '2001:db8::1' })).toBe(`${nibbles}.ip6.arpa`);
  });
});

describe('printable', () => {
  it('escapes control and bidi characters and keeps the rest', () => {
    expect(printable('a\u0000b\nc\u007f')).toBe('a\\x00b\\x0ac\\x7f');
    expect(printable('evil‮com')).toBe('evil\\u{202e}com');
    expect(printable('café <b>')).toBe('café <b>');
  });
});
