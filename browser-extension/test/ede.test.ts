import { describe, expect, it } from 'vitest';

import type { DnsReply } from '../src/shared/dns';
import { blockFromEde, dnsBlockOf, isFirewallBlock, parseTokens, percentDecode } from '../src/shared/ede';

const replyWith = (rcode: number, ede: DnsReply['ede']): DnsReply => ({ id: 1, rcode, truncated: false, answers: 0, ede });

describe('EXTRA-TEXT tokens', () => {
  it('splits key=value tokens; the first of a key wins; junk is skipped', () => {
    const t = parseTokens('bundle=a@b block=x  =y Bad=1 block=z novalue noeq= ');
    expect([...t]).toEqual([
      ['bundle', 'a@b'],
      ['block', 'x'],
      ['noeq', ''],
    ]);
  });

  it('percent-decodes UTF-8 and leaves broken escapes as they are', () => {
    expect(percentDecode('a%20b%40c')).toBe('a b@c');
    expect(percentDecode('caf%C3%A9')).toBe('café');
    expect(percentDecode('100%')).toBe('100%');
    expect(percentDecode('%zz%4')).toBe('%zz%4');
  });
});

describe('blocks', () => {
  it('reads a bundle block: bundle, head and block id', () => {
    expect(blockFromEde({ code: 15, text: 'bundle=block-common@3f2a9c0d11aa22bb block=abcdefgh' })).toEqual({
      blockId: 'abcdefgh',
      bundle: 'block-common',
      head: '3f2a9c0d11aa22bb',
    });
    // An encoded `@` belongs to the bundle id; the literal one separates the head.
    expect(blockFromEde({ code: 15, text: 'bundle=a%40b@h1 block=abcdefgh' })).toMatchObject({ bundle: 'a@b', head: 'h1' });
  });

  it('reads a lookup block: provider and verdict', () => {
    expect(blockFromEde({ code: 15, text: 'lookup=quad9 verdict=timeout block=qrstuvwx' })).toEqual({
      blockId: 'qrstuvwx',
      lookup: 'quad9',
      verdict: 'timeout',
    });
  });

  it('keeps a block whose other tokens were dropped (over 128 bytes, block last)', () => {
    expect(blockFromEde({ code: 15, text: 'block=abcdefgh' })).toEqual({ blockId: 'abcdefgh' });
  });

  it('is no block without EDE 15 and a valid block token', () => {
    expect(blockFromEde({ code: 4, text: 'block=abcdefgh' })).toBeNull();
    expect(blockFromEde({ code: 15, text: 'bundle=x@y' })).toBeNull();
    expect(blockFromEde({ code: 15, text: 'block=' })).toBeNull();
    expect(blockFromEde({ code: 15, text: 'block=a%20b' })).toBeNull();
    expect(blockFromEde({ code: 15, text: `block=${'a'.repeat(65)}` })).toBeNull();
    expect(dnsBlockOf(replyWith(0, []))).toBeNull();
    expect(dnsBlockOf(replyWith(0, [{ code: 18, text: 'not permitted from this address' }]))).toBeNull();
  });

  it('finds the block among several EDE options', () => {
    expect(dnsBlockOf(replyWith(0, [{ code: 4, text: '' }, { code: 15, text: 'block=abcdefgh' }]))?.blockId).toBe('abcdefgh');
  });

  it('reads the PTR probe: NXDOMAIN with EDE 15 cause=firewall', () => {
    expect(isFirewallBlock(replyWith(3, [{ code: 15, text: 'cause=firewall' }]))).toBe(true);
    expect(isFirewallBlock(replyWith(0, [{ code: 15, text: 'cause=firewall' }]))).toBe(false);
    expect(isFirewallBlock(replyWith(3, [{ code: 15, text: 'cause=other' }]))).toBe(false);
    expect(isFirewallBlock(replyWith(3, []))).toBe(false);
  });
});
