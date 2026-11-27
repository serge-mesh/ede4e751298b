import { describe, expect, it } from 'vitest';

import { base64url, buildQuery, DnsError, encodeName, parseReply, QTYPE_A, QTYPE_PTR } from '../src/shared/dns';
import { qname, qtype, reply } from './dns-writer';

describe('buildQuery', () => {
  it('writes one recursive question with an OPT record', () => {
    const q = buildQuery('Ads.Example.com', QTYPE_A, 0x1234);
    const v = new DataView(q.buffer);
    expect(v.getUint16(0)).toBe(0x1234);
    expect(v.getUint16(2)).toBe(0x0100); // RD only
    expect([v.getUint16(4), v.getUint16(6), v.getUint16(8), v.getUint16(10)]).toEqual([1, 0, 0, 1]);
    expect(qname(q)).toBe('Ads.Example.com');
    expect(qtype(q)).toBe(QTYPE_A);
    // OPT: root owner, type 41, UDP size 1232, version 0, DO clear, no options.
    expect([...q.subarray(q.length - 11)]).toEqual([0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
  });

  it('accepts a trailing dot and refuses names DNS cannot carry', () => {
    expect(encodeName('a.b.')).toEqual(encodeName('a.b'));
    for (const bad of ['', '.', 'a..b', 'x'.repeat(64) + '.com', 'bü.de', 'a b.com', `${'a.'.repeat(127)}a`]) {
      expect(() => encodeName(bad), bad).toThrow(DnsError);
    }
    expect(encodeName(`${'a'.repeat(63)}.com`)[0]).toBe(63);
    expect(() => buildQuery('a.com', 1, 70000)).toThrow(DnsError);
  });

  it('encodes the RFC 8484 dns parameter as base64url without padding', () => {
    expect(base64url(Uint8Array.from([0xfb, 0xff, 0xfe]))).toBe('-__-');
    expect(base64url(Uint8Array.from([1]))).toBe('AQ');
  });
});

describe('parseReply', () => {
  const q = buildQuery('blocked.example', QTYPE_A, 0xbeef);

  it('collects EDE options after answers that use compression pointers', () => {
    const r = parseReply(
      reply(q, {
        answers: [{ type: 1, rdata: [0, 0, 0, 0] }],
        ede: [
          { code: 15, text: 'bundle=block-common@3f2a block=abcdefgh' },
          { code: 4, text: '' },
        ],
      }),
      q,
    );
    expect(r).toEqual({
      id: 0xbeef,
      rcode: 0,
      truncated: false,
      answers: 1,
      ede: [
        { code: 15, text: 'bundle=block-common@3f2a block=abcdefgh' },
        { code: 4, text: '' },
      ],
    });
  });

  it('reads NXDOMAIN with an authority SOA, and the extended RCODE', () => {
    const soa = [0, 0, ...new Array<number>(20).fill(0)];
    expect(parseReply(reply(q, { rcode: 3, authority: [{ type: 6, rdata: soa }] }), q).rcode).toBe(3);
    expect(parseReply(reply(q, { rcode: 0, extendedRcode: 1 }), q).rcode).toBe(16);
    expect(parseReply(reply(q, { opt: false }), q).ede).toEqual([]);
  });

  it('refuses replies that do not answer this query', () => {
    expect(() => parseReply(reply(q, { id: 1 }), q)).toThrow('id mismatch');
    expect(() => parseReply(reply(q, { qr: false }), q)).toThrow('not a response');
    const other = buildQuery('other.example', QTYPE_A, 0xbeef);
    expect(() => parseReply(reply(other), q)).toThrow('question mismatch');
    const ptr = buildQuery('blocked.example', QTYPE_PTR, 0xbeef);
    expect(() => parseReply(reply(ptr), q)).toThrow('question mismatch');
    // Case differences in the echoed name are fine.
    const upper = buildQuery('BLOCKED.example', QTYPE_A, 0xbeef);
    expect(parseReply(reply(upper), q).rcode).toBe(0);
  });

  it('refuses malformed messages with DnsError only', () => {
    const good = reply(q, { answers: [{ type: 1, rdata: [1, 2, 3, 4] }], ede: [{ code: 15, text: 'block=abcdefgh' }] });
    expect(() => parseReply(good.subarray(0, good.length - 3), q)).toThrow(DnsError);
    expect(() => parseReply(new Uint8Array(5), q)).toThrow(DnsError);
    expect(() => parseReply(new Uint8Array(70_000), q)).toThrow('message too large');
    const twoOpt = reply(q);
    const doubled = new Uint8Array([...twoOpt, ...twoOpt.subarray(twoOpt.length - 11)]);
    doubled[11] = 2;
    expect(() => parseReply(doubled, q)).toThrow('second OPT record');
    const badLabel = Uint8Array.from(good);
    badLabel[12 + q.length - 12 - 11 + 0] = 0x80; // the answer's owner: a reserved label type
    expect(() => parseReply(badLabel, q)).toThrow(DnsError);

    // Mutations of a valid reply never escape as anything but DnsError.
    let seed = 42;
    const rand = (n: number): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % n;
    };
    for (let i = 0; i < 3000; i++) {
      const m = Uint8Array.from(good);
      for (let k = 0; k <= rand(4); k++) {
        m[rand(m.length)] = rand(256);
      }
      const cut = rand(3) === 0 ? m.subarray(0, rand(m.length)) : m;
      try {
        parseReply(cut, q);
      } catch (e) {
        expect(e).toBeInstanceOf(DnsError);
      }
    }
  });
});
