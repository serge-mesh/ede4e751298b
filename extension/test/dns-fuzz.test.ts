// Seeded random tests of the DoH probe's codec (src/shared/dns.ts, src/shared/ede.ts). Replies
// come from the network, so any bytes must end in either a reply that answers the query or a
// DnsError, and no EXTRA-TEXT may make the EDE decoder throw or report a malformed block.
//
// Well-formed replies are checked field by field against what was written; broken ones (cut,
// overwritten, wrong section counts, spliced-in compression pointers, reserved label types and
// oversized lengths) against invariants. EXTRA-TEXT is written the way the edge writes it
// (crates/picket-wire/src/ede.rs: values percent-encoded, tokens dropped from the left past 128
// bytes), then mangled.
//
// The same seed gives the same cases, and a failure names its seed, case and input.
// PICKET_FUZZ_RUNS sets the cases per test (default 2000) and PICKET_FUZZ_SEED the seed (default
// 1; `random` picks one). `npm run test:fuzz` runs 100,000 cases per test from a random seed
// unless they are set.

import { describe, expect, it } from 'vitest';

import {
  buildQuery,
  DnsError,
  MAX_MESSAGE,
  parseReply,
  QTYPE_A,
  QTYPE_PTR,
  RCODE_NXDOMAIN,
  type DnsReply,
  type Ede,
} from '../src/shared/dns';
import { blockFromEde, dnsBlockOf, isFirewallBlock, parseTokens, percentDecode, type DnsBlock } from '../src/shared/ede';
import { reply } from './dns-writer';

function runsOf(v: string | undefined): number {
  if (v === undefined || v === '') {
    return 2000;
  }
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1) {
    throw new Error(`PICKET_FUZZ_RUNS must be a positive integer, not ${v}`);
  }
  return n;
}

function seedOf(v: string | undefined): number {
  if (v === undefined || v === '') {
    return 1;
  }
  if (v === 'random') {
    return Math.floor(Math.random() * 0xffff_ffff) + 1;
  }
  const n = Number(v);
  if (!Number.isInteger(n)) {
    throw new Error(`PICKET_FUZZ_SEED must be an integer or "random", not ${v}`);
  }
  return n >>> 0 || 1;
}

const RUNS = runsOf(process.env.PICKET_FUZZ_RUNS);
const SEED = seedOf(process.env.PICKET_FUZZ_SEED);
const TIMEOUT_MS = Math.max(10_000, RUNS * 5);

/** The most EDE options a reply's parse keeps, and EXTRA-TEXT bytes kept per option (dns.ts). */
const MAX_EDE = 8;
const MAX_EXTRA_TEXT = 512;
/** What ede.ts accepts as a token key, a block id, and a decoded value's length. */
const KEY = /^[a-z][a-z0-9_-]{0,31}$/;
const BLOCK_ID = /^[A-Za-z0-9._~-]{1,64}$/;
const MAX_VALUE = 255;
/** The edge's EXTRA-TEXT cap (picket-wire `EXTRA_TEXT_MAX`). */
const EXTRA_TEXT_MAX = 128;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** xorshift32: small and seeded, so a failing case repeats. */
class Rng {
  private s: number;

  constructor(seed: number) {
    this.s = seed >>> 0 || 1;
  }

  /** An integer in [0, n). */
  int(n: number): number {
    let s = this.s;
    s ^= s << 13;
    s ^= s >>> 17;
    s ^= s << 5;
    this.s = s >>> 0;
    return this.s % n;
  }

  /** True one time in `n`. */
  oneIn(n: number): boolean {
    return this.int(n) === 0;
  }

  pick<T>(items: readonly T[]): T {
    return items[this.int(items.length)]!;
  }

  bytes(n: number): number[] {
    return Array.from({ length: n }, () => this.int(256));
  }
}

/** Runs `check` on RUNS cases from `make`; a failure names the seed, the case and its input. */
function cases<T>(salt: number, make: (rng: Rng) => T, show: (input: T) => string, check: (input: T) => void): void {
  const rng = new Rng(SEED ^ salt);
  for (let i = 0; i < RUNS; i++) {
    const input = make(rng);
    try {
      check(input);
    } catch (e) {
      const why = e instanceof Error ? e.message : String(e);
      throw new Error(`case ${String(i)} of PICKET_FUZZ_SEED=${String(SEED)}: ${why}\ninput: ${show(input)}`, { cause: e });
    }
  }
}

const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const u16 = (n: number): number[] => [(n >>> 8) & 0xff, n & 0xff];
const u32 = (n: number): number[] => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
const isUpper = (b: number): boolean => b >= 0x41 && b <= 0x5a;
const fold = (b: number): number => (isUpper(b) ? b | 0x20 : b);

// --- EXTRA-TEXT as the edge writes it ---

/** Percent-encodes as the edge does: every UTF-8 byte outside `A-Za-z0-9-._~`, as `%XX`. */
function edgeEncode(value: string): string {
  let out = '';
  for (const b of encoder.encode(value)) {
    const c = String.fromCharCode(b);
    out += /^[A-Za-z0-9._~-]$/.test(c) ? c : `%${b.toString(16).toUpperCase().padStart(2, '0')}`;
  }
  return out;
}

/** `n` code points: controls and ASCII (space, `%`, `@`, `=` among them), Latin-1, BMP, astral. */
function randomValue(rng: Rng, n: number): string {
  let s = '';
  for (let i = 0; i < n; i++) {
    switch (rng.int(5)) {
      case 0:
        s += String.fromCodePoint(rng.int(0x80));
        break;
      case 1:
        s += rng.pick([' ', '%', '@', '=', '+', '/']);
        break;
      case 2:
        s += String.fromCodePoint(0xa0 + rng.int(0x60));
        break;
      case 3:
        s += String.fromCodePoint(0x100 + rng.int(0xd800 - 0x100)); // below the surrogates
        break;
      default:
        s += String.fromCodePoint(0x10000 + rng.int(0x100000));
    }
  }
  return s;
}

const BLOCK_ID_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-';
const KNOWN_KEYS = new Set(['block', 'bundle', 'lookup', 'verdict']);

interface Written {
  text: string;
  /** The block ede.ts should read from `text`. */
  block: DnsBlock;
}

/**
 * A block's EXTRA-TEXT: `bundle=<id>@<head> block=<id>` or `lookup=<p> verdict=<v> block=<id>`,
 * sometimes with tokens of other keys among them. `capped` applies the edge's 128-byte rule;
 * without it, values run past the 255 characters ede.ts keeps.
 */
function writeBlock(rng: Rng, capped: boolean): Written {
  const longest = capped ? 24 : 300;
  const value = (): string => randomValue(rng, 1 + rng.int(longest));
  const blockId = Array.from({ length: 1 + rng.int(64) }, () => BLOCK_ID_CHARS.charAt(rng.int(BLOCK_ID_CHARS.length))).join('');
  const tokens: { text: string; fields: Partial<DnsBlock> }[] = [];
  if (rng.oneIn(2)) {
    const bundle = value();
    const head = value();
    tokens.push({ text: `bundle=${edgeEncode(bundle)}@${edgeEncode(head)}`, fields: { bundle, head } });
  } else {
    const lookup = value();
    const verdict = value();
    tokens.push({ text: `lookup=${edgeEncode(lookup)}`, fields: { lookup } }, { text: `verdict=${edgeEncode(verdict)}`, fields: { verdict } });
  }
  tokens.push({ text: `block=${blockId}`, fields: { blockId } });
  if (rng.oneIn(4)) {
    // A token of another key (one the edge sends elsewhere, or none yet) is skipped. It goes
    // before `block`, which the edge always writes last.
    let key = rng.pick(['cause', 'x', 'detail']);
    while (rng.oneIn(2)) {
      key += 'abcdefghijklmnopqrstuvwxyz0123456789_-'.charAt(rng.int(38));
    }
    if (!KNOWN_KEYS.has(key)) {
      tokens.splice(rng.int(tokens.length), 0, { text: `${key}=${edgeEncode(value())}`, fields: {} });
    }
  }
  // Past 128 bytes the edge drops tokens from the left; `block` (at most 70 bytes) is last.
  while (capped && tokens.map((t) => t.text).join(' ').length > EXTRA_TEXT_MAX && tokens.length > 1) {
    tokens.shift();
  }
  const block: DnsBlock = { blockId };
  for (const t of tokens) {
    for (const [k, v] of Object.entries(t.fields) as [keyof DnsBlock, string][]) {
      if (v.length <= MAX_VALUE) {
        block[k] = v;
      }
    }
  }
  return { text: tokens.map((t) => t.text).join(' '), block };
}

const SOUP = [' ', ' ', '=', '=', '%', '@', 'block', 'bundle', 'lookup', 'verdict', 'cause', 'firewall', 'a', 'Z', '0', '9', 'F', '-', '.', '~'];

/** Any text: pieces of tokens, escapes and separators, and random UTF-16 units (lone surrogates too). */
function soup(rng: Rng): string {
  let s = '';
  for (let i = 0, n = rng.int(80); i < n; i++) {
    s += rng.oneIn(5) ? String.fromCharCode(rng.int(0x10000)) : rng.pick(SOUP);
  }
  return s;
}

/** `text` with a few UTF-16 units deleted, inserted or replaced (which may split a surrogate pair). */
function mangle(rng: Rng, text: string): string {
  const chars = text.split('');
  for (let i = 0, n = 1 + rng.int(4); i < n; i++) {
    const at = rng.int(chars.length + 1);
    switch (rng.int(3)) {
      case 0:
        chars.splice(at, 1);
        break;
      case 1:
        chars.splice(at, 0, rng.pick(SOUP));
        break;
      default:
        chars.splice(at, 1, String.fromCharCode(rng.int(0x10000)));
    }
  }
  return chars.join('');
}

/** A block ede.ts reports holds a valid id and only non-empty values it may show. */
function expectWellFormedBlock(b: DnsBlock | null): void {
  if (b === null) {
    return;
  }
  expect(b.blockId).toMatch(BLOCK_ID);
  for (const [k, v] of Object.entries(b)) {
    expect(['blockId', 'bundle', 'head', 'lookup', 'verdict']).toContain(k);
    expect(typeof v).toBe('string');
    expect((v as string).length).toBeGreaterThan(0);
    expect((v as string).length).toBeLessThanOrEqual(MAX_VALUE);
  }
}

// --- DoH replies ---

const LDH = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-';

/** A probe as the extension sends it: A for a host name, PTR for a reverse name. */
function randomQuery(rng: Rng): Uint8Array {
  const labels = Array.from({ length: 1 + rng.int(5) }, () =>
    Array.from({ length: 1 + rng.int(20) }, () => LDH.charAt(rng.int(LDH.length))).join(''),
  );
  return buildQuery(labels.join('.'), rng.pick([QTYPE_A, QTYPE_PTR]), rng.int(0x10000));
}

const queryId = (query: Uint8Array): number => (query[0]! << 8) | query[1]!;
const questionOf = (query: Uint8Array): Uint8Array => query.subarray(12, query.length - 11);

/** An owner name: the root, a pointer to the question, or binary labels ending in either. */
function ownerName(rng: Rng): number[] {
  switch (rng.int(4)) {
    case 0:
      return [0];
    case 1:
      return [0xc0, 0x0c];
    default: {
      const out: number[] = [];
      for (let i = 0, n = 1 + rng.int(3); i < n; i++) {
        const len = 1 + rng.int(63);
        out.push(len, ...rng.bytes(len));
      }
      out.push(...(rng.oneIn(2) ? [0] : [0xc0, 0x0c]));
      return out;
    }
  }
}

/** A record that isn't OPT. */
function record(rng: Rng): number[] {
  const type = rng.pick([1, 5, 6, 12, 28, 1 + rng.int(0xffff)]);
  const rdata = rng.bytes(rng.int(40));
  return [
    ...ownerName(rng),
    ...u16(type === 41 ? 1 : type),
    ...u16(rng.int(0x10000)),
    ...u32(rng.int(0x10000) * 0x10000 + rng.int(0x10000)),
    ...u16(rdata.length),
    ...rdata,
  ];
}

/** EXTRA-TEXT bytes: the edge's tokens, arbitrary bytes (not always UTF-8), more than is kept, or none. */
function extraText(rng: Rng): number[] {
  switch (rng.int(4)) {
    case 0:
      return [...encoder.encode(writeBlock(rng, true).text)];
    case 1:
      return rng.bytes(rng.int(40));
    case 2:
      return rng.bytes(MAX_EXTRA_TEXT - 20 + rng.int(200));
    default:
      return [];
  }
}

/** An OPT record with other options among up to 12 EDE options; the EDE a parse keeps go in `ede`. */
function optRecord(rng: Rng, extendedRcode: number, ede: Ede[]): number[] {
  const options: number[] = [];
  for (let i = 0, n = rng.int(13); i < n; i++) {
    if (rng.oneIn(3)) {
      const code = rng.pick([8, 10, 12, rng.int(0x10000)]);
      const data = rng.bytes(rng.int(30));
      options.push(...u16(code === 15 ? 12 : code), ...u16(data.length), ...data);
      continue;
    }
    const code = rng.int(0x10000);
    const text = extraText(rng);
    options.push(...u16(15), ...u16(2 + text.length), ...u16(code), ...text);
    if (ede.length < MAX_EDE) {
      ede.push({ code, text: decoder.decode(Uint8Array.from(text.slice(0, MAX_EXTRA_TEXT))) });
    }
  }
  // Root owner, type 41, UDP size, then the TTL: extended RCODE, version, DO and Z.
  return [0, ...u16(41), ...u16(rng.int(0x10000)), extendedRcode, rng.int(256), ...u16(rng.int(0x10000)), ...u16(options.length), ...options];
}

interface Generated {
  query: Uint8Array;
  bytes: Uint8Array;
}

interface WellFormed extends Generated {
  expected: DnsReply;
}

/**
 * A reply to `query` the parse must accept: any flags, the question echoed in any letter case,
 * records with compressed and binary owner names, and at most one OPT anywhere among the
 * additional records.
 */
function wellFormed(rng: Rng, query: Uint8Array): WellFormed {
  const id = queryId(query);
  const flags = 0x8000 | rng.int(0x8000);
  const question = Array.from(questionOf(query));
  for (let i = 0; i < question.length - 4; i++) {
    const b = question[i]!;
    if (fold(b) >= 0x61 && fold(b) <= 0x7a && rng.oneIn(2)) {
      question[i] = b ^ 0x20;
    }
  }
  const an = rng.int(4);
  const ns = rng.int(3);
  const body = [...question];
  for (let i = 0; i < an + ns; i++) {
    body.push(...record(rng));
  }
  const additional = Array.from({ length: rng.int(3) }, () => record(rng));
  const ede: Ede[] = [];
  let rcode = flags & 0xf;
  if (!rng.oneIn(4)) {
    const extendedRcode = rng.int(256);
    additional.splice(rng.int(additional.length + 1), 0, optRecord(rng, extendedRcode, ede));
    rcode |= extendedRcode << 4;
  }
  for (const rr of additional) {
    body.push(...rr);
  }
  const header = [...u16(id), ...u16(flags), ...u16(1), ...u16(an), ...u16(ns), ...u16(additional.length)];
  return {
    query,
    bytes: Uint8Array.from([...header, ...body]),
    expected: { id, rcode, truncated: (flags & 0x0200) !== 0, answers: an, ede },
  };
}

/** Bytes that trip parsers up: pointers, reserved label types, a full label, huge lengths, OPT and EDE codes. */
function pathology(rng: Rng): number[] {
  switch (rng.int(7)) {
    case 0:
      return [0xc0 | rng.int(0x40), rng.int(256)];
    case 1:
      return [rng.pick([0x40, 0x80]) | rng.int(0x40)];
    case 2:
      return [63, ...rng.bytes(rng.int(64))];
    case 3:
      return [0xff, 0xff];
    case 4:
      return [0, 41];
    case 5:
      return [0, 15, ...u16(rng.int(4))];
    default:
      return rng.bytes(1 + rng.int(16));
  }
}

/** A well-formed reply, broken: cut, overwritten, recounted, spliced into, or over the size limit. */
function broken(rng: Rng, query: Uint8Array): Generated {
  const good = wellFormed(rng, query).bytes;
  if (rng.oneIn(200)) {
    const big = new Uint8Array(MAX_MESSAGE + 1 + rng.int(64));
    big.set(good);
    return { query, bytes: big };
  }
  let m = Array.from(good);
  if (rng.oneIn(10)) {
    m = [...m.slice(0, rng.int(13)), ...rng.bytes(rng.int(600))];
  }
  for (let i = 0, n = 1 + rng.int(3); i < n; i++) {
    const at = rng.int(m.length + 1);
    switch (rng.int(5)) {
      case 0:
        m[at] = rng.int(256);
        break;
      case 1:
        m.length = at;
        break;
      case 2: // QDCOUNT, ANCOUNT, NSCOUNT or ARCOUNT
        m.splice(4 + 2 * rng.int(4), 2, ...u16(rng.oneIn(2) ? rng.int(8) : rng.int(0x10000)));
        break;
      case 3:
        m.splice(at, rng.int(3), ...pathology(rng));
        break;
      default:
        m.push(...rng.bytes(1 + rng.int(8)));
    }
  }
  return { query, bytes: Uint8Array.from(m) };
}

/**
 * Parses `bytes` and checks the outcome: a DnsError (null), or a reply that answers `query` and
 * agrees with the header it came in.
 */
function parsed({ query, bytes }: Generated): DnsReply | null {
  let r: DnsReply;
  try {
    r = parseReply(bytes, query);
  } catch (e) {
    if (e instanceof DnsError) {
      return null;
    }
    throw e;
  }
  const question = questionOf(query);
  const echoed = bytes.subarray(12, 12 + question.length);
  expect(bytes.length).toBeLessThanOrEqual(MAX_MESSAGE);
  expect(r.id, 'id').toBe(queryId(query));
  expect(bytes[2]! & 0x80, 'QR').not.toBe(0);
  expect((bytes[4]! << 8) | bytes[5]!, 'QDCOUNT').toBe(1);
  expect(echoed.length === question.length && echoed.every((b, i) => fold(b) === fold(question[i]!)), 'question').toBe(true);
  expect(r.answers, 'ANCOUNT').toBe((bytes[6]! << 8) | bytes[7]!);
  expect(r.truncated, 'TC').toBe((bytes[2]! & 0x02) !== 0);
  expect(r.rcode & 0xf, 'RCODE').toBe(bytes[3]! & 0xf);
  expect(r.rcode).toBeLessThanOrEqual(0xfff);
  expect(r.ede.length).toBeLessThanOrEqual(MAX_EDE);
  for (const e of r.ede) {
    expect(Number.isInteger(e.code) && e.code >= 0 && e.code <= 0xffff, 'INFO-CODE').toBe(true);
    expect(e.text.length).toBeLessThanOrEqual(MAX_EXTRA_TEXT);
  }
  return r;
}

describe('DoH replies (seeded random)', () => {
  it(
    'reads every well-formed reply field by field',
    () => {
      cases(
        1,
        (rng) => wellFormed(rng, randomQuery(rng)),
        (c) => hex(c.bytes),
        (c) => {
          expect(parseReply(c.bytes, c.query)).toEqual(c.expected);
        },
      );
    },
    TIMEOUT_MS,
  );

  it(
    'ends every broken reply in a DnsError or a reply that answers the query',
    () => {
      cases(
        2,
        (rng) => broken(rng, randomQuery(rng)),
        (c) => hex(c.bytes),
        (c) => {
          const r = parsed(c);
          if (r !== null) {
            expectWellFormedBlock(dnsBlockOf(r));
            expect(typeof isFirewallBlock(r)).toBe('boolean');
          }
        },
      );
    },
    TIMEOUT_MS,
  );
});

describe('EXTRA-TEXT (seeded random)', () => {
  it(
    'reads the block the edge writes, whatever its values hold',
    () => {
      cases(
        3,
        (rng) => writeBlock(rng, !rng.oneIn(4)),
        (c) => JSON.stringify(c.text),
        (c) => {
          expect(blockFromEde({ code: 15, text: c.text })).toEqual(c.block);
        },
      );
    },
    TIMEOUT_MS,
  );

  it(
    "carries the edge's block, and the firewall cause, through a reply among other EDE options",
    () => {
      const noise = (rng: Rng): Ede =>
        rng.pick([
          { code: 4, text: '' },
          { code: 18, text: 'not permitted from this address' },
          { code: 15, text: `cause=${rng.pick(['optimistic', 'stale', 'other'])}` },
          { code: rng.int(15), text: soup(rng) },
        ]);
      cases(
        4,
        (rng) => {
          const query = randomQuery(rng);
          const written = writeBlock(rng, true);
          // The block's option or the firewall cause among up to 7 others, all within the 8 kept.
          const ede = Array.from({ length: rng.int(MAX_EDE) }, () => noise(rng));
          const firewall = rng.oneIn(2);
          ede.splice(rng.int(ede.length + 1), 0, { code: 15, text: firewall ? 'cause=firewall' : written.text });
          // The firewall cause counts only with NXDOMAIN; a block's EDE with any RCODE.
          const rcode = rng.oneIn(3) ? rng.pick([0, 2, 5]) : RCODE_NXDOMAIN;
          const answers = rcode === 0 ? [{ type: 1, rdata: [0, 0, 0, 0] }] : [];
          return { query, bytes: reply(query, { rcode, answers, ede }), firewall, rcode, written };
        },
        (c) => hex(c.bytes),
        (c) => {
          const r = parseReply(c.bytes, c.query);
          if (c.firewall) {
            expect(isFirewallBlock(r)).toBe(c.rcode === RCODE_NXDOMAIN);
            expect(dnsBlockOf(r)).toBeNull();
          } else {
            expect(dnsBlockOf(r)).toEqual(c.written.block);
            expect(isFirewallBlock(r)).toBe(false);
          }
        },
      );
    },
    TIMEOUT_MS,
  );

  it(
    'never throws on any text, and reports only well-formed tokens and blocks',
    () => {
      cases(
        5,
        (rng) => (rng.oneIn(2) ? soup(rng) : mangle(rng, writeBlock(rng, !rng.oneIn(4)).text)),
        (text) => JSON.stringify(text),
        (text) => {
          for (const key of parseTokens(text).keys()) {
            expect(key).toMatch(KEY);
          }
          expect(typeof percentDecode(text)).toBe('string');
          expectWellFormedBlock(blockFromEde({ code: 15, text }));
          const r: DnsReply = { id: 0, rcode: RCODE_NXDOMAIN, truncated: false, answers: 0, ede: [{ code: 15, text }] };
          expectWellFormedBlock(dnsBlockOf(r));
          expect(typeof isFirewallBlock(r)).toBe('boolean');
        },
      );
    },
    TIMEOUT_MS,
  );

  it(
    'percent-decodes what the edge encodes, with hex digits in either case',
    () => {
      cases(
        6,
        (rng) => {
          const value = randomValue(rng, rng.int(64));
          // The edge writes upper case; RFC 3986 escapes may come in either.
          const encoded = edgeEncode(value).replace(/%[0-9A-F]{2}/g, (m) => (rng.oneIn(2) ? m.toLowerCase() : m));
          return { value, encoded };
        },
        (c) => JSON.stringify(c.encoded),
        (c) => {
          expect(percentDecode(c.encoded)).toBe(c.value);
        },
      );
    },
    TIMEOUT_MS,
  );
});
