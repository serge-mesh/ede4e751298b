// Seeded random tests of the DoH probe's codec (src/shared/dns.ts, src/shared/ede.ts). Replies
// come from the network, so any bytes must end in either a reply that answers the query or a
// DnsError, and no EXTRA-TEXT may make the EDE decoder throw or report a malformed block.
//
// Well-formed replies are checked field by field against what was written; broken ones (cut,
// overwritten, wrong section counts, spliced-in compression pointers, reserved label types and
// oversized lengths) and arbitrary buffers (empty, short, and just under, at and over the
// message-size limit) against invariants. Replies built to reach one of the parser's guards (the
// label limit in a name, section counts and RDATA lengths past the end, a second OPT, EDNS options
// cut short) must end in that guard's DnsError, and dense valid replies at the size limit are read
// field by field before their boundary mutations. EXTRA-TEXT is written the way the edge writes it
// (crates/picket-wire/src/ede.rs: values percent-encoded, tokens dropped from the left past 128
// bytes), then mangled.
//
// The same seed gives the same cases, and a failure names its seed, case and input.
// PICKET_FUZZ_RUNS sets the cases per test (default 2000) and PICKET_FUZZ_SEED the seed (default
// 1; `random` picks one). `npm run test:fuzz` runs 100,000 cases per test from a random seed
// unless they are set. The dense near-limit test runs a 25th as many (each case is ~64 KiB).

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
/** Cases of the dense near-limit test, whose inputs are ~64 KiB each. */
const DENSE_RUNS = Math.max(1, Math.ceil(RUNS / 25));

/** The most EDE options a reply's parse keeps, and EXTRA-TEXT bytes kept per option (dns.ts). */
const MAX_EDE = 8;
const MAX_EXTRA_TEXT = 512;
/** The most labels dns.ts reads in one name, the root or pointer that ends it not counted (skipName). */
const MAX_LABELS = 128;
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

/** Runs `check` on `runs` cases from `make`; a failure names the seed, the case and its input. */
function cases<T>(salt: number, make: (rng: Rng) => T, show: (input: T) => string, check: (input: T) => void, runs = RUNS): void {
  const rng = new Rng(SEED ^ salt);
  for (let i = 0; i < runs; i++) {
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
const showBytes = (b: Uint8Array): string => `${String(b.length)} bytes: ${hex(b)}`;
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

/** `labels` binary labels of 1 to `longest` bytes, ending in the root or a pointer to the question. */
function deepName(rng: Rng, labels: number, longest: number): number[] {
  const out: number[] = [];
  for (let i = 0; i < labels; i++) {
    const len = 1 + rng.int(longest);
    out.push(len, ...rng.bytes(len));
  }
  out.push(...(rng.oneIn(2) ? [0] : [0xc0, 0x0c]));
  return out;
}

/**
 * An owner name: the root, a pointer to the question, or binary labels ending in either; now and
 * then just within the label limit, so mutations land near it.
 */
function ownerName(rng: Rng): number[] {
  if (rng.oneIn(32)) {
    return deepName(rng, MAX_LABELS - rng.int(4), rng.oneIn(4) ? 63 : 3);
  }
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

/** The query's question as a reply echoes it, its letters in either case. */
function echoQuestion(rng: Rng, query: Uint8Array): number[] {
  const question = Array.from(questionOf(query));
  for (let i = 0; i < question.length - 4; i++) {
    const b = question[i]!;
    if (fold(b) >= 0x61 && fold(b) <= 0x7a && rng.oneIn(2)) {
      question[i] = b ^ 0x20;
    }
  }
  return question;
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
  const question = echoQuestion(rng, query);
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

/** Parses `bytes` and checks it ends in a DnsError with `message`. */
function expectDnsError(bytes: Uint8Array, query: Uint8Array, message: string): void {
  let error: unknown = null;
  try {
    parseReply(bytes, query);
  } catch (e) {
    error = e;
  }
  expect(error, `a DnsError: ${message}`).toBeInstanceOf(DnsError);
  expect((error as DnsError).message).toBe(message);
}

// --- Arbitrary buffers ---

/**
 * Any bytes: empty, shorter than a header, around a header and question, a few KiB, or (one case
 * in 40) just under, at or just over the size limit. Most start with a header and question that
 * pass the first checks, so the bytes after them reach the records.
 */
function arbitrary(rng: Rng): Generated {
  const query = randomQuery(rng);
  let length: number;
  if (rng.oneIn(40)) {
    length = rng.pick([MAX_MESSAGE - 1 - rng.int(64), MAX_MESSAGE, MAX_MESSAGE + 1, MAX_MESSAGE + 2 + rng.int(64)]);
  } else {
    length = rng.pick([rng.int(12), 12 + rng.int(query.length + 8), rng.int(512), rng.int(4096)]);
  }
  const bytes = new Uint8Array(length);
  switch (rng.int(4)) {
    case 0:
      bytes.fill(rng.pick([0, 0xff, 0xc0, 0x3f, 0x29]));
      break;
    case 1: {
      const pattern = pathology(rng);
      for (let i = 0; i < length; i++) {
        bytes[i] = pattern[i % pattern.length]!;
      }
      break;
    }
    default:
      for (let i = 0; i < length; i++) {
        bytes[i] = rng.int(256);
      }
  }
  if (length >= 12 && !rng.oneIn(3)) {
    const count = (): number[] => u16(rng.pick([0, 0, 1, rng.int(4), rng.int(0x10000)]));
    const head = [
      ...u16(rng.oneIn(8) ? rng.int(0x10000) : queryId(query)),
      ...u16((rng.oneIn(8) ? 0 : 0x8000) | rng.int(0x8000)),
      ...u16(rng.oneIn(8) ? rng.int(4) : 1),
      ...count(),
      ...count(),
      ...count(),
    ];
    if (rng.oneIn(2)) {
      head.push(...echoQuestion(rng, query));
    }
    bytes.set(head.slice(0, length));
  }
  return { query, bytes };
}

// --- Replies built to reach one guard ---

interface Sections {
  an: number[][];
  ns: number[][];
  ar: number[][];
}

/** A reply's parts, with the EDE options and extended RCODE its OPT record (if any) carries. */
interface Parts {
  query: Uint8Array;
  flags: number;
  question: number[];
  sections: Sections;
  ede: Ede[];
  extendedRcode: number;
}

interface Guarded extends Generated {
  /** The reply the parse must return, or the message of the DnsError it must end in. */
  outcome: DnsReply | string;
}

const insertAt = <T>(rng: Rng, items: T[], item: T): void => {
  items.splice(rng.int(items.length + 1), 0, item);
};

/** A well-formed reply's parts: a few records in each section and, if `opt`, an OPT record. */
function parts(rng: Rng, opt: boolean): Parts {
  const query = randomQuery(rng);
  const flags = 0x8000 | rng.int(0x8000);
  const question = echoQuestion(rng, query);
  const sections: Sections = {
    an: Array.from({ length: rng.int(4) }, () => record(rng)),
    ns: Array.from({ length: rng.int(3) }, () => record(rng)),
    ar: Array.from({ length: rng.int(3) }, () => record(rng)),
  };
  const ede: Ede[] = [];
  const extendedRcode = opt ? rng.int(256) : 0;
  if (opt) {
    insertAt(rng, sections.ar, optRecord(rng, extendedRcode, ede));
  }
  return { query, flags, question, sections, ede, extendedRcode };
}

/** The reply's bytes; `counts` overrides ANCOUNT, NSCOUNT and ARCOUNT. */
function assemble(p: Parts, counts = [p.sections.an.length, p.sections.ns.length, p.sections.ar.length]): Uint8Array {
  const out = [...u16(queryId(p.query)), ...u16(p.flags), ...u16(1), ...counts.flatMap(u16), ...p.question];
  for (const rr of [...p.sections.an, ...p.sections.ns, ...p.sections.ar]) {
    for (const b of rr) {
      out.push(b);
    }
  }
  return Uint8Array.from(out);
}

/** The reply the parse of {@link assemble}'s bytes returns. */
const expectedOf = (p: Parts): DnsReply => ({
  id: queryId(p.query),
  rcode: (p.flags & 0xf) | (p.extendedRcode << 4),
  truncated: (p.flags & 0x0200) !== 0,
  answers: p.sections.an.length,
  ede: p.ede,
});

/** Where `rr` (one of `p`'s records) starts in {@link assemble}'s bytes. */
function offsetOf(p: Parts, rr: number[]): number {
  let o = 12 + p.question.length;
  for (const r of [...p.sections.an, ...p.sections.ns, ...p.sections.ar]) {
    if (r === rr) {
      return o;
    }
    o += r.length;
  }
  throw new Error('no such record');
}

/** A record of `owner`, type `type`, with up to 15 bytes of RDATA. */
function recordOf(rng: Rng, owner: number[], type: number): number[] {
  const rdata = rng.bytes(rng.int(16));
  return [...owner, ...u16(type), ...u16(1), ...u32(rng.int(0x10000)), ...u16(rdata.length), ...rdata];
}

/**
 * A record in any section whose owner has 125 to 131 labels: read up to the label limit, refused
 * past it.
 */
function deepOwner(rng: Rng): Guarded {
  const p = parts(rng, !rng.oneIn(4));
  const labels = MAX_LABELS - 3 + rng.int(7);
  const owner = deepName(rng, labels, rng.oneIn(4) ? 63 : 3);
  insertAt(rng, rng.pick([p.sections.an, p.sections.ns, p.sections.ar]), recordOf(rng, owner, rng.pick([1, 16, 28])));
  return { query: p.query, bytes: assemble(p), outcome: labels <= MAX_LABELS ? expectedOf(p) : 'too many labels' };
}

/**
 * Lengths that disagree with the bytes: a section count past the records present, an RDATA
 * length (of any record, OPT too) past the end of the message, or the message cut anywhere. A
 * well-formed reply is read to its last byte, so each ends in a truncated message.
 */
function inconsistentLengths(rng: Rng): Guarded {
  const p = parts(rng, !rng.oneIn(4));
  switch (rng.int(3)) {
    case 0: {
      const counts = [p.sections.an.length, p.sections.ns.length, p.sections.ar.length];
      const i = rng.int(3);
      counts[i] = Math.min(0xffff, counts[i]! + 1 + (rng.oneIn(2) ? rng.int(4) : rng.int(0x10000)));
      return { query: p.query, bytes: assemble(p, counts), outcome: 'truncated message' };
    }
    case 1: {
      const owner = ownerName(rng);
      const victim = recordOf(rng, owner, rng.pick([1, 28, 41]));
      insertAt(rng, rng.pick([p.sections.an, p.sections.ns, p.sections.ar]), victim);
      const bytes = assemble(p);
      const at = offsetOf(p, victim) + owner.length + 8;
      const left = bytes.length - (at + 2);
      const rdlength = Math.min(0xffff, left + 1 + (rng.oneIn(2) ? rng.int(4) : rng.int(0x10000)));
      bytes.set(u16(rdlength), at);
      return { query: p.query, bytes, outcome: 'truncated message' };
    }
    default: {
      const bytes = assemble(p);
      return { query: p.query, bytes: bytes.subarray(0, rng.int(bytes.length)), outcome: 'truncated message' };
    }
  }
}

/** Two or three OPT records among the additional records: refused. */
function secondOpt(rng: Rng): Guarded {
  const p = parts(rng, true);
  for (let i = 0, n = 1 + rng.int(2); i < n; i++) {
    insertAt(rng, p.sections.ar, optRecord(rng, rng.int(256), []));
  }
  return { query: p.query, bytes: assemble(p), outcome: 'second OPT record' };
}

/**
 * An OPT record whose options end badly: an option header cut short, an option longer than the
 * RDATA left, or an EDE option too short for its INFO-CODE. The short EDE option is refused unless
 * the 8 EDE options a parse keeps came before it, when it is skipped like any past the 8th.
 */
function optionFraming(rng: Rng): Guarded {
  const p = parts(rng, false);
  p.extendedRcode = rng.int(256);
  const options: number[] = [];
  const other = (): void => {
    const code = rng.pick([8, 10, 12, rng.int(0x10000)]);
    const data = rng.bytes(rng.int(30));
    options.push(...u16(code === 15 ? 12 : code), ...u16(data.length), ...data);
  };
  const ede = (): void => {
    const code = rng.int(0x10000);
    const text = extraText(rng);
    options.push(...u16(15), ...u16(2 + text.length), ...u16(code), ...text);
    if (p.ede.length < MAX_EDE) {
      p.ede.push({ code, text: decoder.decode(Uint8Array.from(text.slice(0, MAX_EXTRA_TEXT))) });
    }
  };
  const kind = rng.int(4);
  const leading = kind === 3 ? MAX_EDE + rng.int(3) : rng.int(MAX_EDE);
  for (let i = 0; i < leading; i++) {
    while (rng.oneIn(3)) {
      other();
    }
    ede();
  }
  if (rng.oneIn(2)) {
    other();
  }
  let outcome: DnsReply | string = 'truncated message';
  switch (kind) {
    case 0:
      options.push(...rng.bytes(1 + rng.int(3)));
      break;
    case 1: {
      const data = rng.bytes(rng.int(8));
      const length = data.length + 1 + (rng.oneIn(2) ? rng.int(4) : rng.int(0xffff - data.length));
      options.push(...u16(rng.oneIn(2) ? 15 : rng.int(0x10000)), ...u16(length), ...data);
      break;
    }
    default: {
      const short = rng.bytes(rng.int(2));
      options.push(...u16(15), ...u16(short.length), ...short);
      while (rng.oneIn(2)) {
        if (rng.oneIn(2)) {
          ede();
        } else {
          other();
        }
      }
      outcome = kind === 2 ? 'short EDE option' : expectedOf(p);
    }
  }
  const opt = [0, ...u16(41), ...u16(rng.int(0x10000)), p.extendedRcode, rng.int(256), ...u16(rng.int(0x10000)), ...u16(options.length), ...options];
  insertAt(rng, p.sections.ar, opt);
  return { query: p.query, bytes: assemble(p), outcome };
}

/** What the parse of a guarded case gives: the reply, or the message of its DnsError (any other error is thrown). */
function outcomeOf(c: Guarded): DnsReply | string {
  try {
    return parseReply(c.bytes, c.query);
  } catch (e) {
    if (e instanceof DnsError) {
      return e.message;
    }
    throw e;
  }
}

const showGuarded = (c: Guarded): string => `${typeof c.outcome === 'string' ? c.outcome : 'a reply'} expected from ${showBytes(c.bytes)}`;

// --- Dense replies at the size limit ---

interface Dense extends WellFormed {
  size: number;
  /** A byte for the tail that grows the reply to the limit and past it. */
  fill: number;
  /** A byte overwritten near the end, and its new value. */
  at: number;
  value: number;
}

/** A size at the limit, just under it, or within 4 KiB of it. */
const nearLimit = (rng: Rng): number => rng.pick([MAX_MESSAGE, MAX_MESSAGE - 1 - rng.int(16), MAX_MESSAGE - 1 - rng.int(4096)]);

/**
 * A well-formed reply of exactly `size` bytes: authority and additional records (an OPT among
 * them) as {@link wellFormed} writes them, then hundreds of answers (some with owners at the label
 * limit) until less than 1 KiB is left, then one record among the answers or authority records
 * whose RDATA fills the rest.
 */
function dense(rng: Rng, size: number): Dense {
  const p = parts(rng, true);
  p.sections.an = [];
  const length = (rrs: number[][]): number => rrs.reduce((n, rr) => n + rr.length, 0);
  let gap = size - (12 + p.question.length + length(p.sections.ns) + length(p.sections.ar));
  if (gap < 12) {
    throw new Error(`no room for the last record in ${String(size)} bytes`);
  }
  while (gap >= 12 + 1024) {
    const rr = rng.oneIn(64) ? recordOf(rng, deepName(rng, MAX_LABELS, 3), rng.pick([1, 16, 28])) : record(rng);
    // An owner at the label limit with long labels can run to 8 KiB; one that won't fit is dropped.
    if (rr.length <= gap - 12) {
      p.sections.an.push(rr);
      gap -= rr.length;
    }
  }
  const rdata = rng.bytes(gap - 12);
  const filler = [0xc0, 0x0c, ...u16(rng.pick([16, 99, 0xff00])), ...u16(1), ...u32(rng.int(0x10000)), ...u16(rdata.length)];
  for (const b of rdata) {
    filler.push(b);
  }
  insertAt(rng, rng.pick([p.sections.an, p.sections.ns]), filler);
  const bytes = assemble(p);
  return { query: p.query, bytes, expected: expectedOf(p), size, fill: rng.int(256), at: bytes.length - 1 - rng.int(64), value: rng.int(256) };
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

describe('DoH replies at the input boundaries (seeded random)', () => {
  it(
    'ends any bytes, empty to just past the size limit, in a DnsError or a reply that answers the query',
    () => {
      let accepted = 0;
      cases(
        7,
        arbitrary,
        (c) => showBytes(c.bytes),
        (c) => {
          if (c.bytes.length > MAX_MESSAGE) {
            expectDnsError(c.bytes, c.query, 'message too large');
          } else if (c.bytes.length < 12) {
            expectDnsError(c.bytes, c.query, 'truncated message');
          } else if (parsed(c) !== null) {
            accepted += 1;
          }
        },
      );
      // The headers written in front of the bytes let some through to the records and past them.
      if (RUNS >= 1000) {
        expect(accepted).toBeGreaterThan(0);
      }
    },
    TIMEOUT_MS,
  );

  it(
    'reads names up to the label limit in every section, and refuses longer ones',
    () => {
      cases(8, deepOwner, showGuarded, (c) => {
        expect(outcomeOf(c)).toEqual(c.outcome);
      });
    },
    TIMEOUT_MS,
  );

  it(
    'refuses section counts and RDATA lengths that run past the message',
    () => {
      cases(9, inconsistentLengths, showGuarded, (c) => {
        expect(outcomeOf(c)).toEqual(c.outcome);
      });
    },
    TIMEOUT_MS,
  );

  it(
    'refuses a second OPT record anywhere among the additional records',
    () => {
      cases(10, secondOpt, showGuarded, (c) => {
        expect(outcomeOf(c)).toEqual(c.outcome);
      });
    },
    TIMEOUT_MS,
  );

  it(
    'refuses EDNS options cut short and EDE options too short for an INFO-CODE',
    () => {
      cases(11, optionFraming, showGuarded, (c) => {
        expect(outcomeOf(c)).toEqual(c.outcome);
      });
    },
    TIMEOUT_MS,
  );

  it(
    'reads dense replies at the size limit field by field, and refuses them cut, recounted or grown past it',
    () => {
      cases(
        12,
        (rng) => dense(rng, nearLimit(rng)),
        (c) => showBytes(c.bytes),
        (c) => {
          const { query, bytes } = c;
          expect(bytes.length).toBe(c.size);
          expect(parseReply(bytes, query)).toEqual(c.expected);
          // A well-formed reply is read to its last byte, so one byte short or one record more is truncated.
          expectDnsError(bytes.subarray(0, bytes.length - 1), query, 'truncated message');
          const recounted = Uint8Array.from(bytes);
          recounted.set(u16(((bytes[10]! << 8) | bytes[11]!) + 1), 10);
          expectDnsError(recounted, query, 'truncated message');
          // Grown to the limit with trailing bytes, then one past it.
          const grown = new Uint8Array(MAX_MESSAGE + 1).fill(c.fill);
          grown.set(bytes);
          parsed({ query, bytes: grown.subarray(0, MAX_MESSAGE) });
          expectDnsError(grown, query, 'message too large');
          const overwritten = Uint8Array.from(bytes);
          overwritten[c.at] = c.value;
          parsed({ query, bytes: overwritten });
        },
        DENSE_RUNS,
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
