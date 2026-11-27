// DNS messages for the extension's DoH probe (browser-extension.md §3 step 2; edge.md §4, §12).
//
// The probe is one question with an OPT record, so the edge can answer with Extended DNS
// Errors (EDE, RFC 8914; sent only when the query has OPT, RFC 6891 §7). The reply comes from
// the network and is untrusted: every read is bounds-checked, every loop is bounded by the
// message length, and anything malformed is a `DnsError`.

export const QTYPE_A = 1;
export const QTYPE_PTR = 12;
export const TYPE_OPT = 41;
export const CLASS_IN = 1;
/** EDNS option code of an Extended DNS Error (RFC 8914). */
export const OPTION_EDE = 15;
/** EDE info-code 15, *Blocked*. */
export const EDE_BLOCKED = 15;
export const RCODE_NOERROR = 0;
export const RCODE_NXDOMAIN = 3;
/** The UDP payload size the probe advertises (any size works: the probe goes over DoH). */
export const EDNS_UDP_SIZE = 1232;
/** Largest DNS message (a DoH body bigger than this is refused before parsing). */
export const MAX_MESSAGE = 65_535;
/** Most EDE options kept from one reply. */
const MAX_EDE = 8;
/** Most bytes of EXTRA-TEXT kept per option (the edge sends at most 128). */
const MAX_EXTRA_TEXT = 512;

export class DnsError extends Error {
  override readonly name = 'DnsError';
}

export interface Ede {
  code: number;
  text: string;
}

export interface DnsReply {
  id: number;
  /** The full response code (header RCODE plus the OPT's extended bits). */
  rcode: number;
  truncated: boolean;
  answers: number;
  ede: Ede[];
}

/** The wire form of a host name: ASCII labels, each 1–63 bytes, at most 255 bytes in all. */
export function encodeName(name: string): Uint8Array {
  const trimmed = name.endsWith('.') ? name.slice(0, -1) : name;
  if (trimmed.length === 0) {
    throw new DnsError('empty name');
  }
  const labels = trimmed.split('.');
  const out: number[] = [];
  for (const label of labels) {
    if (label.length === 0 || label.length > 63) {
      throw new DnsError('bad label length');
    }
    out.push(label.length);
    for (let i = 0; i < label.length; i++) {
      const c = label.charCodeAt(i);
      // Host names from URLs are ASCII (IDNs arrive as punycode); no spaces or controls.
      if (c <= 0x20 || c >= 0x7f) {
        throw new DnsError('name is not printable ASCII');
      }
      out.push(c);
    }
  }
  out.push(0);
  if (out.length > 255) {
    throw new DnsError('name too long');
  }
  return Uint8Array.from(out);
}

/** A recursive query for `name`/`qtype`, class IN, with an OPT record (DO clear). */
export function buildQuery(name: string, qtype: number, id: number): Uint8Array {
  if (!Number.isInteger(id) || id < 0 || id > 0xffff) {
    throw new DnsError('bad id');
  }
  if (!Number.isInteger(qtype) || qtype < 1 || qtype > 0xffff) {
    throw new DnsError('bad qtype');
  }
  const qname = encodeName(name);
  const msg = new Uint8Array(12 + qname.length + 4 + 11);
  const v = new DataView(msg.buffer);
  v.setUint16(0, id);
  v.setUint16(2, 0x0100); // RD
  v.setUint16(4, 1); // QDCOUNT
  v.setUint16(10, 1); // ARCOUNT: the OPT record
  msg.set(qname, 12);
  let o = 12 + qname.length;
  v.setUint16(o, qtype);
  v.setUint16(o + 2, CLASS_IN);
  o += 4;
  msg[o] = 0; // root owner
  v.setUint16(o + 1, TYPE_OPT);
  v.setUint16(o + 3, EDNS_UDP_SIZE);
  v.setUint32(o + 5, 0); // extended RCODE 0, version 0, DO clear
  v.setUint16(o + 9, 0); // no options
  return msg;
}

/** RFC 8484 `dns` parameter: base64url without padding. */
export function base64url(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) {
    bin += String.fromCharCode(b);
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

class Reader {
  pos = 0;
  constructor(private readonly buf: Uint8Array) {}

  get remaining(): number {
    return this.buf.length - this.pos;
  }

  u8(): number {
    const b = this.buf[this.pos];
    if (b === undefined) {
      throw new DnsError('truncated message');
    }
    this.pos += 1;
    return b;
  }

  u16(): number {
    return (this.u8() << 8) | this.u8();
  }

  u32(): number {
    return ((this.u16() << 16) >>> 0) + this.u16();
  }

  bytes(n: number): Uint8Array {
    if (n < 0 || n > this.remaining) {
      throw new DnsError('truncated message');
    }
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  skip(n: number): void {
    this.bytes(n);
  }

  /** Skips a possibly compressed name (a pointer ends it; pointers aren't followed). */
  skipName(): void {
    for (let labels = 0; labels <= 128; labels++) {
      const len = this.u8();
      if (len === 0) {
        return;
      }
      const tag = len & 0xc0;
      if (tag === 0xc0) {
        this.u8();
        return;
      }
      if (tag !== 0) {
        throw new DnsError('bad label type');
      }
      this.skip(len);
    }
    throw new DnsError('too many labels');
  }
}

function sameQuestion(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    const lx = x >= 0x41 && x <= 0x5a ? x | 0x20 : x;
    const ly = y >= 0x41 && y <= 0x5a ? y | 0x20 : y;
    if (lx !== ly) {
      return false;
    }
  }
  return true;
}

/**
 * Parses a reply to `query` (as built by {@link buildQuery}): checks it is a response with the
 * query's id and question, and collects its EDE options.
 */
export function parseReply(buf: Uint8Array, query: Uint8Array): DnsReply {
  if (buf.length > MAX_MESSAGE) {
    throw new DnsError('message too large');
  }
  if (buf.length < 12 || query.length < 12) {
    throw new DnsError('truncated message');
  }
  const r = new Reader(buf);
  const id = r.u16();
  const flags = r.u16();
  const qd = r.u16();
  const an = r.u16();
  const ns = r.u16();
  const ar = r.u16();
  if ((flags & 0x8000) === 0) {
    throw new DnsError('not a response');
  }
  const queryId = ((query[0] ?? 0) << 8) | (query[1] ?? 0);
  if (id !== queryId) {
    throw new DnsError('id mismatch');
  }
  if (qd !== 1) {
    throw new DnsError('question count mismatch');
  }
  // The edge echoes the query's question bytes; anything else answers another question.
  const qStart = r.pos;
  r.skipName();
  r.skip(4);
  // The query is header, question, then the 11-byte OPT record.
  if (!sameQuestion(buf.subarray(qStart, r.pos), query.subarray(12, query.length - 11))) {
    throw new DnsError('question mismatch');
  }
  for (let i = 0; i < an + ns; i++) {
    r.skipName();
    r.skip(8);
    r.skip(r.u16());
  }
  let rcode = flags & 0x000f;
  const ede: Ede[] = [];
  let sawOpt = false;
  for (let i = 0; i < ar; i++) {
    r.skipName();
    const type = r.u16();
    r.u16(); // class (UDP size for OPT)
    const ttl = r.u32();
    const rdata = r.bytes(r.u16());
    if (type !== TYPE_OPT) {
      continue;
    }
    if (sawOpt) {
      throw new DnsError('second OPT record');
    }
    sawOpt = true;
    rcode |= (ttl >>> 24) << 4;
    const o = new Reader(rdata);
    while (o.remaining > 0) {
      const code = o.u16();
      const data = o.bytes(o.u16());
      if (code !== OPTION_EDE || ede.length >= MAX_EDE) {
        continue;
      }
      if (data.length < 2) {
        throw new DnsError('short EDE option');
      }
      const info = ((data[0] ?? 0) << 8) | (data[1] ?? 0);
      const textBytes = data.subarray(2, 2 + MAX_EXTRA_TEXT);
      ede.push({ code: info, text: new TextDecoder('utf-8', { fatal: false }).decode(textBytes) });
    }
  }
  return { id, rcode, truncated: (flags & 0x0200) !== 0, answers: an, ede };
}
