// DNS messages for the fake edge's DoH listener: reads the browsers' queries (any EDNS options,
// e.g. padding) and writes replies the way the edge does (the question echoed, answers pointing
// at it, an SOA for negative answers, and an OPT record with EDE options when the query had one).

export const TYPE_A = 1;
export const TYPE_SOA = 6;
export const TYPE_PTR = 12;
export const TYPE_AAAA = 28;
export const TYPE_OPT = 41;
export const RCODE_NOERROR = 0;
export const RCODE_NXDOMAIN = 3;
export const RCODE_REFUSED = 5;
export const EDE_BLOCKED = 15;

export interface Query {
  id: number;
  /** Lowercase, without the trailing dot. */
  name: string;
  qtype: number;
  /** The question section's bytes, echoed in the reply. */
  question: Buffer;
  hasOpt: boolean;
}

export interface Answer {
  rcode: number;
  a?: string[];
  aaaa?: string[];
  /** Adds an SOA to the authority section (negative answers), with this TTL and minimum. */
  negativeTtl?: number;
  ede?: { code: number; text: string }[];
  ttl?: number;
}

export function parseQuery(buf: Buffer): Query {
  if (buf.length < 12) {
    throw new Error('short DNS message');
  }
  const qd = buf.readUInt16BE(4);
  const an = buf.readUInt16BE(6);
  const ns = buf.readUInt16BE(8);
  const ar = buf.readUInt16BE(10);
  if (qd !== 1 || an !== 0 || ns !== 0) {
    throw new Error('not a single-question query');
  }
  let o = 12;
  const labels: string[] = [];
  for (;;) {
    const len = buf[o];
    if (len === undefined || len > 63) {
      throw new Error('bad name');
    }
    o += 1;
    if (len === 0) {
      break;
    }
    labels.push(buf.subarray(o, o + len).toString('latin1'));
    o += len;
  }
  const qtype = buf.readUInt16BE(o);
  o += 4;
  const question = buf.subarray(12, o);
  let hasOpt = false;
  for (let i = 0; i < ar; i++) {
    // The browsers send only the OPT record here: root name, then type, class, TTL, RDATA.
    if (buf[o] !== 0) {
      throw new Error('unexpected additional record');
    }
    const type = buf.readUInt16BE(o + 1);
    const rdlen = buf.readUInt16BE(o + 9);
    hasOpt ||= type === TYPE_OPT;
    o += 11 + rdlen;
  }
  return { id: buf.readUInt16BE(0), name: labels.join('.').toLowerCase(), qtype, question: Buffer.from(question), hasOpt };
}

const u16 = (n: number): Buffer => {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n);
  return b;
};
const u32 = (n: number): Buffer => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0);
  return b;
};

function ipv4Bytes(ip: string): Buffer {
  return Buffer.from(ip.split('.').map(Number));
}

function ipv6Bytes(ip: string): Buffer {
  const [head = '', tail] = ip.split('::');
  const parse = (s: string): number[] => (s === '' ? [] : s.split(':').map((g) => parseInt(g, 16)));
  const h = parse(head);
  const t = tail === undefined ? [] : parse(tail);
  const groups = [...h, ...new Array<number>(8 - h.length - t.length).fill(0), ...t];
  return Buffer.concat(groups.map(u16));
}

function record(type: number, ttl: number, rdata: Buffer, owner: Buffer = Buffer.from([0xc0, 0x0c])): Buffer {
  // The owner is by default a pointer to the question's name (offset 12).
  return Buffer.concat([owner, u16(type), u16(1), u32(ttl), u16(rdata.length), rdata]);
}

/** A pointer to the name's parent within the question (offset 12 + its first label), or the root. */
function parentOwner(q: Query): Buffer {
  const first = q.question[0] ?? 0;
  return first > 0 && q.question[1 + first] !== 0 ? Buffer.from([0xc0, 12 + 1 + first]) : Buffer.from([0]);
}

export function buildReply(q: Query, ans: Answer): Buffer {
  const ttl = ans.ttl ?? 1;
  const answers = [
    ...(q.qtype === TYPE_A ? (ans.a ?? []).map((ip) => record(TYPE_A, ttl, ipv4Bytes(ip))) : []),
    ...(q.qtype === TYPE_AAAA ? (ans.aaaa ?? []).map((ip) => record(TYPE_AAAA, ttl, ipv6Bytes(ip))) : []),
  ];
  const authority: Buffer[] = [];
  if (ans.negativeTtl !== undefined) {
    const n = ans.negativeTtl;
    // MNAME and RNAME are the root; serial, refresh, retry, expire, minimum.
    const rdata = Buffer.concat([Buffer.from([0, 0]), u32(1), u32(3600), u32(600), u32(86400), u32(n)]);
    // Owned by the name's parent, as a zone apex would be.
    authority.push(record(TYPE_SOA, n, rdata, parentOwner(q)));
  }
  const additional: Buffer[] = [];
  if (q.hasOpt) {
    const options = (ans.ede ?? []).map((e) => {
      const text = Buffer.from(e.text, 'utf8');
      return Buffer.concat([u16(15), u16(2 + text.length), u16(e.code), text]);
    });
    const rdata = Buffer.concat(options);
    additional.push(Buffer.concat([Buffer.from([0]), u16(TYPE_OPT), u16(1232), u32(0), u16(rdata.length), rdata]));
  }
  const header = Buffer.concat([
    u16(q.id),
    u16(0x8180 | (ans.rcode & 0xf)),
    u16(1),
    u16(answers.length),
    u16(authority.length),
    u16(additional.length),
  ]);
  return Buffer.concat([header, q.question, ...answers, ...authority, ...additional]);
}

/** The IP a reverse name (`in-addr.arpa`, `ip6.arpa`) stands for, or null. */
export function ipOfReverseName(name: string): string | null {
  const v4 = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\.in-addr\.arpa$/.exec(name);
  if (v4 !== null) {
    return [v4[4], v4[3], v4[2], v4[1]].join('.');
  }
  const v6 = /^((?:[0-9a-f]\.){32})ip6\.arpa$/.exec(name);
  if (v6 !== null) {
    const nibbles = (v6[1] ?? '').split('.').filter((x) => x !== '').reverse();
    const groups: string[] = [];
    for (let i = 0; i < 32; i += 4) {
      groups.push(parseInt(nibbles.slice(i, i + 4).join(''), 16).toString(16));
    }
    return groups.join(':');
  }
  return null;
}
