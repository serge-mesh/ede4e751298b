// Writes DNS replies for tests, the way the edge does: the query's question echoed, answers
// with compression pointers to it, and an OPT record with EDE options.

export interface Rr {
  type: number;
  rdata: number[];
  ttl?: number;
}

export interface ReplyOptions {
  rcode?: number;
  extendedRcode?: number;
  answers?: Rr[];
  authority?: Rr[];
  ede?: { code: number; text: string }[];
  opt?: boolean;
  id?: number;
  qr?: boolean;
}

const u16 = (n: number): number[] => [(n >> 8) & 0xff, n & 0xff];
const u32 = (n: number): number[] => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];

export function reply(query: Uint8Array, o: ReplyOptions = {}): Uint8Array {
  const answers = o.answers ?? [];
  const authority = o.authority ?? [];
  const opt = o.opt ?? true;
  const id = o.id ?? ((query[0] ?? 0) << 8) | (query[1] ?? 0);
  const flags = ((o.qr ?? true) ? 0x8000 : 0) | 0x0180 | ((o.rcode ?? 0) & 0xf);
  const out: number[] = [...u16(id), ...u16(flags), ...u16(1), ...u16(answers.length), ...u16(authority.length), ...u16(opt ? 1 : 0)];
  out.push(...query.subarray(12, query.length - 11));
  for (const rr of [...answers, ...authority]) {
    out.push(0xc0, 0x0c, ...u16(rr.type), ...u16(1), ...u32(rr.ttl ?? 10), ...u16(rr.rdata.length), ...rr.rdata);
  }
  if (opt) {
    const options: number[] = [];
    for (const e of o.ede ?? []) {
      const text = [...new TextEncoder().encode(e.text)];
      options.push(...u16(15), ...u16(2 + text.length), ...u16(e.code), ...text);
    }
    out.push(0, ...u16(41), ...u16(1232), ...u32(((o.extendedRcode ?? 0) << 24) >>> 0), ...u16(options.length), ...options);
  }
  return Uint8Array.from(out);
}

/** A response of `bytes` with HTTP status and headers, for a fake fetch. */
export function dnsResponse(bytes: Uint8Array, status = 200): Response {
  return new Response(new Uint8Array(bytes), { status, headers: { 'content-type': 'application/dns-message' } });
}

/** The DNS query in a DoH GET URL. */
export function queryOf(url: string): Uint8Array {
  const param = new URL(url).searchParams.get('dns') ?? '';
  const b64 = param.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/** The question name of a query, as text. */
export function qname(query: Uint8Array): string {
  const labels: string[] = [];
  let i = 12;
  for (;;) {
    const len = query[i] ?? 0;
    if (len === 0) {
      break;
    }
    labels.push(String.fromCharCode(...query.subarray(i + 1, i + 1 + len)));
    i += 1 + len;
  }
  return labels.join('.');
}

/** The question type of a query. */
export function qtype(query: Uint8Array): number {
  let i = 12;
  while ((query[i] ?? 0) !== 0) {
    i += 1 + (query[i] ?? 0);
  }
  return ((query[i + 1] ?? 0) << 8) | (query[i + 2] ?? 0);
}
