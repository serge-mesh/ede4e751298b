// Picket's EDE EXTRA-TEXT (edge.md §4 "Extended DNS Errors"): ASCII `key=value` tokens
// separated by spaces; values percent-encode bytes outside `A-Za-z0-9-._~`; `bundle=<id>@<head>`
// joins two encoded parts with a literal `@`. Over 128 bytes the edge drops tokens from the left,
// `block` last, so any token but `block` may be missing.

import { EDE_BLOCKED, RCODE_NXDOMAIN, type DnsReply, type Ede } from './dns';

/** Longest decoded value kept (longer ones are dropped). */
const MAX_VALUE = 255;
const KEY = /^[a-z][a-z0-9_-]{0,31}$/;
/** What a block id may hold: the edge's ids are eight base32 characters. */
const BLOCK_ID = /^[A-Za-z0-9._~-]{1,64}$/;

/** Decodes `%XX` escapes as UTF-8 bytes; a `%` not followed by two hex digits stays as it is. */
export function percentDecode(raw: string): string {
  const bytes: number[] = [];
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charCodeAt(i);
    if (c === 0x25 && i + 2 < raw.length && /^[0-9A-Fa-f]{2}$/.test(raw.slice(i + 1, i + 3))) {
      bytes.push(parseInt(raw.slice(i + 1, i + 3), 16));
      i += 2;
    } else if (c < 0x80) {
      bytes.push(c);
    } else {
      // Not ASCII (the edge never sends it): keep the character as UTF-8.
      for (const b of new TextEncoder().encode(raw.charAt(i))) {
        bytes.push(b);
      }
    }
  }
  return new TextDecoder('utf-8', { fatal: false }).decode(Uint8Array.from(bytes));
}

/** The raw (still encoded) value of each token; the first of a repeated key wins. */
export function parseTokens(text: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const token of text.split(' ')) {
    const eq = token.indexOf('=');
    if (eq <= 0) {
      continue;
    }
    const key = token.slice(0, eq);
    if (!KEY.test(key) || out.has(key)) {
      continue;
    }
    out.set(key, token.slice(eq + 1));
  }
  return out;
}

function decoded(raw: string | undefined): string | undefined {
  if (raw === undefined) {
    return undefined;
  }
  const v = percentDecode(raw);
  return v.length > 0 && v.length <= MAX_VALUE ? v : undefined;
}

/** A Picket DNS block, as the EDE of a block reply describes it. */
export interface DnsBlock {
  blockId: string;
  bundle?: string;
  head?: string;
  lookup?: string;
  verdict?: string;
}

/** The block one EDE option describes: EDE 15 with a valid `block=` token, else null. */
export function blockFromEde(ede: Ede): DnsBlock | null {
  if (ede.code !== EDE_BLOCKED) {
    return null;
  }
  const t = parseTokens(ede.text);
  const blockId = decoded(t.get('block'));
  if (blockId === undefined || !BLOCK_ID.test(blockId)) {
    return null;
  }
  const out: DnsBlock = { blockId };
  const bundleRaw = t.get('bundle');
  if (bundleRaw !== undefined) {
    const at = bundleRaw.indexOf('@');
    const bundle = decoded(at < 0 ? bundleRaw : bundleRaw.slice(0, at));
    const head = at < 0 ? undefined : decoded(bundleRaw.slice(at + 1));
    if (bundle !== undefined) {
      out.bundle = bundle;
    }
    if (head !== undefined) {
      out.head = head;
    }
  }
  const lookup = decoded(t.get('lookup'));
  if (lookup !== undefined) {
    out.lookup = lookup;
  }
  const verdict = decoded(t.get('verdict'));
  if (verdict !== undefined) {
    out.verdict = verdict;
  }
  return out;
}

/** The block a name probe's reply reports (edge.md §12), or null for a miss. */
export function dnsBlockOf(reply: DnsReply): DnsBlock | null {
  for (const e of reply.ede) {
    const b = blockFromEde(e);
    if (b !== null) {
      return b;
    }
  }
  return null;
}

/**
 * True when a PTR probe's reply says Picket holds no grant for the IP (edge.md §12): NXDOMAIN
 * with EDE 15 `cause=firewall`.
 */
export function isFirewallBlock(reply: DnsReply): boolean {
  return (
    reply.rcode === RCODE_NXDOMAIN &&
    reply.ede.some((e) => e.code === EDE_BLOCKED && decoded(parseTokens(e.text).get('cause')) === 'firewall')
  );
}
