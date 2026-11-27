// Hosts of page URLs: host names, IPv4 and IPv6 literals, and the reverse names the PTR probe
// asks for an IP (browser-extension.md §3 step 2).

export type Host =
  | { kind: 'name'; name: string }
  | { kind: 'ip'; ip: string; version: 4 | 6 };

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

/** The 16-bit groups of an IPv6 address (with an optional embedded IPv4 tail), or null. */
export function ipv6Groups(text: string): number[] | null {
  if (text.length === 0 || text.length > 45 || !/^[0-9A-Fa-f:.]+$/.test(text)) {
    return null;
  }
  let s = text;
  if (s.includes('.')) {
    // An embedded IPv4 tail becomes its two groups.
    const lastColon = s.lastIndexOf(':');
    const v4 = s.slice(lastColon + 1);
    if (lastColon < 0 || !IPV4.test(v4)) {
      return null;
    }
    const o = v4.split('.').map(Number);
    const hi = (((o[0] ?? 0) << 8) | (o[1] ?? 0)).toString(16);
    const lo = (((o[2] ?? 0) << 8) | (o[3] ?? 0)).toString(16);
    s = `${s.slice(0, lastColon + 1)}${hi}:${lo}`;
  }
  const parts = s.split('::');
  if (parts.length > 2) {
    return null;
  }
  const parse = (p: string): number[] | null => {
    if (p === '') {
      return [];
    }
    const out: number[] = [];
    for (const g of p.split(':')) {
      if (!/^[0-9A-Fa-f]{1,4}$/.test(g)) {
        return null;
      }
      out.push(parseInt(g, 16));
    }
    return out;
  };
  const head = parse(parts[0] ?? '');
  const rest = parts.length === 2 ? parse(parts[1] ?? '') : [];
  if (head === null || rest === null) {
    return null;
  }
  const total = head.length + rest.length;
  if (parts.length === 2) {
    return total > 7 ? null : [...head, ...new Array<number>(8 - total).fill(0), ...rest];
  }
  return total === 8 ? head : null;
}

/** RFC 5952 text of IPv6 groups: lowercase, the first longest run of two or more zeros as `::`. */
export function ipv6Text(groups: readonly number[]): string {
  let best = -1;
  let bestLen = 1;
  for (let i = 0; i < groups.length; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < groups.length && groups[j] === 0) {
      j++;
    }
    if (j - i > bestLen) {
      best = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (best < 0) {
    return hex.join(':');
  }
  return `${hex.slice(0, best).join(':')}::${hex.slice(best + bestLen).join(':')}`;
}

/**
 * The host of an `http:` or `https:` URL, or null for another scheme or no host. IPv4-mapped
 * IPv6 literals count as the IPv4 address (as the edge canonicalises them).
 */
export function hostOf(url: string): Host | null {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    return null;
  }
  let h = u.hostname.toLowerCase();
  if (h.startsWith('[') && h.endsWith(']')) {
    const groups = ipv6Groups(h.slice(1, -1));
    if (groups === null) {
      return null;
    }
    const mapped = groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff;
    if (mapped) {
      const a = groups[6] ?? 0;
      const b = groups[7] ?? 0;
      return { kind: 'ip', version: 4, ip: [a >> 8, a & 255, b >> 8, b & 255].join('.') };
    }
    return { kind: 'ip', version: 6, ip: ipv6Text(groups) };
  }
  if (IPV4.test(h)) {
    return { kind: 'ip', version: 4, ip: h };
  }
  if (h.endsWith('.')) {
    h = h.slice(0, -1);
  }
  return h.length > 0 ? { kind: 'name', name: h } : null;
}

/**
 * False for an IP no firewall block can be about, so the extension doesn't probe it: an IP allow
 * names a unicast address of another host (edge.md §12), and a browser reaches loopback,
 * link-local and "this network" addresses without passing the edge's firewall. Left out: IPv4
 * 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16 and 224.0.0.0/3 (multicast, reserved, broadcast); IPv6
 * ::/96 (unspecified, loopback, IPv4-compatible), fe80::/10 and ff00::/8. IPv4-mapped IPv6 is
 * already read as IPv4 by `hostOf`.
 */
export function isProbeableIp(host: Extract<Host, { kind: 'ip' }>): boolean {
  if (host.version === 4) {
    const [a = 0, b = 0] = host.ip.split('.').map(Number);
    return !(a === 0 || a === 127 || (a === 169 && b === 254) || a >= 224);
  }
  const g = ipv6Groups(host.ip);
  if (g === null) {
    return false;
  }
  const first = g[0] ?? 0;
  return !(g.slice(0, 6).every((x) => x === 0) || (first & 0xffc0) === 0xfe80 || (first & 0xff00) === 0xff00);
}

/** An IP's canonical text (IPv4 dotted, IPv6 RFC 5952, IPv4-mapped as IPv4), or null. */
export function canonicalIp(text: string): string | null {
  const h = hostOf(`http://${text.includes(':') ? `[${text}]` : text}/`);
  return h?.kind === 'ip' ? h.ip : null;
}

/** The reverse-lookup name of an IP (`in-addr.arpa` or `ip6.arpa`). */
export function reverseName(host: Extract<Host, { kind: 'ip' }>): string {
  if (host.version === 4) {
    return `${host.ip.split('.').reverse().join('.')}.in-addr.arpa`;
  }
  const groups = ipv6Groups(host.ip);
  if (groups === null) {
    throw new Error('not an IPv6 address');
  }
  const nibbles: string[] = [];
  for (const g of [...groups].reverse()) {
    for (let shift = 0; shift < 16; shift += 4) {
      nibbles.push(((g >> shift) & 0xf).toString(16));
    }
  }
  return `${nibbles.join('.')}.ip6.arpa`;
}

/** Text safe to show: control characters escaped as `\xNN` / `\u{…}` (shown via textContent). */
export function printable(text: string): string {
  let out = '';
  for (const ch of text) {
    const c = ch.codePointAt(0) ?? 0;
    if (c < 0x20 || (c >= 0x7f && c < 0xa0)) {
      out += `\\x${c.toString(16).padStart(2, '0')}`;
    } else if (c === 0x2028 || c === 0x2029 || (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069)) {
      // Line separators and bidi controls could reorder what the user reads.
      out += `\\u{${c.toString(16)}}`;
    } else {
      out += ch;
    }
  }
  return out;
}
