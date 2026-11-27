# `dns` lookup module

Asks a filtering resolver whether it blocks a name, and takes only the verdict from its answer
(providers.md §5 `dns`). The config, rules, detail and presets are specified there; this file gives
the presets' sources and the fixtures' provenance.

## Presets

### `quad9` (category `security`)

- Servers `9.9.9.9`, `149.112.112.112`, `2620:fe::fe`, `2620:fe::9`; TLS name `dns.quad9.net`;
  DoT on 853, DoH on 443 at `/dns-query`. Source: Quad9's service addresses page,
  <https://www.quad9.net/service/service-addresses-and-features>.
- Blocks: Quad9 answers a blocked name with NXDOMAIN (or SERVFAIL) and an Extended DNS Error
  (RFC 8914) 15 *Blocked*, 16 *Censored* or 17 *Filtered*, with an empty authority section; a
  real NXDOMAIN carries the zone's SOA, and locally synthesised NXDOMAINs (RFC 8198) carry EDE 29
  *Synthesized*. `censored` is its own rule so an admin can set it to `clean` (RFC 8914 §4.17:
  a block for a legal requirement). `nxdomain_without_soa` gives Unknown rather than Block, so a
  nonexistent name answered without an SOA isn't blocked for `block_ttl_s`.
- Self-test: `isitblocked.org`, expected Block, hourly (`0 * * * *`).

### `nextdns` (category `mixed`)

- Servers: the anycast addresses `45.90.28.0`, `45.90.30.0`, `2a07:a8c0::`, `2a07:a8c1::`. DoT
  uses the TLS name `<profile>.dns.nextdns.io`; DoH uses `dns.nextdns.io` with the path
  `/<profile>`. Source: the Setup tab of a NextDNS configuration (<https://my.nextdns.io>), which
  lists these endpoints for the configuration ID.
- Blocks: NextDNS answers a blocked name `0.0.0.0` (A) or `::` (AAAA) with EDE 17 and the text
  `Blocked by NextDNS`. This is undocumented; with the profile's Block Page on, A answers point at
  the block page instead (the EDE rule still matches, or add the page's addresses to `sinkhole`).
- Self-test: optional, a name on the profile's denylist, expected Block, hourly. It catches the
  free plan's monthly limit, past which NextDNS answers without filtering.

## Fixtures (`tests/`)

One file per resolver and transport, each with cases `case`, `qname`, `qtype`, `answer` (hex,
replayed with the query's ID) and `expect <verdict> <rule|->`:

| File | Live recordings | Synthesised |
|---|---|---|
| `nextdns-dot.txt`, `nextdns-doh.txt` | `example.com` and a nonexistent name, from `45.90.28.0` without a profile (2026-11-20T19:16:38Z) | a denylisted name (`0.0.0.0` + EDE 17 `Blocked by NextDNS`), `0.0.0.0` without EDE |
| `quad9-dot.txt`, `quad9-doh.txt`, `quad9-udp.txt` | none | `isitblocked.org` (EDE 15), EDE 16, EDE 17 on SERVFAIL, a nonexistent name with SOA, EDE 29, NXDOMAIN without SOA, a normal answer, a bare SERVFAIL |

Quad9 (DoT and DoH) was unreachable from the network the fixtures were recorded on, and a
denylisted NextDNS name needs a profile. The synthesised answers follow the published behaviour
above. **To replace them with recordings:** send a padded query (RFC 8467, 128-byte blocks; the
module's own query writer) over each transport to the preset's first server, for `isitblocked.org`,
a nonexistent name under a real zone, a name Quad9 answers with EDE 29, a normal name, and, on a
NextDNS profile with a denylist entry, that name; paste each answer's hex into the matching case.
The tests check every case's verdict and rule, and that its detail stays under 512 bytes.
