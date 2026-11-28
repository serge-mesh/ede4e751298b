# `dns` lookup module

Asks a filtering resolver whether it blocks a name, and takes only the verdict from its answer
(providers.md §5 `dns`). The config, rules, detail and presets are specified there; this file gives
the presets' sources and the fixtures' provenance.

## Presets

### `quad9` (category `security`)

- Servers `9.9.9.9`, `149.112.112.112`, `2620:fe::fe`, `2620:fe::9`; TLS name `dns.quad9.net`;
  DoT on 853, DoH on 443 at `/dns-query`. Source: Quad9's service addresses page,
  <https://www.quad9.net/service/service-addresses-and-features>.
- Blocks: the live `isitblocked.org` recordings below return NXDOMAIN with Extended DNS Error
  (RFC 8914) 17 *Filtered* and an empty authority section, matching the preset's `filtered`
  rule. The preset also recognises EDE 15 *Blocked* and 16 *Censored*, including on SERVFAIL.
  A real NXDOMAIN carries the zone's SOA, and locally synthesised NXDOMAINs (RFC 8198) carry
  EDE 29 *Synthesized*. `censored` is its own rule so an admin can set it to `clean` (RFC 8914 §4.17:
  a block for a legal requirement). `nxdomain_without_soa` gives Unknown rather than Block, so a
  nonexistent name answered without an SOA isn't blocked for `block_ttl_s`.
- Self-test: `isitblocked.org`, expected Block, hourly (`0 * * * *`).

### `nextdns` (category `mixed`)

- Servers: the anycast addresses `45.90.28.0`, `45.90.30.0`, `2a07:a8c0::`, `2a07:a8c1::`. DoT
  uses the TLS name `<profile>.dns.nextdns.io`; DoH uses `dns.nextdns.io` with the path
  `/<profile>`. Source: the Setup tab of a NextDNS configuration (<https://my.nextdns.io>), which
  lists these endpoints for the configuration ID.
- Blocks: the live denylist recordings below return NOERROR, `0.0.0.0` (A), and EDE 17 with the
  text `Blocked by NextDNS: blacklist`. NextDNS also uses `::` for blocked AAAA queries. This
  is undocumented; with the profile's Block Page on, A answers point at
  the block page instead (the EDE rule still matches, or add the page's addresses to `sinkhole`).
- Self-test: optional, a name on the profile's denylist, expected Block, hourly. It catches the
  free plan's monthly limit, past which NextDNS answers without filtering.

## Fixtures (`tests/`)

One file per resolver and transport, each with cases `case`, `qname`, `qtype`, `answer` (hex,
replayed with the query's ID) and `expect <verdict> <rule|->`:

| File | Live recordings | Synthesised |
|---|---|---|
| `nextdns-dot.txt`, `nextdns-doh.txt` | `example.com` (denylisted: NOERROR, `0.0.0.0`, EDE 17 `Blocked by NextDNS: blacklist`), `example.org` (normal), `nxdomain-picket-fixture.iana.org` (NXDOMAIN + SOA), from `45.90.28.0` using a profile (2026-11-28; UTC timestamp per case) | `sinkhole_without_ede`: `0.0.0.0` without EDE, not observed with these queries |
| `quad9-dot.txt`, `quad9-doh.txt`, `quad9-udp.txt` | `isitblocked.org` (NXDOMAIN, EDE 17, no SOA), `nxdomain-picket-fixture.iana.org` (NXDOMAIN + SOA), `x.invalid` (NXDOMAIN + SOA, EDE 29 `Result synthesized by root-nx-trust`), `example.com` (normal), `dnssec-failed.org` (SERVFAIL with DNSSEC EDE 6 or 7), from `9.9.9.9` (2026-11-28; UTC timestamp per case) | `censored` (EDE 16), `filtered` (EDE 17 on SERVFAIL), `nxdomain_without_soa` (no SOA or EDE); no live test names available |

The 2026-11-28 recordings were collected on a remote Linux host over SSH. Each live case is
marked with its UTC timestamp; the DNS response bytes are copied verbatim, including the original
query ID, flags, TTLs and EDNS options. Only the ID is patched when replaying a fixture. The
remaining synthetic cases are marked individually and retained for rule coverage.

Queries match the module's `picket-wire` upstream writer: A/IN, RD set, DO and CD clear, an OPT
with payload 1232, and no ECS. DoT and DoH queries carry RFC 8467 padding to 128-byte blocks;
UDP queries are unpadded. **All live replies were unpadded**, including Quad9 DoT/DoH. Padding
in the remaining synthetic Quad9 DoT/DoH edge cases is test-only parser coverage, not an observed
resolver behaviour.

To re-record, send those queries to the preset's first server, with TLS certificate verification:

- Quad9: `9.9.9.9`, TLS name `dns.quad9.net`, DoT port 853, DoH `/dns-query` on 443.
  Use HTTP/2 for DoH (HTTP/1.1 returned 505 on this recording network).
- NextDNS: `45.90.28.0`, DoT TLS name `<profile>.dns.nextdns.io` on 853, DoH
  `https://dns.nextdns.io/<profile>` on 443. Use a profile with the test name denylisted and a
  different normal name. These recordings use `example.com` and `example.org`, respectively.

Use a nonexistent name under a real zone and verify NXDOMAIN plus SOA before replacing
`nonexistent`: the old NextDNS `nxdomain-picket-fixture.example.org` recording was actually
NOERROR/NODATA. Check EDE 29 for `synthesized`, and the actual RCODE, address and EDE text for a
denylisted name; do not infer them from the case name or a Clean/Block verdict.

Run `cargo test --locked -p picket-lookup answers_per_transport` to replay all eight Quad9 cases
per transport and all four NextDNS cases per transport. The tests check every verdict and rule,
the NXDOMAIN/SOA, synthesized, SERVFAIL and NextDNS denylist facts, and detail under 512 bytes.
