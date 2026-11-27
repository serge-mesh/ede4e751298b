# fixtures/wire

Recorded DNS exchanges for picket-wire's tests, allocation budgets and fuzz seeds
(build-and-test.md §4, §5).

Each `<name>.txt` holds one upstream exchange: comment lines (`#`) with what it is and where it was
recorded, then `query <hex>` (the query exactly as picket-wire's upstream query writer builds it:
RD, the edge's OPT with UDP size 1232, DO as noted, and RFC 8467 padding for DoT) and
`answer <hex>` (the resolver's answer, unmodified).

| File | Answer |
|---|---|
| `plain-a.txt` | `example.com A`, plain |
| `cname-chain.txt` | `www.microsoft.com A`: a CNAME chain through edgekey.net and akamaiedge.net |
| `signed-nsec3-nxdomain.txt` | NXDOMAIN in the NSEC3-signed `com` zone: SOA, NSEC3 proofs, RRSIGs |
| `nxdomain-soa.txt` | NXDOMAIN with the zone SOA |
| `nodata-signed.txt` | NODATA with a signed SOA and NSEC |
| `https-hints.txt` | `cloudflare.com HTTPS`: alpn and ipv4hint |
| `dname.txt` | a DNAME with its synthesised CNAME, a wildcard-expanded A and an NSEC proof |
| `dot-padded-a.txt` | `example.com A` over DoT: padded query, answer padded to 468 bytes |
| `wildcard-nsec3.txt` | a wildcard-expanded signed A with its NSEC3 proof (constructed, see below) |

`queries.txt` holds client queries, one per line as `<name> <hex>`: the baseline shapes the
allocation budgets name (`a-no-opt`, `a-opt`, `aaaa-opt-do`, `https-opt-padded`) and other shapes
with committed budgets (`crates/picket-wire/tests/alloc_budget.rs`).

Answers were recorded on 2026-11-21 from Cloudflare's 1.1.1.1 (UDP and DoT), except
`wildcard-nsec3.txt`, built by hand with dummy signatures (from the first generation's fixtures)
for a shape public resolvers rarely return; its query is what the writer builds for it. Re-recording
changes TTLs and record order, so tests assert structure (types, names, counts), not TTL values;
the allocation budgets in `alloc_budget.rs` may need re-baselining in the same commit.
