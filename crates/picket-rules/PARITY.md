# AdGuard parity harness

`dns` and `ip` rules must decide as AdGuard Home v0.107.80 decides with urlfilter v0.23.x
(rules.md §3; README §2 "AdGuard parity"). This crate checks that in these layers.

## 1. The differential test (`tests/urlfilter_parity.rs`)

build-and-test.md §4–§5 "AdGuard parity": at least **99.99 %** decision agreement with urlfilter on
a rules × names corpus, every `rule_policy` option at `keep`.

**The oracle** is `tools/urlfilter-oracle`, a small Go program pinned to
`github.com/AdguardTeam/urlfilter v0.23.4` (go.mod / go.sum). It reads cases on stdin (a rule list
and queries), builds one `DNSEngine` per case as AdGuard Home does (one filter list,
`IgnoreCosmetic`), and prints AdGuard Home's decision per query by porting `matchHost`,
`processDNSResultRewrites` and `processDNSRewrites` (internal/filtering): rewrites first (the first
CNAME or rcode rewrite answers alone, values otherwise merge, a CNAME to the name itself is
ignored), then the basic network rule (`block` / `allow`), then hosts rules with their addresses.
It also has a response mode (§5) and a Go-regex mode (§6). The protocol is documented at the top of
`main.go`.

**Go versions.** `go.mod`'s `go 1.27.4` is the minimum the module (and its dependencies) needs
(golibs v0.35.20 declares `go 1.27.4`): any Go from 1.27.4 builds it, and an older `go` command with
`GOTOOLCHAIN=auto` (Go's default) fetches 1.27.4 itself. The recommended toolchain is the one the
recorded tables and the results below were produced with, currently also Go 1.27.4: the oracle's
Go-regex mode (§6) reports what the building Go's `regexp` accepts, so a different Go release can
disagree on that mode's edge cases. The two are allowed to differ; raise the `go` line only when a
dependency needs it, and record the Go release in the results when the tables are regenerated with
a new one.

**Maintenance.** Dependabot proposes updates to the oracle's Go modules (`gomod`,
`/tools/urlfilter-oracle`, weekly, grouped). `github.com/AdguardTeam/urlfilter` and `golibs` are
the behaviour under comparison: an update to either is merged together with a parity run against
the new oracle (and regenerated tables, §3), never on its own.

Build and run:

```sh
# Go 1.27.4 (the minimum and the recommended toolchain), user-locally (no root): the official tarball, checked against go.dev's SHA-256
curl -sSLO https://go.dev/dl/go1.27.4.linux-amd64.tar.gz
tar -C ~/.local/opt -xzf go1.27.4.linux-amd64.tar.gz
export PATH=$HOME/.local/opt/go/bin:$PATH

(cd tools/urlfilter-oracle && go build -o /tmp/urlfilter-oracle .)
PICKET_URLFILTER_ORACLE=/tmp/urlfilter-oracle cargo test --release -p picket-rules \
  --test urlfilter_parity --test response_parity --test goregex_parity --test top_lists -- --nocapture
```

Without `PICKET_URLFILTER_ORACLE` the oracle tests check their recorded tables (§3) or print a skip
message. The name report is written to `$CARGO_TARGET_TMPDIR/urlfilter-parity-report.txt`.

**The corpus** (`tests/common/mod.rs`) is generated deterministically:

- *single rules*: ~190 rule texts covering every form and modifier the crate supports × 73 names
  (ordinary names, names that are IP text, and 13 names with unusual bytes: `!`, a `.` byte inside a
  label, space, `\000`, `\255`, uppercase, `/`) × 6 query contexts + 10 answer addresses;
- *pairs*: every ordered pair of 31 interacting rules on one domain family × 10 names × 2 contexts;
- the three AdGuard parity examples of build-and-test.md §5;
- *rewrite order*: rewrites whose answer depends on urlfilter's matched-rule order (`src/order.rs`):
  shortcut slices, unindexed rules, browser rules taking slots, urlfilter's exception skipping;
- *`$denyallow` entities* (`tracker.*`) with the bundled public suffix list, on names under ICANN,
  private and wildcard suffixes, no suffix, and urlfilter's text quirk (`a.tracker.xtracker.com`);
- *fixtures*: the AdGuard-readable files in `fixtures/rules/` as whole lists × all names × 2 contexts;
- *the hand-written corpus*: every group of `fixtures/rules/parity-corpus.txt` (§2). The test also
  fails if a written expectation there isn't urlfilter's decision (groups marked `(picket)` excepted).

**The metric** counts every decision except those rules.md §3's deliberate exceptions make, decided
per decision by re-running the case:

1. *protocol/port extension*: the case without its extension rules agrees with AdGuard;
2. *names with unusual bytes*: the name has a label holding a byte other than `a-z0-9-_`, and the
   case with its keyed rules read as AdGuard's text patterns agrees (keyed rules match whole labels);
3. *response-check differences*: don't arise for single names (§5 measures them);
4. *`rule_policy`*: every option is `keep`.

Three deviations wait for an owner decision. Each is its own reported group, asserted against an
explicit list of expected deviations (`EXPECTED_DEVIATIONS` in the test; a new deviation, or a listed
one that no longer occurs, fails the test):

- **normalisation** (rules.md §1): rule names are normalised (ASCII lowercase, IDN → A-labels,
  trailing dot stripped; `$denyallow` names and entity prefixes too). AdGuard compares host rules,
  hosts lines and `$denyallow` text as written and keeps a key's trailing dot.
- **several `$badfilter` rules on one request**: urlfilter keeps a rule unless *every* `$badfilter`
  matching the request negates it (`filterNegatedRules`), so `||example.com^` + `||example.com^$badfilter`
  + `||www.example.com^$badfilter` still blocks `www.example.com` in AdGuard; Picket resolves each
  `$badfilter` on its own (rules.md §4) and blocks nothing there.
- **browser path rules × names with `/` bytes** (review round 1, R10): rules.md §2 sends network
  rules with a URL path to browser lists, but AdGuard's DNS engine still matches them against a
  name's text, which can hold `/` (`/ads/banner` blocks `x/ads/banner.example`). Picket keeps them
  browser-only: shipping every path rule (tens of thousands in EasyList) as an edge pattern to match
  names no resolver sees would cost edge RAM for nothing. The expected list is every decision a path
  rule changes on a `/` name.

A hosts-line answer compares as Picket reads hosts lines: any block address (`0.0.0.0`,
`127.0.0.1`, `::`) among the matched lines is a block (feeds.md §4), otherwise the set of mapped
addresses.

## 2. The hand-written corpus (`tests/parity_corpus.rs`)

`fixtures/rules/parity-corpus.txt` holds ~120 rule groups (one bundle each) with the decision for
each name or answer address, written from urlfilter's DNS engine tests and rule docs, and from the
oracle for the review-round-1 groups (bare `^`, Go regex acceptance, `$denyallow` entities, rewrite
order, text compared as written, IPv6 hosts lines, IPv4-mapped `$client`). `decisive=` pins the
rule attribution must name. The file documents its syntax. The test checks Picket against every
line on every `cargo test`; the differential test (§1) runs the same groups through the oracle.
Groups marked `(picket)` check a deviation the spec names instead.

## 3. The recorded tables (CI has no Go)

- `fixtures/rules/urlfilter-expectations.tsv` (`tests/parity_table.rs`): ~3,450 rule × name rows
  (the single-rule cases, parity examples, rewrite-order and entity cases).
- `fixtures/rules/response-expectations.tsv` (`tests/response_parity.rs`): ~1,070 response-phase rows.
- `fixtures/rules/go-regex-expectations.tsv` (`tests/goregex_parity.rs`): 4,000 Go regexes with Go's
  verdict and matches on 38 subjects.

Regenerate after changing a corpus:

```sh
PICKET_URLFILTER_ORACLE=/tmp/urlfilter-oracle PICKET_WRITE_PARITY_TABLE=1 \
  cargo test -p picket-rules --test parity_table
PICKET_URLFILTER_ORACLE=/tmp/urlfilter-oracle PICKET_WRITE_RESPONSE_TABLE=1 \
  cargo test -p picket-rules --test response_parity
PICKET_URLFILTER_ORACLE=/tmp/urlfilter-oracle PICKET_WRITE_GOREGEX_TABLE=1 \
  cargo test --release -p picket-rules --test goregex_parity
```

## 4. The top lists (`tests/top_lists.rs`)

rules.md §3 "≥ 99.99 % agreement on the top lists". `tools/urlfilter-oracle/fetch-top-lists.sh`
fetches the AdGuard DNS filter, EasyList, HaGeZi Pro and TIF (adblock syntax) and FireHOL level 1 into
`$PICKET_TOP_LISTS_DIR` (default `~/.cache/picket/top-lists`), never into the repository. The test
runs each present list as one bundle against names sampled from its own rules (each key and a name
below it, names around pattern literals), the corpus names and answer addresses, with §1's
exclusions; skipped without the oracle or the lists. FireHOL is read as an `adblock` list there
(AdGuard parity of that reading); Picket's preset reads it as `plain`, whose indicators aren't
AdGuard rules.

## 5. Response phase (`tests/response_parity.rs`)

build-and-test.md §5: response-phase decisions replayed on recorded upstream answers
(`fixtures/rules/recorded-answers.txt`: CNAME chains, A/AAAA, HTTPS/SVCB with hints and target names,
MX, unusual target names), compared with AdGuard Home v0.107.80's `filterDNSResponse`, which the
oracle ports: only when the query has no result; CNAME targets as type CNAME, answer IPs as A/AAAA,
HTTPS hints as HTTPS; a rewrite on an item is ignored, an exception passes it, a block or any hosts
line blocks the response. Picket's side applies rules.md §5 step 5 and §6 with the reference matcher;
a host-IP mapping matched there counts as a block, as in AdGuard Home. rules.md §6's differences
(SVCB hints, HTTPS/SVCB target names) are excluded per decision, as are §1's exceptions.

## 6. Go regex acceptance (`tests/goregex_parity.rs`)

`src/goregex.rs` ports Go's `regexp/syntax` parser (tree, factoring, limits) and writes Rust syntax
from the tree. 40,000 deterministic random regexes (urlfilter rule syntax and Go's corner cases) must
be accepted exactly when Go's `regexp.Compile` accepts them and match exactly the subjects Go
matches; a regex Go accepts that is over the shared NFA limit counts as dropped (rules.md §3).

## 7. Unit tests

`src/*` unit tests pin each piece to urlfilter's source: `adguard.rs` (rule splitting, pattern →
regex, match target, the shortcut and its quirks), `goregex.rs` (Go acceptance, folding, limits),
`order.rs` (urlfilter's slice filing), `psl.rs` (`x/net/publicsuffix`), `entity.rs` (`matchWildcard`,
expansion = full list on every rule of the bundled list, the shared `rich.json` entity table),
`rewrite.rs`, `badfilter.rs` (`negatesBadfilter` identity; the cross-feed scan: sound over ordinary
names, aggregated per canceller, within its work cap), `matcher.rs` (the regex resident set).

## Results (2026-11-21, urlfilter v0.23.4, Go 1.27.4; review round 2)

Re-run on 2026-11-28 with golibs v0.35.20 and miekg/dns v1.1.73 (Dependabot #101): every group
below unchanged, the regenerated tables identical, and the top lists (fetched that day) all at
100.0000 % (AdGuard DNS filter 15,320 · EasyList 13,322 · HaGeZi Pro 12,270 · HaGeZi TIF 12,182 ·
FireHOL level 1 2,465 queries).

| Group | Agreement |
|---|---|
| main (the metric) | **92,208 / 92,208 (100.0000 %)**; excluded: 95 extension-rule decisions, 1,786 unusual-name decisions (12,012 unusual-name queries, 10,202 agree) |
| response phase | **106,256 / 106,256 (100.0000 %)**, 2,585 of them response blocks; excluded: 706 rules.md §6, 976 unusual bytes, 36 extension |
| top lists | AdGuard DNS filter 15,448/15,448 · HaGeZi Pro 12,198/12,198 (re-run in round 2, 100.0000 %); round 1: EasyList 13,902/13,902 · HaGeZi TIF (1.22 M rules) 12,166/12,166 · FireHOL level 1 2,473/2,473 |
| Go regexes | 40,000: 13,104 accepted, 26,613 refused, 283 over the NFA limit; 0 differ from Go |
| owner: normalisation | 62/83 agree; the 21 others are exactly the listed deviations |
| owner: several `$badfilter` | 2/12 agree; the 10 others are exactly the listed deviations |
| owner: path rules × `/` names | 0/12 agree; exactly the decisions path rules change |

## Semantics followed where urlfilter is quirky

- Inline `#` in host rules: urlfilter cuts the line one byte *before* the `#`
  (`0.0.0.0 example.com#x` blocks `example.co`); Picket does the same.
- A hosts line takes any token as its name (`0.0.0.0 2001:db8::1` blocks that answer address); a
  token keys can't hold becomes the exact-text pattern `|token|`, still a host rule. A mapping to
  another address (`192.0.2.1 2001:db8::1`) is that pattern with the address: the text name answers
  with it, and an answer address it matches is blocked (review round 2).
- The shortcut is a hard requirement: `/ads|tracker/` needs `tracker`, `/\bads\b/` needs `bads`.
- A bare `^` pattern matches nothing, whatever its modifiers; `/*` (normalised to `^`) matches all.
- `$badfilter` and `@@…$dnsrewrite` compare text as written: `||Example.org^$badfilter` doesn't
  remove `||example.org^`, and a rewrite's CNAME keeps its case (`Self.EXAMPLE` isn't the name).
- `$badfilter` never touches `$dnsrewrite` rules, and a `$dnsrewrite,badfilter` rule rewrites.
- `$badfilter` doesn't compare `$dnstype`, `$denyallow` or `$dnsrewrite`; one with its own
  `$dnstype`/`$denyallow` removes its target only for queries it matches.
- Rewrites and `@@…$dnsrewrite` follow urlfilter's matched-rule order, including the exception it
  skips after one that removed an earlier rule (that one then merges as a value).
- `@@…$dnsrewrite=…` with an MX, SRV or HTTPS/SVCB value cancels nothing (Go compares pointers).
- `$denyallow` rules never match IP text; entities follow `matchWildcard` (public suffix from
  `x/net/publicsuffix`, ICANN only, and its text test); `||1.2.3.4^` also decides the name `1.2.3.4`
  and its subdomains; `||10.0.0^` matches the address text's last labels (`1.10.0.0`, not `10.0.0.7`).
- `$client` with an IPv4-mapped address never matches an IPv4 client.
- Go regex syntax as Go 1.27 reads it: `\C` refused, numeric and repeated capture names accepted,
  nested repeats over 1000 copies refused, loose Unicode names (`\pl`, `\p{Letter}`, `\p{greek}`),
  scripts as Script (not Script_Extensions), factoring quirks kept.
- A host rule is a token that passes AdGuard's host-name check on its A-label, lowercase form; a
  trailing dot fails it, so `example.com.` and `ads.` stay patterns (and `https://ads.` isn't the
  protocol/port extension of `ads`).
