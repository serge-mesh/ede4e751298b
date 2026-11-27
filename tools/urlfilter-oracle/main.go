// Command urlfilter-oracle prints AdGuard Home's DNS decision for names against rule lists, as
// AdGuard Home v0.107.80 calls urlfilter v0.23's DNS engine (internal/filtering/filtering.go
// matchHost, processDNSResultRewrites, processDNSRewrites). It is the oracle of picket-rules'
// differential parity test (crates/picket-rules/PARITY.md).
//
// Input (stdin), line protocol:
//
//	case <id>
//	rule <rule text>                       (any number; one filter list per case)
//	query <qtype> <client-ip|-> <client-name|-> <tag,tag|-> <hostname text>
//	end
//
// The client name is percent-encoded (url.PathUnescape). The hostname is AdGuard Home's text
// form of the name (lowercased presentation form without the trailing dot), or an address's text
// for an answer check; it is the rest of the line.
//
// Output, one line per query: "<case>\t<index>\t<decision>", where decision is one of
//
//	none | allow | block | hosts <ip,ip,...> | rewrite cname <name> | rewrite rcode <n> |
//	rewrite records <type>=<value>|<type>=<value>...
//
// Go regex mode (picket-rules' goregex differential, review round 1):
//
//	re <id>\t<Go regex>
//	sj <subject>                            (any number)
//	re-end
//
// prints "<id>\tERR" when Go's regexp.Compile refuses the regex, otherwise "<id>\tOK\t<bits>"
// with one 0/1 per subject (MatchString).
//
// Response mode (AdGuard Home's filterDNSResponse on a recorded answer), inside a case:
//
//	resp <qtype> <client-ip|-> <client-name|-> <tag,tag|-> <qname>\t<rr>;<rr>;...
//
// with each rr one of "CNAME <target>", "A <ip>", "AAAA <ip>", "HTTPS <prio> <target>
// [ipv4hint=<ip,...>] [ipv6hint=<ip,...>]", "SVCB …" (same fields) or "MX <pref> <host>". It prints
// "<case>\t<index>\t<decision>": "request <decision>" when the query's own decision isn't "none"
// (AdGuard Home then doesn't filter the response), else "response block <rr index>" for the first
// answer record that matchHost filters, or "response pass".
package main

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
)

type query struct {
	qtype uint16
	ip    netip.Addr
	name  string
	tags  []string
	host  string
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<24)
	out := bufio.NewWriterSize(os.Stdout, 1<<20)
	defer out.Flush()

	var caseID string
	var ruleLines []string
	var queries []query
	var reID, rePat string
	var subjects []string
	var resps []response
	for in.Scan() {
		line := in.Text()
		switch {
		case strings.HasPrefix(line, "re "):
			reID, rePat, _ = strings.Cut(strings.TrimPrefix(line, "re "), "\t")
			subjects = subjects[:0]
		case strings.HasPrefix(line, "sj "):
			subjects = append(subjects, strings.TrimPrefix(line, "sj "))
		case line == "re-end":
			runRegex(out, reID, rePat, subjects)
		case strings.HasPrefix(line, "case "):
			caseID = strings.TrimPrefix(line, "case ")
			ruleLines = ruleLines[:0]
			queries = queries[:0]
			resps = resps[:0]
		case strings.HasPrefix(line, "resp "):
			r, err := parseResponse(line)
			if err != nil {
				fmt.Fprintf(os.Stderr, "case %s: %v\n", caseID, err)
				os.Exit(2)
			}
			resps = append(resps, r)
		case strings.HasPrefix(line, "rule "):
			ruleLines = append(ruleLines, strings.TrimPrefix(line, "rule "))
		case strings.HasPrefix(line, "query "):
			q, err := parseQuery(line)
			if err != nil {
				fmt.Fprintf(os.Stderr, "case %s: %v\n", caseID, err)
				os.Exit(2)
			}
			queries = append(queries, q)
		case line == "end":
			runCase(out, caseID, ruleLines, queries, resps)
		}
	}
	if err := in.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

// runRegex prints Go's verdict on one regex and its matches on the subjects.
func runRegex(out *bufio.Writer, id, pat string, subjects []string) {
	re, err := regexp.Compile(pat)
	if err != nil {
		fmt.Fprintf(out, "%s\tERR\n", id)
		return
	}
	bits := make([]byte, len(subjects))
	for i, s := range subjects {
		bits[i] = '0'
		if re.MatchString(s) {
			bits[i] = '1'
		}
	}
	fmt.Fprintf(out, "%s\tOK\t%s\n", id, bits)
}

func parseQuery(line string) (q query, err error) {
	f := strings.SplitN(line, " ", 6)
	if len(f) != 6 {
		return q, fmt.Errorf("bad query line %q", line)
	}
	t, err := strconv.ParseUint(f[1], 10, 16)
	if err != nil {
		return q, err
	}
	q.qtype = uint16(t)
	if f[2] != "-" {
		q.ip, err = netip.ParseAddr(f[2])
		if err != nil {
			return q, err
		}
	}
	if f[3] != "-" {
		q.name, err = url.PathUnescape(f[3])
		if err != nil {
			return q, err
		}
	}
	if f[4] != "-" {
		q.tags = strings.Split(f[4], ",")
	}
	q.host = f[5]
	return q, nil
}

// response is a query and its recorded answer records.
type response struct {
	q   query
	rrs []string
}

func parseResponse(line string) (r response, err error) {
	head, rrs, ok := strings.Cut(line, "\t")
	if !ok {
		return r, fmt.Errorf("bad resp line %q", line)
	}
	r.q, err = parseQuery("query " + strings.TrimPrefix(head, "resp "))
	if err != nil {
		return r, err
	}
	for _, rr := range strings.Split(rrs, ";") {
		if rr = strings.TrimSpace(rr); rr != "" {
			r.rrs = append(r.rrs, rr)
		}
	}
	return r, nil
}

// filtered mirrors AdGuard Home's matchHost for one response item as filterDNSResponse uses it:
// a rewrite (other than a CNAME to the host itself) and an exception leave it unfiltered; a block
// rule or any hosts rule filters it (FilteredBlockList).
func filtered(engine *urlfilter.DNSEngine, q query) bool {
	d := decide(engine, q)
	return d == "block" || strings.HasPrefix(d, "hosts")
}

// decideResponse mirrors processFilteringAfterResponse and filterDNSResponse (internal/dnsforward
// filter.go, process.go) for a block filter engine.
func decideResponse(engine *urlfilter.DNSEngine, r response) string {
	if d := decide(engine, r.q); d != "none" {
		return "request " + d
	}
	item := func(host string, rrtype uint16) bool {
		q := r.q
		q.host = host
		q.qtype = rrtype
		return filtered(engine, q)
	}
	for i, rr := range r.rrs {
		f := strings.Fields(rr)
		if len(f) < 2 {
			continue
		}
		hit := false
		switch f[0] {
		case "CNAME":
			// The rest of the record: a name may hold an escaped space ("x\\ y.example.").
			target := strings.TrimSpace(strings.TrimPrefix(rr, "CNAME"))
			hit = item(strings.TrimSuffix(target, "."), dns.TypeCNAME)
		case "A":
			hit = item(net.ParseIP(f[1]).String(), dns.TypeA)
		case "AAAA":
			hit = item(net.ParseIP(f[1]).String(), dns.TypeAAAA)
		case "HTTPS":
			// Only the hints, each checked as type HTTPS (filterHTTPSRecords, filterSVCBHint).
			for _, kv := range f[2:] {
				k, v, _ := strings.Cut(kv, "=")
				if k != "ipv4hint" && k != "ipv6hint" {
					continue
				}
				for _, ip := range strings.Split(v, ",") {
					if !hit && item(net.ParseIP(ip).String(), dns.TypeHTTPS) {
						hit = true
					}
				}
			}
		default:
			// SVCB, MX and others aren't checked.
		}
		if hit {
			return fmt.Sprintf("response block %d", i)
		}
	}
	return "response pass"
}

func runCase(out *bufio.Writer, id string, ruleLines []string, queries []query, resps []response) {
	list := filterlist.NewString(&filterlist.StringConfig{
		ID:             1,
		RulesText:      strings.Join(ruleLines, "\n"),
		IgnoreCosmetic: true,
	})
	storage, err := filterlist.NewRuleStorage([]filterlist.Interface{list})
	if err != nil {
		fmt.Fprintf(os.Stderr, "case %s: %v\n", id, err)
		os.Exit(2)
	}
	engine := urlfilter.NewDNSEngine(storage)
	for i, q := range queries {
		fmt.Fprintf(out, "%s\t%d\t%s\n", id, i, decide(engine, q))
	}
	for i, r := range resps {
		fmt.Fprintf(out, "%s\tr%d\t%s\n", id, i, decideResponse(engine, r))
	}
}

// decide mirrors AdGuard Home's matchHost for a block filter engine (no allowlist engine).
func decide(engine *urlfilter.DNSEngine, q query) string {
	host := strings.ToLower(q.host)
	req := &urlfilter.DNSRequest{
		Hostname:          host,
		ClientTags:        container.NewSortedSliceSet(q.tags...),
		ClientIP:          q.ip,
		ClientIdentifiers: container.NewSortedSliceSet(q.name),
		DNSType:           q.qtype,
	}
	res, matched := engine.MatchRequest(req)

	// processDNSResultRewrites: rewrites first.
	if dnsr := res.DNSRewrites(); len(dnsr) > 0 {
		if d, ok := processDNSRewrites(dnsr, host); ok {
			return d
		}
	}
	if !matched {
		return "none"
	}
	if nr := res.NetworkRule; nr != nil {
		if nr.Whitelist {
			return "allow"
		}
		return "block"
	}
	var ips []string
	for _, h := range res.HostRulesV4 {
		ips = append(ips, h.IP.String())
	}
	for _, h := range res.HostRulesV6 {
		ips = append(ips, h.IP.String())
	}
	sort.Strings(ips)
	ips = dedup(ips)
	return "hosts " + strings.Join(ips, ",")
}

// processDNSRewrites mirrors AdGuard Home's: the first CNAME or non-NOERROR rewrite answers alone;
// otherwise values merge by type. A CNAME to the name itself is ignored (ok = false).
func processDNSRewrites(dnsr []*rules.NetworkRule, host string) (d string, ok bool) {
	var recs []string
	for _, nr := range dnsr {
		dr := nr.DNSRewrite
		if dr.NewCNAME != "" {
			if dr.NewCNAME == host {
				return "", false
			}
			return "rewrite cname " + dr.NewCNAME, true
		}
		if dr.RCode != dns.RcodeSuccess {
			return "rewrite rcode " + strconv.Itoa(dr.RCode), true
		}
		if dr.Value != nil {
			recs = append(recs, fmt.Sprintf("%d=%s", dr.RRType, valueText(dr.Value)))
		}
	}
	sort.Strings(recs)
	recs = dedup(recs)
	return strings.TrimSpace("rewrite records " + strings.Join(recs, "|")), true
}

func valueText(v rules.RRValue) string {
	switch v := v.(type) {
	case netip.Addr:
		return v.String()
	case string:
		return v
	case *rules.DNSMX:
		return fmt.Sprintf("%d %s", v.Preference, v.Exchange)
	case *rules.DNSSRV:
		return fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, v.Target)
	case *rules.DNSSVCB:
		s := fmt.Sprintf("%d %s", v.Priority, v.Target)
		keys := make([]string, 0, len(v.Params))
		for k := range v.Params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			s += " " + k + "=" + v.Params[k]
		}
		return s
	default:
		return fmt.Sprintf("%v", v)
	}
}

func dedup(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}
