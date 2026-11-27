#!/bin/sh
# Fetches the top lists the AdGuard parity test runs on when they are present
# (crates/picket-rules/tests/top_lists.rs, PARITY.md): the AdGuard DNS filter, EasyList, HaGeZi Pro
# and Threat Intelligence Feeds (adblock syntax) and FireHOL level 1. They stay in a cache
# directory, never in the repository.
#
#   tools/urlfilter-oracle/fetch-top-lists.sh            # into $PICKET_TOP_LISTS_DIR
#                                                        # (default ~/.cache/picket/top-lists)
set -eu

dir="${PICKET_TOP_LISTS_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/picket/top-lists}"
mkdir -p "$dir"

fetch() {
	name="$1"
	url="$2"
	curl -fsSL --proto '=https' --max-time 300 --max-filesize 104857600 -o "$dir/$name.tmp" "$url"
	mv "$dir/$name.tmp" "$dir/$name"
	printf '%s\t%s lines\n' "$name" "$(wc -l < "$dir/$name")"
}

fetch adguard-dns.txt https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
fetch easylist.txt https://easylist.to/easylist/easylist.txt
fetch hagezi-pro.txt https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt
fetch hagezi-tif.txt https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt
fetch firehol-level1.netset https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset
date -u +%Y-%m-%dT%H:%M:%SZ > "$dir/fetched-at"
echo "top lists in $dir"
