A second rendering of the UniFi layouts in `fixtures/unifi/`, also written from the spec rather than recorded from a gateway. Each set makes different guesses about details the spec leaves open, so the helper is tested against both:

- Firewall Policy comments carry an id (`FIREWALL_POLICY:6731c0de…`, unquoted), and the NFLOG prefix names the zone pair (`[LAN_WAN-R-30000]`) without the `FIREWALL_POLICY` tag.
- A Hotspot zone (`br20`) with its own zone→External chain, and Internal→Internal traffic matched on `UBIOS_local_zoned_subnets` itself.
- The port-53 DNAT sits in `UBIOS_PREROUTING_USER_HOOK`; IPv6 covers only `br0`.
- `ip-addr.json` holds this gateway's addresses. Each `.rules` file starts with what the helper should do with it.
