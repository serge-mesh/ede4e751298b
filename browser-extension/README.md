# picket-browser-extension

Picket's block page and temporary allows for Brave and Firefox. The spec's `browser-extension.md` is normative. One TypeScript codebase, built with Vite and `webextension-polyfill`.

## Commands

Node ≥ 26.13.1. Use the exact version in the repository’s `.node-version` for reproducible archives.

The type-check script uses the TypeScript 7 compiler installed as `typescript-native`.
`typescript` stays on 6.0.3 to supply the compiler API required by ESLint.

| Command | Does |
|---|---|
| `npm ci` | installs the pinned dependencies (`package-lock.json`) |
| `npm run build` | builds `dist/brave` (Chromium MV3) and `dist/firefox` (Firefox MV3 ≥ 128 ESR) |
| `npm run lint` | type-checks, runs ESLint and `web-ext lint` on `dist/firefox` (build first) |
| `npm test` | runs the Vitest suites (jsdom, a fake WebExtension API) |
| `npm run test:fuzz` | runs the DoH codec's seeded random tests (`test/dns-fuzz.test.ts`: generated, broken and arbitrary replies, replies built to hit each parser guard, dense replies at the 64 KiB limit, EXTRA-TEXT as the edge writes it) with 100,000 cases each (4,000 for the dense replies) from a random seed (about 5 minutes; not in CI, where `npm test` runs 2,000 from seed 1). A failure prints its seed: `PICKET_FUZZ_SEED=<seed> npm run test:fuzz` repeats it, and `PICKET_FUZZ_RUNS` sets the cases (both are kept when set) |
| `npm run test:browser` | builds, then runs the real-browser tests in Playwright's Chromium and Firefox, headless (first `npx playwright install chromium firefox`; `PICKET_HEADED=1` shows the browsers) |
| `npm run test:browser:slow` | builds, then runs the opt-in slow browser tests (several minutes; not in CI): the edge's real TTL and `retry_after_s`, blocked loads after the background went idle, Chromium's dropped connections, and the block page test with 300 loads |
| `npm run package` | builds, then writes `dist/picket-browser-extension-<ver>-brave.zip` and `-firefox.xpi` with `.sha256` files |

`PICKET_VERSION` sets the version (else `package.json`'s). Builds and packages are reproducible: unminified code with fixed names, archives with sorted entries and one timestamp (`SOURCE_DATE_EPOCH`, else 2026-01-01).

## Layout

| Path | Holds |
|---|---|
| `src/background/` | the background script: edge client (bypass API, DoH probe), page-load flow, sub-resource detection, per-tab store, message router |
| `src/pages/` | block page, popup, options (HTML, TypeScript, one stylesheet) |
| `src/shared/` | DNS codec, EDE parsing, hosts, settings, messages, API types, the block-error lists |
| `scripts/` | build, manifests, packaging (ZIP writer), Firefox lint, icon drawing |
| `test/` | Vitest suites |
| `test/browser/` | real-browser tests (Playwright) and their harness: a fake edge (DoH and the bypass API over HTTPS with a test CA), local sites and block targets, the two browser drivers |

## Restarts and bounds

The background script unloads after ~30 s idle (Brave's service worker, Firefox's event page). What a restart would lose is kept in `storage.session` (README §2 "Restarts"), each only while it has a use:

- the edge's clock skew (origin, skew, when learned);
- each tab's pending retry after an allow (URL, phase, window, and the due time of a second attempt, kept until its navigation starts, so a restarted script makes an attempt that was due or not yet started): dropped when its navigation completes or fails for good, when another navigation starts or the tab closes, and when its 60 s window ends (or at the next start, if no script ran then);
- each tab's blocked hosts: cleared with the tab's next page or when it closes;
- a long page URL for a block page: kept for its tab only while the tab shows that block page (dropped when the tab navigates elsewhere or closes, or when the block page was never opened).

Pending retries and kept URLs live in memory, mirrored to one key each (`retries`, `blockUrls`): decisions never wait on storage, and a restarted script reads each key once. Until that read is done, every event that reads or changes the state waits in a list and is then applied to the restored state in arrival order (`session.ts`); nothing is written before the read. Each tab's blocked hosts aren't kept in memory: every write reads the stored list first.

Every change to a tab (the block page, the reload after an allow, its retry, a listed blocked host) is checked right before it is made, after its last await, against the tab's navigation token and the allow epoch it was decided under (`tab-guard.ts`); a main-frame probe answered while allows changed is made again.

Bounds the spec leaves to the implementer (README §2 "Bounded"; policy choices, owner to confirm):

| What | Value | Where |
|---|---|---|
| Edge clock skew (from each reply's `Date`) trusted for | 60 s; older or from the future → a `GET /v1/temporary-allows` learns it before an allow's `expires_at` is computed, so a clock step errs by ≤ 60 s. Any skew is used (the edge's own `Date`, over TLS); a reply without a usable `Date` refuses the allow (`no_edge_time`) | `edge-client.ts` `CLOCK_FRESH_MS` |
| Retry after an allow's reload | once, 2 s later, within 60 s; bound to the navigation it started (a new navigation to the same URL takes it over; any other top-level navigation cancels it); at most 16 tabs with one pending | `navigation.ts` `MAX_RETRIES` |
| Main-frame probes | one pending failure per tab (its newest; one probe per (tab, host)); 4 in flight, 32 tabs waiting, the rest dropped and counted; a failure keeps its slot until its block page is opened or abandoned (a newer failure of the host takes it over, and gets the page once the opening ends) | `navigation.ts` `MAX_PROBES`, `MAX_WAITING_PROBES` |
| Events waiting for the read of kept retries or URLs after a start | 64 per key; one more gives that key's kept state up (this script's state replaces it) | `session.ts` `MAX_EARLY` |
| Sub-resource probes | one per host; 4 in flight, 64 hosts waiting, results cached 60 s (512 hosts) | `subresources.ts` |
| Blocked hosts per tab | 50; writes coalesced per tab (one in flight, one waiting) | `tab-store.ts` |
| Page URL kept for the block page | ≤ 4096 characters in its query; up to 64 KiB in `storage.session` (one per tab, at most 16); longer: the allow still works and the page says to load it again | `block-info.ts` |

A second attempt is timed in memory (no `alarms` permission): if the script stops within its 2 s, or after asking for the attempt but before its navigation starts, the attempt is made when the script next starts (on the tab's next event, or any other), within the 60 s window. In that last case it may load the page twice.

Sub-resource lists follow the tab's navigation token, which changes when the next navigation starts, while the page it leaves runs on until the next one commits and then runs its unload handlers. Brave says which document a request came from, so a failure of a page being unloaded (`documentLifecycle: pending_deletion`, e.g. an unload beacon), going into the back/forward cache (`cached`, e.g. a pagehide beacon) or prerendered is ignored. Firefox has no such field: there such a failure is listed for the next page. On both, a request the old page makes between the next navigation's start and its commit is listed for the next page.

Not probed (no firewall block can be about them): IPv4 `0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`, `224.0.0.0/3`; IPv6 `::/96`, `fe80::/10`, `ff00::/8` (IPv4-mapped read as IPv4). The edge's PTR probe likewise answers `cause=firewall` only for an IP a `PATCH` would accept (unicast, not the edge itself).

History: on Firefox the block page replaces the failed load's entry (`tabs.update` `loadReplace`), and so does the reload after an allow. Firefox commits a failed load's error page only after `onErrorOccurred`, and a LAN probe can answer first, so the block page waits for that commit (at most 2 s; without its event, the tab's top frame (`webNavigation.getFrame`) says whether it committed: showing the failed URL in a document other than the one the failure left, the error page is replaced; otherwise, or without Firefox's document IDs, a plain load, which ends a pending error page and so leaves the failed load no entry either, and never drops one): replacing earlier would replace the page before it, and pushing after it would leave the failed entry behind *Go back* (both seen in the browser tests under load); Chromium has no such option, so the block page's *Go back* skips the failed entry (`history.go(-2)`). The browser's own Back button on Chromium still returns to the failed entry. The browser tests check that *Go back* returns to the page before on both.

Same-URL navigations: Firefox starts a load from an extension page (the block page's reload after an allow) a second time in a web content process, with a second `onBeforeNavigate`; Chromium's error page starts a failed URL again by itself about 1 s after the failure (seen in the browser tests: it loads the page once the DNS answer has changed, and fails as `net::ERR_ABORTED` while it hasn't). A pending retry follows the newest navigation to its URL. On Firefox the extension's attempt 2 s later is what loads the page after a stale answer; on Chromium the error page's own reload comes first (the stale-answer test passes on Chromium without the extension's attempt, not on Firefox).

`src/shared/block-errors.ts` holds the `details.error` values that trigger a probe, per browser and host kind. A host name's failure is probed for any error a block mode produces (the EDE decides). An IP literal's is probed only for a connect-level error (refused, reset, timed out, unreachable): the PTR answer says Picket holds no grant, not that it refused this connection, so a TLS, certificate, empty-response or closed-connection error (which needs a completed connection) never gets a firewall block page (except on Firefox, which reports a closed connection as a reset). The browser tests check the lists against what each browser reports ("Real-browser tests" below); the background console logs each top-frame failure's error and outcome (never its URL) at debug level to help.

## Install

- **Brave:** unzip `-brave.zip` into a fixed folder, open `brave://extensions`, turn on Developer mode, *Load unpacked*. To update, replace the folder's contents and press *Reload*. The ID is fixed by the manifest `key`: `aagdcikeegoglnhilmlaonmjnmlckdgk`.
- **Firefox Developer Edition, Nightly or ESR:** set `xpinstall.signatures.required` to `false` in `about:config`, then `about:addons` → *Install Add-on From File…* with `-firefox.xpi`. Release Firefox is not supported.

Then, in the options page: the edge API URL (e.g. `https://dns.home.arpa:9853`) and optionally core's UI URL; *Save and test* grants access to the edge and checks `GET /v1/temporary-allows`. The browser must trust the LAN CA root.

Blocked sub-resource detection on Brave works from the browser's next start: Chromium passes `webRequest` events for access granted at run time only after a restart (an extension reload doesn't help), and the options page says so when it is turned on. Firefox starts at once.

## Real-browser tests

`npm run test:browser` (browser-extension.md §5) runs the built extension in Playwright's Chromium (Chrome for Testing 159, standing in for Brave) and Firefox (159), headless, against a fake edge on 127.0.0.1: DoH and the bypass API over HTTPS with a test CA, the browsers' only resolver (Chromium's secure DNS in the profile, Firefox's TRR), answering each name as a block response would, with EDE. The fake edge refuses what the edge refuses (no extension header, a non-extension `Origin`, a preflight), writes EXTRA-TEXT in the edge's token order with EDE 4 on answers that carry records, and gives IP allows `retry_after_s` 0; by default DNS answers live 1 s and DNS allows get `retry_after_s` 1, to keep the run short. Local servers stand in for the sites and the block targets; nothing reaches the network or a core. The CI job `browser-extension` runs them in Playwright's image; `npm run test:browser:slow` adds the slow ones below.

| §5 / flow | Covered (both browsers unless noted) | Spec |
|---|---|---|
| Setup | options page opened on install, https-only edge URL, the edge's host permission, the test `GET` with `X-Picket-Client`, only the two URLs stored | `setup` |
| Block detection | DoH probe (type A, extension header) for every block mode; PTR probe for a firewall-blocked IP literal; no block page for failures that aren't blocks | `blocks` |
| Block page | name and bundle, lookup provider and verdict, or IP and stage; 15 min / 1 h allows as `PATCH` (`block_id` or `ip`, `subdomains` only when ticked); countdown, reload, and the second attempt after a stale answer; `403` (only "ask an admin / open core UI") and other errors (Retry); *Go back* | `blocks` |
| Popup | blocked sub-resources (DNS and firewall) with the badge, allowing selected hosts, *End now*, *Reload page*; on Brave before its restart, no detection and the restart hint instead of a list | `popup` |
| Browser-list URLs | pruned, full and bundle URLs on core's address, the `-full` check, Copy | `lists` |
| `details.error` per block type | every block response, custom_ip targets that reset, close, fail TLS (handshake, wrong name, untrusted) or drop; IP-literal refusals, resets and drops; page loads and sub-resources; Firefox with HTTPS-First too | `errors` |
| Block page for blocked loads | 24 blocked loads across the modes and IP literals, back to back: 24/24 on both. That bounds the miss rate below about 12 % (95 % confidence), not the 1 % of §5, which takes about 300 loads (`PICKET_BROWSER_LOADS=300`, which the slow run sets: 300/300 on both, 2026-11-26). Slow: blocked loads after the background script went idle (Firefox unloads its event page after ~30 s; Chromium keeps its worker while Playwright is attached, so it is stopped after 30 s idle) | `blocks`, `slow` |
| Allow → working page | about 1.2 s with the fake edge's 1 s `retry_after_s` (harness timing); the second attempt after one stale answer. Slow, with the edge's TTL and `retry_after_s` (block time + max(60 s, TTL + 5 s) − now) and no faked stale answer: after a negative answer (TTL 10 s or 90 s) the reload at `retry_after_s` works on both; after a custom_ip sinkhole's address (TTL 10 s or 90 s) both browsers' reload still gets the cached address and the next load works (Chromium's own reload of its error page about 1 s later; the extension's attempt 2 s later on Firefox). The 5 s past the TTL matter for long TTLs: a reload right at the TTL found Firefox's entry unexpired, and Firefox then served the expired entry to the second attempt too while refreshing it, so the page stayed on its error page (#15) | `blocks`, `slow` |
| Install and update | Brave: unpacked from a folder in Developer mode with its fixed ID, folder contents replaced, Reload; Firefox: a temporary add-on with its gecko ID, a newer build installed over it; settings and access kept | `install` |

How each browser gets the extension: Chromium loads the unpacked build (`--load-extension`) into a persistent profile with Developer mode on, and is driven by Playwright; it trusts the test CA by key (`--ignore-certificate-errors-spki-list`), and since a headless browser can't answer permission prompts, the tests first add the host in chrome://extensions site access, so `permissions.request` grants at once. Firefox gets a temporary add-on through WebDriver BiDi (`webExtension.install`); Playwright's Juggler leaves `moz-extension:` pages alone, so the tests drive them through BiDi with trusted input, with `extensions.webextOptionalPermissionPrompts` off and the test CA imported into the certificate store.

`details.error` seen (Chromium 159.0.8154.6, Firefox 159.0; Firefox page loads give the nsresult as `Error code <n>`):

| Block | Chromium | Firefox |
|---|---|---|
| nxdomain, nodata, refused | `net::ERR_NAME_NOT_RESOLVED` | `NS_ERROR_UNKNOWN_HOST` |
| null_ip (nothing listening locally) | `net::ERR_CONNECTION_REFUSED` | `NS_ERROR_CONNECTION_REFUSED` |
| custom_ip that resets after accepting | `net::ERR_CONNECTION_RESET` or `net::ERR_SOCKET_NOT_CONNECTED` | `NS_ERROR_NET_RESET` |
| custom_ip that closes without a reply | `net::ERR_EMPTY_RESPONSE` or `net::ERR_SOCKET_NOT_CONNECTED` | `NS_ERROR_NET_RESET` |
| custom_ip TLS failures | `net::ERR_SSL_VERSION_OR_CIPHER_MISMATCH`, `net::ERR_CERT_AUTHORITY_INVALID` | security-module codes; in webRequest the localized message ("Peer’s Certificate issuer is not recognized."; English Firefox only) |
| custom_ip or IP literal that drops connections | `net::ERR_CONNECTION_TIMED_OUT` (after about 2 minutes, so only with `PICKET_BROWSER_SLOW=1`) | `NS_ERROR_NET_TIMEOUT` |
| IP literal: firewall reject | `net::ERR_CONNECTION_REFUSED` | `NS_ERROR_CONNECTION_REFUSED` |
| IP literal: allow ends mid-load | reset, retried by the browser, refused: `net::ERR_CONNECTION_REFUSED` | `NS_ERROR_CONNECTION_REFUSED` |

Not covered by that run (checked by hand below): Brave's own builds and Firefox ESR or Developer Edition; the native permission prompts; the unsigned `.xpi` install (Playwright's Firefox requires signed add-ons, like release Firefox); the toolbar popup itself (the popup page opens in a background tab next to the page, so it reads that tab as the active one); a wrong-name certificate on Chromium (its trust by key lifts every certificate error of a chain holding the test CA); HTTPS upgrades in Chromium (Playwright turns them off).

### Checked by hand in real browsers

On 2026-11-28 (issue #43) the packaged builds (`npm run package`, version 0.1.0) went through the checklist below in **Brave 1.100.59 (Chromium 158.0.8127.92)** and **Firefox ESR 153.8.0esr**, on Linux (Ubuntu 24.04, X11), each started by hand with its debugging port on (`--remote-debugging-port`), with a fresh profile, as a non-root user. Every click, including the native permission prompts, the file pickers and the toolbar icon, was a real X input event on the browser's own UI, and the results were read from screenshots, from the edge's request log and, on Brave, from the extension's storage over CDP. The edge was the fake edge of the Playwright harness (DoH and the bypass API over HTTPS), kept running by `test/browser/manual-env.spec.ts`:

```sh
PICKET_MANUAL_ENV=/tmp/env.json npx playwright test manual-env --project=chromium
```

It writes the edge's URLs, the test CA and the sites to the file. Each browser trusted the test CA as a user trusts the LAN CA root (Brave: the NSS database; Firefox: the profile's Authorities), used the edge as its only resolver (Brave: secure DNS with a custom provider; Firefox: TRR mode 3), and the edge gave DNS allows its real `retry_after_s` (blocked answers live 10 s).

| Check | Brave | Firefox ESR |
|---|---|---|
| Install | Load unpacked from the unzipped `.zip` in Developer mode; fixed ID `aagdcikeegoglnhilmlaonmjnmlckdgk` | `xpinstall.signatures.required` false, then *Install Add-on From File…*: the unverified-extension prompt, then installed; options page opened on install |
| *Save and test*: the native host-permission prompt | shown for the edge's host; Deny gives "Access to the edge was not granted…", Allow gives "Connected." | the same |
| Blocked top-level page | block page with name, bundle and block ID; *Go back* returns to the page before; the 15 min allow reloaded the page about 57 s later (the edge's `retry_after_s`) and it loaded | the same, about 36 s; after the allow, Back goes to the page before and Forward to the loaded page: the block page left the history (`loadReplace`) |
| Detection: the native all-sites prompt | shown; the options page then says to restart Brave | shown; on at once |
| Real toolbar popup on a page with blocked sub-resources | before the restart: the restart hint (but see below); after it: both blocked hosts (DNS and firewall) with the badge | without a restart: the blocked host with the badge |
| *Allow*, *Reload page*, *End now* from the toolbar popup | the allow for both hosts, *Reload page* once the countdown ended (the badge cleared), *End now* removed the allow at the edge | the same |
| Update in place | folder contents replaced (version 0.1.1), *Reload*: settings, the edge's access and `<all_urls>` kept, detection still working | 0.1.1 `.xpi` installed over 0.1.0: settings and detection kept, same internal UUID |
| custom_ip with a certificate for another name, an untrusted certificate, null_ip | block page for each (with the CA trusted as a root, not by key) | not repeated (Playwright covers them) |

Brave's default HTTPS upgrade setting didn't get in the way: the `http://` sites loaded, and blocked loads got the block page.

Found: real Brave delivered `webRequest` events as soon as detection was granted. Before any restart, the extension had already recorded both blocked hosts of the page and set the badge to 2, but the popup showed the restart hint instead of the list, because the options page assumes every Chromium needs a restart (`detectionNeedsRestart`). Playwright's Chrome for Testing 159, which loads the extension with `--load-extension`, does need the restart (the `popup` spec). #61 tracks it.

Not checked by hand: a signed `.xpi`, Firefox Developer Edition or Nightly, Brave Shields set to aggressive, macOS and Windows, and a real Picket edge and core (the fake edge answers as the edge does, see above).

