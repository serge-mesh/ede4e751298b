# Clocks, initialization and the LAN CA

This page is the maintained statement of picket-core's clock rule, its bootstrap exceptions and
the LAN CA rotation rule. Source comments that cite "README §2 Clocks" or core.md §11 refer to
the rules written here.

## The clock rule

Anything that writes a wall-clock time core can't take back waits until the clock is
synchronised: systemd-timesyncd's flag, or `timedatectl`'s `NTPSynchronized`
(`apps/picket-core/src/clock.rs`). That covers dating certificates (edge listener CSRs, rotated
LAN CA roots), retention's wall-clock deletes, expiry sweeps and the other jobs that check
`clock.synced()`. Until then they are refused or deferred and change nothing: a CSR gets `503`
with code `clock` and the edge keeps serving the certificate it has; a rotation (`lanca.zones`
change) gets `503` and no root is staged.

## Initialization doesn't need the clock

`picket-core init` must work before the clock is synchronised, offline included, so nothing in it
waits for network time. `picket-core-init.service` is ordered `After=time-set.target`, which only
helps the local clock be roughly right when the platform provides it; it isn't the correctness
mechanism, and the unit doesn't use `time-sync.target`, which can delay startup until a time
server answers.

Two things are created regardless of the clock. They are the only exceptions to the rule, and
they apply on every path that creates or recovers them, not only on the first start:

### The bootstrap root

`init` creates the LAN CA's first root (`lanca/ca.{key,crt}`) with dates that don't come from
the clock (`lanca::RootDates::Bootstrap`):

- `notBefore` is 2026-01-01T00:00:00Z, earlier than any release, so a client with a correct clock
  never sees the root as not yet valid;
- `notAfter` is 9999-12-31T23:59:59Z, RFC 5280's value for "no well-defined expiration"
  (§4.1.2.5).

A clock far ahead or far behind at `init` therefore leaves no trace in the root. Synchronising
the clock later never regenerates or re-dates it: its key and fingerprint stay, since it may
already be trusted by devices.

Lifetime: the root never ends by date. It is replaced only by a rotation, today a change of
`lanca.zones` (an explicit same-zone replacement is a separate follow-up). Trust-anchor dates are
handled differently by different TLS stacks (rustls doesn't keep them at all: a trust anchor is a
subject, a public key and name constraints), so what matters for interoperability is that the
root's dates are fixed and plausible, not that they bound its use. Leaf certificates, which every
client does date-check, keep short lifetimes (397 days) and are dated by the clock that signs
them.

Rotated roots are dated by the synchronised clock: from a day before the rotation, for 20 years.

### The bootstrap web certificate

With managed web TLS (`web.tls: managed`, the default), core needs a certificate for its web port
before it can serve anything. When there is no usable `lanca/web.{crt,key}` pair (the first
start, or a pair that is missing, mismatched or doesn't load), core issues one from the LAN CA
even if the clock isn't synchronised, and dates it with the clock it has.

Before synchronisation only the certificate's names decide whether it is kept, so a wrong clock
never replaces a good certificate with a badly dated one. Once the clock is synchronised, the
minute refresh re-issues a certificate that starts in the future, has less than 30 days left
(including one that has already ended), or wasn't signed by the current root.

## LAN CA rotation

A change of `lanca.zones` makes a new root (`apps/picket-core/src/lanca/rotation.rs`). The rollout
is deliberately conservative:

- The previous root stays trusted by core until **every assigned managed listener**, DoT and DoH,
  reports a certificate from the current root.
- A listener that hasn't reported counts as pending. While a previous root is retained, pending
  listeners block the next rotation with `409`, naming the blocking edges and listeners and
  whether each edge is offline.
- With no previous root retained, a listener with no report doesn't by itself block the first
  rotation.
- Unassigning the listener or deleting the edge clears its participation: that is the
  operational way out when an edge will never come back.
- Core keeps at most the current root and one previous root.
- A rotation needs a synchronised clock (above), and an interrupted one is recovered at start.
