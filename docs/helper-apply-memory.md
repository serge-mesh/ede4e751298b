# Helper apply memory investigation (#86)

The request-lifetime gap can exceed the 64 MiB budget **under an injected engine stall**,
through the real Unix socket and its four edge connection slots. Both malformed inputs and
supported valid inputs can accumulate. This experiment does not reproduce a production
incident, a remote exploit, or a kernel/cgroup OOM. The interface remains restricted to the
edge UID and root.

The fix streams validation and normalisation during socket decoding and admits at most one
edge apply and one administrator apply across decoding, queueing and execution. It leaves
the wire format, supported configuration limits, connection caps, engine queue capacity and
`MemoryMax=64M` unchanged.

## Method and reproduction

Measured on 2026-11-28, x86_64 Linux, Rust 1.100.0, release profile, system allocator with
`MALLOC_ARENA_MAX=2` (the service setting). The baseline is main at
`9a4eab3fa058d045fbea85677f7039eaae9e4546`. Raw observations are in
[helper-apply-memory-results.json](helper-apply-memory-results.json).
The hardened helper was revalidated after rebasing onto main at
`b2697fac22632034b913a514d51481102186b083`, including its newer UniFi local-destination reporting.

The `apply-memory` example runs the real `Server`, length-delimited codec, two Tokio workers,
four-blocking-thread limit, fast worker, 16-slot engine queue and `Engine` with `FakeBackend`.
The engine starts normally, then a gate suspends it before dequeueing until explicitly
released. This is deliberately stronger than the fake backend's bounded 20-second restore
wait. It tests admission during a stall; it does not establish how a production engine would
reach that stall. After release the real engine validates/applies the queued work, persists
rules and shuts down, so the RSS peak also includes engine working allocations.

The Python driver is a separate process. Its generated JSON, client buffers and thread pool
are excluded from helper RSS. Four connections authenticate as the probe's edge UID; requests
are serialised on each connection and a new request is sent only after its previous response.
Administrator-mode runs instead map the probe UID to `admin_uid`, enforcing the real two-slot
administrator cap. Simultaneous distinct edge/admin dispatch and reserved admission are
covered by unit tests, rather than by impersonating another OS UID in this unprivileged probe.

Each experiment uses an isolated child, a 512 MiB address-space ceiling, an external 128 MiB
RSS watchdog and a wall-time watchdog. Decode subprocesses have a 15-second deadline. Production
timing runs use the actual 120-second response timeout and two waves, keeping the injected
stall below the 300-second engine watchdog threshold. Short runs use a 200 ms response timeout
to exercise the same ownership transitions. No live gateway or firewall is stressed.

Build before and after in **separate target directories**. The example is compatible with
both revisions; only its diagnostic manifest/dev-dependency and source are copied to baseline:

```sh
mkdir -p work
git worktree add --detach work/issue-86-before 9a4eab3fa058d045fbea85677f7039eaae9e4546
mkdir -p work/issue-86-before/apps/picket-edge-helper/examples
cp apps/picket-edge-helper/Cargo.toml work/issue-86-before/apps/picket-edge-helper/Cargo.toml
cp apps/picket-edge-helper/examples/apply-memory.rs work/issue-86-before/apps/picket-edge-helper/examples/apply-memory.rs
cp Cargo.lock work/issue-86-before/Cargo.lock
CARGO_TARGET_DIR="$PWD/work/before-target" cargo build --release \
  --manifest-path work/issue-86-before/Cargo.toml -p picket-edge-helper \
  --features testkit --example apply-memory --locked
CARGO_TARGET_DIR="$PWD/work/after-target" cargo build --release \
  -p picket-edge-helper --features testkit --example apply-memory --locked

python3 scripts/measure-helper-apply.py work/before-target/release/examples/apply-memory \
  --expect baseline --queue valid-duplicates --timeout-ms 120000 --rounds 2
python3 scripts/measure-helper-apply.py work/after-target/release/examples/apply-memory \
  --expect hardened --queue valid-duplicates --timeout-ms 120000 --rounds 2
```

Repeat with `--queue invalid-empty --reconnect --rounds 2`, or
`--queue valid-unique --background-mib 18 --rounds 2` (leave out `--timeout-ms` for short runs).
`--role admin` exercises the administrator cap. Every invocation measures all decode fixtures
in fresh subprocesses before the socket run. It records a binary SHA-256, and `--expect`
checks the executable's decoder behaviour to catch an accidentally reused baseline binary.

## Decode allocations and valid workloads

Requested heap bytes immediately after decoding, excluding the already-resident wire buffer:

| Input | Wire bytes | Before live bytes | After live bytes | After result |
|---|---:|---:|---:|---|
| Small legitimate apply | 102 | 340 | 205 | accepted |
| 209,572 valid duplicate `::` addresses across static/exempt | 1,047,914 | 6,710,704 | 188 | accepted; two normalised entries |
| 65,536 static and 51,900 exempt distinct IPv6 addresses | 1,048,242 | 3,841,712 | 2,114,000 | accepted; all 117,436 members retained |
| 349,511 empty CIDR strings | 1,048,576 | 12,583,016 | 55 | `invalid` before queueing |
| Oversized escaped interface name | 1,048,439 | 174,962 | 95 | `invalid` before queueing |

For empty strings, the old decoder grew the string vector's capacity to 524,288 (12 MiB)
although every entry was already invalid and the raw collection limit was exceeded. The new
decoder allocates 280 bytes cumulatively before rejecting its first element. For valid
duplicates, cumulative decode allocations fall from 6,710,717 to 633 bytes. The dense unique
case allocates 6,609,669 bytes cumulatively during streaming validation, versus 3,841,725 for
the old *unvalidated* decode; its final live storage is smaller, and validation no longer
leaves a second string representation queued for the engine. Cumulative allocation traffic
is not peak live memory.

Escaped strings still need serde_json's scratch buffer (262,354 cumulative bytes in the
escaped-name case). It is bounded by the wire limit and discarded on rejection; the helper
does not copy the oversized name into an owned interface string. Unknown fields, absent or
null `data`, trimmed CIDRs, `/0` expansion, duplicate normalisation, interface modes and the
existing 64-interface / 131,072-raw-entry / 65,536-per-family limits retain their semantics.

## Reachability, peaks and headroom

The queue capacity is not the concurrency assumption. With a stopped engine and four edge
connections, wave one admits four requests. At 120 seconds their response receivers time out
but their commands remain in the queue. The same four connections can then submit wave two:
**eight payloads** are live at about 120 seconds, before the 300-second stall threshold.
Reconnections reproduce the same retention; a disconnect does not cancel engine work.

Across both roles there can be six connection tasks, each retaining a wire body of at most
1 MiB plus codec capacity while awaiting a response. Responses are also limited to 1 MiB,
with a transient encoding copy and write timeout. Before this change, one executing command
and the 16-slot queue bound engine-owned payload *count*, independently of those wire buffers
and the two transient decode permits; only eight queued payloads were needed in the measured
four-connection run. After this change, two apply permits bound decoding/queued/executing
payloads together, with one retained desired state and one engine thread's working sets.
At most two apply decoders can build their bounded temporary network sets concurrently.

RSS peaks below include baseline runtime memory and, where specified, a resident 18 MiB
budget charge for the two largest retained dump copies (9 MiB each). That charge is touched
anonymous storage, not a claim to have run the actual concurrent dump-building workflow.

| Socket experiment | Before peak MiB | After peak MiB | After RSS headroom below 64 MiB |
|---|---:|---:|---:|
| Valid duplicates; actual 120 s timeout | 96.63 | 6.04 | 57.96 MiB |
| Empty strings; reconnect; 200 ms timeout | 71.82 | 6.67 | 57.33 MiB |
| Valid duplicates + 18 MiB background; 200 ms | 114.62 | 23.95 | 40.05 MiB |
| Dense unique members + 18 MiB background; 200 ms | 95.40 | 43.96 | 20.04 MiB |

The default-timeout runs follow the same ownership transitions as the accelerated runs;
the baseline exceeds 64 MiB without filling all 16 queue slots. Peaks are observed process
RSS, polled externally every 10 ms alongside the recorded in-process RSS/high-water samples.

The small-request hardened run peaks at 3.21 MiB; administrator duplicate runs peak at
5.05 MiB across three waves. Invalid requests now return `invalid` immediately. For valid
requests during the stall, one request holds the role's admission and eventually gets the
response timeout; further applies return `busy` without decoding their payload. Once the
engine releases the command, a later request can be admitted.

These figures distinguish ownership from retention. For example, the baseline duplicate run
with background storage holds about 69 MiB of requested live heap after the second wave's
timeouts. After the queue drains it drops to about 18 MiB, while RSS remains around 76 MiB:
freed allocations can remain resident in glibc. The unique-member probe also retains fake
kernel members inside `FakeBackend`; a real kernel keeps these outside helper process RSS.
The peak includes this conservative extra cost.

This host did not provide an independently delegated 64 MiB cgroup. RSS above 64 MiB proves
a process-budget overrun in this experiment, but there was no cgroup OOM test. After-headroom
is the measured RSS difference, not a universal bound on cgroup charges, arbitrary external
iptables-save output, every concurrent background operation, or aarch64 allocator behaviour.
The probe's UniFi local-destination snapshots are empty; the background charge models retained
dump storage, rather than every possible interface's external firewall state.
The admission and collection bounds themselves do not depend on allocator retention or the
number of timeout/reconnect cycles.

## Ownership and regression coverage

Apply admission uses separate, non-waiting edge and administrator permits, taken before
payload decoding regardless of frame size. Fast ensure/delete, status and administrator
disable/enable do not wait for these permits. The edge cannot consume the administrator's
apply reservation.

The command owns the permit through queueing and execution. Parser/semantic rejection,
failed/full/disconnected enqueue, dropped queued commands and unwinding return it by RAII.
A timed-out or cancelled response waiter, or a disconnected peer, does **not** return a
queued command's permit. Engine completion returns admission before sending the response.
Consequently there are at most two admitted apply payloads plus the engine's retained
desired state, rather than a new batch on every timeout. Final per-family network vectors
are exact-sized and hold at most 65,536 entries each; transient sets stop at the first entry
over the limit. The engine consumes validated desired state without decoding/normalising
another string copy.
On this target `IpNet` occupies 18 bytes: even ignoring the tighter wire-size constraint,
the four final network vectors hold at most 4.5 MiB per request, or 13.5 MiB for two admitted
requests plus retained desired state. This counts owned network vectors, not transient trees,
engine working sets, string/interface overhead or total process RSS.

Regression coverage includes allocation budgets for early rejection, valid duplicate-heavy
and full-family inputs, raw and normalised count overflow, interface and redirect limits,
semantic parity with `Desired::from_request`, rejection before enqueue, timeout, task
cancellation, socket disconnect, queue full/disconnected/drop, successful execution, separate
administrator admission, and fast work while both apply slots are occupied. The existing
real-socket held-restore test now checks `busy` while execution holds admission and successful
re-admission after completion. The helper-frame fuzz target checks persisted-form parity
with the newly validated decoded request.

Validation on x86_64: 174 helper tests and 50 edge firewall tests passed; helper Clippy over
all targets (`-D warnings`), rustdoc with warnings denied, rustfmt, typos and the helper fuzz
workspace's locked all-target build passed. Native aarch64 CI remains the platform check;
these memory measurements are from the x86_64 probe described above.
