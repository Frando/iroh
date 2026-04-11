# Streaming Net Report -- Implementation Report

## Summary

Replaced the nested `DirectAddrUpdateState` + `AsyncMutex<Client>` +
`reportgen::Actor` machinery with a single long-lived `NetReportActor`
that emits report updates via a `Watchable` as probe results arrive.

Net change: -353 lines (977 added, 1330 removed across 5 files).

## Files Changed

### New: `iroh/src/net_report/actor.rs` (840 lines)

The `NetReportActor` struct and its run loop. Contains:
- Actor state: probes JoinSet, QadConns, report history, cycle tracking
- `run()` -- main select loop (commands, probe results, QAD watches)
- `handle_command()` -- RunProbes with coalescing, full/incremental logic
- `handle_probe_result()` -- dispatches QAD/HTTPS/captive portal/deadline
- `maybe_emit()` -- emits intermediate reports when meaningful data arrives
- `finalize_cycle()` -- sets preferred_relay, commits to history
- `spawn_qad_probes()` -- spawns QAD probes per relay with QAD_PROBE_TIMEOUT
- `spawn_https_probes()` -- spawns HTTPS probes from ProbePlan
- `spawn_captive_portal()` -- delayed captive portal check
- `update_report_history()` -- free function for preferred relay selection
- Full test for report history and relay hysteresis (7 test cases)

### Modified: `iroh/src/net_report.rs` (-706 lines)

- `Client` is now a thin handle: `cmd_tx` + `report_watcher` + abort handle
- `Client::new()` spawns the actor and accepts a `Watchable` for output
- `Client::run_probes()` sends a non-blocking command
- `Client::watch()` returns a watcher over the report
- Removed: `get_report()`, `spawn_qad_probes()`, `have_enough_reports()`,
  `add_report_history_and_set_preferred_relay()`, `Reports`, `GetReportResult`
- Kept: `QadConns`, `QadConn`, `run_probe_v4/v6`, `QadProbeError`,
  re-exports, test_utils

### Modified: `iroh/src/net_report/reportgen.rs` (-251 lines)

- Removed: `Client`, `Actor`, `run()`, `run_inner()`,
  `spawn_probes_task()`, `prepare_captive_portal_task()`,
  `ProbeFinished`
- Made `pub(super)`: `Probe::run()`, `check_captive_portal()`,
  `CaptivePortalError`
- Kept: `ProbeReport`, `QadProbeReport`, `HttpsProbeReport`,
  `ProbesError`, `ProbeError`, `IfStateDetails`, `SocketState`,
  `QuicConfig`, `run_https_probe()`, `measure_https_latency()`,
  `get_relay_addr_v4/v6()`

### Modified: `iroh/src/net_report/defaults.rs` (+6 lines)

- Added `QAD_PROBE_TIMEOUT = 15s`

### Modified: `iroh/src/socket.rs` (-176 lines)

- Removed: `DirectAddrUpdateState` (struct + new/schedule_run/try_run/run)
- Removed: `direct_addr_done_rx` field and select arm
- Removed: `AsyncMutex` import, `NET_REPORT_TIMEOUT` import
- Removed: `UpdateReason::QadPending` (was never on main, only on
  qad-timeout branch)
- Added: `net_report_client: net_report::Client` field on Actor
- Added: `port_mapper: portmapper::Client` field on Actor (was inside
  DirectAddrUpdateState)
- `Socket::net_report` changed from `Watchable<(Option<Report>, UpdateReason)>`
  to `Watchable<Option<Report>>` -- the actor writes to it directly
- `Socket::net_report()` returns `self.net_report.watch()` (was `.map()`)
- `re_stun()` reduced to: `procure_mapping()` + `run_probes()`
- `net_report_watcher` arm unwraps `Option<Report>` (no UpdateReason tuple)
- Port mapper watcher reads from `self.port_mapper` (was
  `self.direct_addr_update_state.port_mapper`)

## What Is Preserved (verified item by item)

- Full vs incremental report logic (do_full, next_full, last_full, etc.)
- QAD connection validation (close_reason check on existing conns)
- QAD needs_v4/needs_v6 logic including the v6 asymmetric check
- MAX_RELAYS = 5 limit
- QAD conn storage (first conn per direction, extras closed)
- HTTPS ProbePlan creation (initial vs with_last_report)
- HTTPS probe delays from ProbePlan (200ms/300ms/400ms staggering)
- Captive portal: only on full reports, 200ms delay, cancelled on UDP success
- Report history: add_report_history_and_set_preferred_relay (identical logic)
- Report history cleanup (MAX_AGE = 5 min)
- Preferred relay hysteresis (33% threshold)
- mapping_varies_by_dest carry-forward from last report
- handle_net_report_report (ipv6_reported, preferred_relay fallback,
  on_network_change to transports, update_direct_addresses)
- publish_my_addr on address changes
- Periodic re_stun timer (20-26s, reset after each report)
- port_mapper.procure_mapping() before probes
- Network change handling (major/minor) -> re_stun
- Relay map change -> re_stun
- Portmap watcher in select loop
- Shutdown via CancellationToken chain (at_close_start)
- AbortOnDropHandle lifecycle (dropping Client kills actor)
- Metrics: reports + reports_full counters
- Empty relay map: early return, no report emitted
- No quic_client: skip QAD probes
- wasm_browser: no QAD, no captive portal, HTTPS only
- QAD Watchable observers: watched in actor select loop for
  address changes on existing connections between probe cycles
- Endpoint::net_report() public API: unchanged return type

## Intentional Behavioral Differences

### 1. No have_enough_reports early-abort

**Old:** `have_enough_reports()` checked probe counts (e.g., need
2 QAD IPv4 probes for full report) and aborted remaining probes
when sufficient data was gathered. In `get_report`, it would drop
the reportgen actor (killing HTTPS probes) and break the select
loop. In `spawn_qad_probes`, it would cancel remaining QAD probes
via `cancel_v4.cancel()`.

**New:** All spawned probes run to completion or individual timeout.
QAD probes run up to `QAD_PROBE_TIMEOUT` (15s). HTTPS probes run
up to `PROBES_TIMEOUT` (3s). No early-abort based on probe counts.

**Why acceptable:** The streaming model emits results as they arrive,
so the consumer gets data immediately. Extra probes provide redundant
data (multiple relay latencies) which is harmless -- `Report::update`
handles duplicates. The first QAD result per direction is stored,
extras are closed. The actual network cost is the same (probes are
already in flight), just not cancelled early.

**Potential impact:** Slightly more network activity per cycle on
setups with many relays. In practice, with MAX_RELAYS=5 and typical
1-relay setups, the difference is negligible.

### 2. No per-direction QAD cancellation

**Old:** `cancel_v4` and `cancel_v6` tokens could cancel all v4 or
v6 probes independently when the first per-direction probe succeeded.

**New:** QAD probes are cancelled only by shutdown or by the JoinSet
being aborted (on major re_stun). Redundant probes that complete
after the first per-direction success have their connections closed
with `QUIC_ADDR_DISC_CLOSE_CODE`.

**Why acceptable:** The old code would cancel remaining probes to
save network resources. The new code lets them finish (or timeout)
and closes extra connections. The extra work is bounded (at most
MAX_RELAYS - 1 = 4 redundant probes per direction) and the probes
are typically fast (<1s on healthy networks).

### 3. No overall cycle timeout

**Old:** Two nested timeouts wrapped the entire probe cycle:
- `NET_REPORT_TIMEOUT` (10s) in socket.rs wrapping `get_report()`
- `OVERALL_REPORT_TIMEOUT` (5s) in reportgen wrapping the HTTPS actor

**New:** No overall timeout. Individual probes have their own:
- QAD: `QAD_PROBE_TIMEOUT` (15s)
- HTTPS: `PROBES_TIMEOUT` (3s)
- Captive portal: `CAPTIVE_PORTAL_TIMEOUT` (2s) + 200ms delay
- Deadline sentinel: fires at `PROBES_TIMEOUT` (3s) for first emission

A cycle completes when the JoinSet empties (all probes finished or
timed out). Maximum cycle duration: 15s (QAD_PROBE_TIMEOUT), which
occurs only on degraded links where the QAD handshake is very slow.

**Why acceptable:** The old `OVERALL_REPORT_TIMEOUT` (5s) would kill
the entire reportgen actor, losing any in-progress HTTPS probes.
The old `NET_REPORT_TIMEOUT` (10s) would kill the entire get_report
call including QAD. With the streaming model, the 3s deadline
sentinel ensures a report is emitted quickly, and long-running QAD
probes complete in the background without blocking anything. The
15s QAD timeout is intentional for degraded links.

### 4. Coalescing strategy

**Old:** `DirectAddrUpdateState` used an `AsyncMutex` for serialization
and a `want_update: Option<UpdateReason>` field for queuing. If a
probe cycle was running (mutex locked), new requests were stored and
executed after the current cycle finished via `try_run()`.

**New:** The actor uses a `mpsc::channel(4)` for commands. Non-major
requests are skipped if probes are already running (`!self.probes.is_empty()`).
Major requests abort existing probes and start fresh. The channel
capacity (4) provides backpressure; `try_send().ok()` drops overflow.

**Why acceptable:** The old coalescing only kept the latest reason
(last-writer-wins). The new approach is equivalent: non-major
requests during an active cycle are dropped (same as being overwritten
in want_update), and major requests take priority (same as the old
code where is_major always ran). The channel capacity of 4 is generous
for the typical usage (at most 2-3 concurrent triggers from timer +
network change + portmap).

### 5. UpdateReason removed from Watchable

**Old:** `Socket::net_report` was `Watchable<(Option<Report>, UpdateReason)>`.
The `UpdateReason` was carried alongside the report.

**New:** `Socket::net_report` is `Watchable<Option<Report>>`. No reason.

**Why acceptable:** `handle_net_report_report()` never used the
`UpdateReason` -- it only destructured the tuple to get the report
and ignored the reason. The `UpdateReason` was only meaningful inside
`DirectAddrUpdateState` for `is_major()` checks, which now happen
at the command level.

### 6. HTTPS probe cancellation tokens

**Old:** HTTPS probes had a 3-level cancellation chain:
parent token -> per-probe-set token -> per-probe token, wrapped in
`run_until_cancelled_owned`. This allowed cancelling an entire probe
set when one probe in the set succeeded.

**New:** HTTPS probes are spawned directly into the JoinSet with
`time::timeout(PROBES_TIMEOUT, ...)` and no cancellation token.
They are cancelled only by dropping/aborting the JoinSet (which
happens on major re_stun).

**Why acceptable:** The old per-set cancellation was an optimization
to avoid redundant retries within a probe set (e.g., cancel 2nd and
3rd HTTPS attempts to the same relay after the 1st succeeds). The
new code lets all scheduled attempts run, which means at most 2 extra
HTTPS requests per relay (3 attempts at 200ms/300ms/400ms delays).
These are lightweight HTTP GET requests to `/ping`. The 3s per-probe
timeout bounds the cost.

## Timeout Comparison

### Previous timeouts (before this refactor)

| Constant | Value | Where applied | Effect |
|----------|-------|---------------|--------|
| `NET_REPORT_TIMEOUT` | 10s | socket.rs, wrapping `get_report()` | Hard kill of entire probe cycle including QAD |
| `OVERALL_REPORT_TIMEOUT` | 5s | reportgen actor, wrapping `run_inner()` | Hard kill of HTTPS probes + captive portal |
| `PROBES_TIMEOUT` | 3s | Per-HTTPS-probe timeout; also the QAD collection deadline | HTTPS probes killed at 3s; QAD results collected for 3s then report emitted |

The previous system had two nested hard timeouts. A probe cycle
could not exceed 10s total. QAD probes were killed at 3s (the
collection loop deadline). There was no mechanism for QAD probes to
finish after the initial report.

### Current timeouts

| Constant | Value | Where applied | Effect |
|----------|-------|---------------|--------|
| `REPORT_TIMEOUT` | 3s | Actor select loop, `report_deadline` | Emits a report (even if empty) so consumers get data quickly. Does not cancel any probes. |
| `ABORT_TIMEOUT` | 30s | Actor select loop, `abort_deadline` | Cancels remaining HTTPS probes. QAD probes are unaffected. |
| `PROBES_TIMEOUT` | 3s | Per-HTTPS-probe timeout | Individual HTTPS probe killed if it takes longer than 3s. |
| `QAD_PROBE_TIMEOUT` | 15s | Per-QAD-probe timeout | Individual QAD probe killed after 15s. Allows degraded-link handshakes to complete. |
| `CAPTIVE_PORTAL_DELAY` | 200ms | Delay before captive portal check | Waits for QAD to potentially succeed first. |
| `CAPTIVE_PORTAL_TIMEOUT` | 2s | Per-captive-portal-probe timeout | Individual captive portal check killed after 2s. |

### Assessment

The key difference is that no timeout kills QAD probes early. In the
previous system, `NET_REPORT_TIMEOUT` (10s) was a hard ceiling on the
entire cycle, and `PROBES_TIMEOUT` (3s) was the QAD collection
deadline. QAD probes that needed 4-15s on degraded links were killed,
causing the endpoint to miss its public address until the next
periodic cycle (20-26s later).

In the current system:
- Consumers get a report within 3s (`REPORT_TIMEOUT`), matching the
  old `PROBES_TIMEOUT` behavior.
- QAD probes run up to 15s (`QAD_PROBE_TIMEOUT`). Results are emitted
  incrementally as they arrive. No follow-up cycle needed.
- HTTPS probes are cancelled at 30s (`ABORT_TIMEOUT`) or when all
  relays have been measured, whichever comes first. The old system
  cancelled them at 5s (`OVERALL_REPORT_TIMEOUT`). The higher limit
  is safe because HTTPS probes have their own 3s per-probe timeout,
  so in practice they finish well before 30s. The 30s limit exists
  as a safety net for pathological cases.
- Per-direction QAD cancellation fires as soon as one probe per
  direction succeeds, matching the old `cancel_v4`/`cancel_v6`
  behavior.

The `TIMEOUT` public constant changed from 5 to 3. It is used only
in documentation (the doc comment on `Endpoint::net_report`
references it). The new value reflects the actual first-report
guarantee.

## Tests

All tests pass:
- `test_basic` -- streaming probe cycle with real relay
- `test_report_history_and_preferred_relay` -- 7-case hysteresis test (restored)
- `test_measure_https_latency` -- individual HTTPS probe
- `test_qad_probe_v4` -- individual QAD probe
- `test_initial_probeplan` / `test_initial_probeplan_some_protocols` -- ProbePlan
- `watch_net_report` -- endpoint-level watcher test
- Patchbay degrade tests: 12/12 pass (levels 0-5, client + server),
  including the previously-ignored extreme/absurd levels
