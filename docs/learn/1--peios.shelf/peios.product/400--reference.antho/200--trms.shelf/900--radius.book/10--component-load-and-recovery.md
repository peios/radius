---
title: Component Load and Recovery
description: Measuring synthetic admission and accounting loads, checking storage failures, and interpreting incomplete fuzzing evidence.
---

`radius-qualify` is a developer tool. It uses temporary synthetic identities,
an ephemeral certificate, and exclusively created scratch directories. It
opens no external sockets, reads no deployed configuration, and contacts no
native authentication service. It does not build a package, kernel, or image.

## Build and run

From the repository root:

```sh
pekit build --strict -j 2 qualify
pekit test --strict -j 2 qualification clippy
```

Use the executable path printed by the build. The Cargo equivalent is
`cargo build --locked -p radius-qualification`; the executable is
`target/debug/radius-qualify`. Use an optimized executable for measurements.
Do not compare debug and optimized throughput.

```sh
radius-qualify auth --requests 4096 --concurrency 32
radius-qualify accounting --requests 2048 --concurrency 256 --batch 128 --scratch-parent /path/to/scratch
radius-qualify failures --scratch-parent /path/to/scratch
```

The scratch parent must already exist. Each invocation creates a new private
subdirectory and removes it on completion. The failure fixture creates and
terminates its own child processes; it never opens an existing ledger.
`--help` lists workload options. Requests, peers, queue depth, batch size,
and completion deadlines are bounded. Unexpected rejection fails a normal
load; `--allow-overload` allows intentional rejection while still checking
request conservation and recovery.

To collect the nine standard load cases and machine context:

```sh
python3 tools/capacity-qualification.py --binary /path/to/optimized/radius-qualify --out /path/to/new-results --scratch-parent /path/to/scratch
```

The output directory must be new. The runner records the executable hash,
CPU, affinity, starting load, filesystem type, commands, exit statuses, and
JSON results. Each case has a controller deadline. Keep the report with the
source revision and build settings used to produce that executable.

## What the workloads measure

Authentication runs full TTLS/PAP exchanges through the production
coordinator and TLS implementation. Credential verification and authorization
use a fixed synthetic backend. The measurement excludes native authd,
password hashing cost, UDP transport, APs, and client radio behavior. After
the load drains, a fresh conversation must succeed on the same coordinator.

Accounting submits unique session Start records to the real asynchronous
owner and SQLite WAL/FULL ledger. Latency runs from submission to receipt
collection and includes batching delay. Every accepted receipt must map to
a unique retained observation after stopping and reopening the owner. This
is not a mixed Start/Interim/Stop benchmark or a measurement of native packet
ingestion. Both workloads use a bounded window of outstanding work rather
than a fixed external arrival rate.

`max_pending` counts outstanding synthetic peers for authentication and
submitted receipts awaiting collection for accounting. It does not measure
internal queue occupancy. Peak RSS is the process high-water mark from Linux,
including fixtures and recovery checks. Successful completions determine
throughput and latency percentiles; rejections are reported separately.

## Observed measurements

On 19 November 2026, the optimized hermetic build ran on a Ryzen 5 7600X
host with 12 logical CPUs available. The host was shared with other work;
starting load averages were approximately 3.7, 7.0, and 4.2. The scratch
filesystem reported `ext2/ext3`. These single-run observations establish
neither a production ceiling nor a recommended deployment limit.

| Workload | Window / batch | Completed per second | p99 latency |
| --- | --- | --- | --- |
| Synthetic TTLS/PAP, serial | 1 / none | 3,990 | 0.29 ms |
| Synthetic TTLS/PAP | 32 / none | 4,112 | 8.05 ms |
| Synthetic TTLS/PAP | 128 / none | 4,088 | 31.66 ms |
| Accounting Starts | 64 / 16 | 4,908 | 25.68 ms |
| Accounting Starts | 256 / 128 | 13,180 | 21.65 ms |
| Accounting Starts | 1,024 / 512 | 17,323 | 59.30 ms |

The timer-driven case used a 64-record window below the 512-record batch
threshold. Its one-second flush timer produced about 1.02-second p99
latency, as expected. Do not infer poor saturated throughput from that case.
Peak process RSS across all nine cases remained below 13 MiB.

The authentication overload case completed 4 and rejected 4,092 requests
with a four-attempt limit, then accepted a new conversation after draining.
The accounting overload case committed 32 and rejected 4,064 submissions
with a four-record queue; all accepted receipts survived reopening. Queue
capacity limits queued work, not all work already committed or in progress.
These rejection counts depend on the synthetic arrival pattern and timing.

## Failure regressions

The storage fixture checks 20 cases: eight write-error points, two sync-error
points, eight full-storage points, termination during a sync, and termination
after commit before acknowledgement. It checks atomic retention, idempotent
retry, SQLite integrity, and foreign-key integrity after reopening. Faults
are installed only inside dedicated developer child processes. A fault
family must reach an injection point for its run to pass.

Other deterministic regressions check bounded authentication tables,
accounting queue saturation, recovery when an authority check becomes
available, and failed or stalled required services. The production
coordinator is exercised with unavailable event delivery: a successful
authority and admission result can still succeed, while failed required
authentication or accounting cannot produce an acceptance.

These checks passed on the host. The service failures use synthetic backend
contracts. They do not establish native service restart behavior, physical
power-loss durability, device-specific disconnect behavior, or a long soak.
See [Qualification](~peios/reference/radius/qualification) for independent
supplicant and disposable native gates.

## Instrumented campaign status

The optional `fuzz/` workspace contains five bounded target adapters for
packets, engine sequences, coordinator sequences, ledger replay, and control
records. Shared entry points also support deterministic stable-Rust replay.
`tools/fuzz-qualification.py` records seeds, commands, source and executable
hashes, execution counts, coverage, logs, and artifacts in a new directory.

The first five AddressSanitizer campaign attempts all aborted during startup
on an SQLite `aiOff` global ODR diagnostic. No execution or coverage counts
were obtained, and no RADIUS failure artifact was produced. Compilation and
deterministic seed checks do not establish an instrumented campaign pass.
The instrumentation issue remains unresolved; the campaign gate is incomplete.
Do not disable sanitizer diagnostics to count this gate as passing.

The adapters have further limits: successful encrypted exchanges in the
coordinator fixture use TTLS/PAP; PEAP coverage here stops at method
selection. Control sequences exercise durable records rather than a real AP
transport. The existing independent and native protocol gates remain
necessary. None of these checks is a complete security audit.
