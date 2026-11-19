---
title: Accounting
description: Durable network session reports, protected history, principal allowances, and Disconnect outcomes.
---

Accounting records what a network access server (NAS) reports about access:
session starts, updates, ends, and cumulative traffic counters. The reports
contain identities and device metadata. They contain no browsing history or
packet payloads. Accounting is independent of credential verification.

## Storage and acknowledgments

radiusd authenticates the actual sender against the most specific configured
client prefix and its shared secret. An asserted NAS name never establishes
transport trust. Disabled specific prefixes mask broader enabled clients.
The accounting listener uses its own configuration path, independent of
authentication certificates and private keys.

One owner writes a private SQLite ledger at
`/var/state/radius/accounting/ledger.db`. WAL mode with FULL synchronization
commits observations, retry receipts, session interpretation, and quota
evidence together. Accounting-Response follows a successful commit. Failure,
queue pressure, and uncertain outcomes produce no success acknowledgment.
The sender can retry after a lost reply without adding the usage twice.

Batches wait at most their configured intentional delay from the oldest
queued report. Count and byte limits also flush batches. A management or
admission operation flushes pending reports first. These bounds do not promise
a total response latency during slow storage. The database owner never blocks
the authentication packet loop while it performs disk operations.

SQLite limits database pages within a transaction. Free pages remain reusable
after retention. Lowering the limit does not shrink an existing file. The
reported storage size includes the allocated database and WAL; WAL, shared
memory, and filesystem overhead require additional disk space. Automatic
checkpoints bound steady-state WAL growth, but one transaction can exceed
that checkpoint threshold. Keep filesystem headroom outside the database cap.

Corruption, foreign databases, unsupported schema versions, links, and
untrusted file descriptors do not cause automatic replacement with an empty
ledger. A separate file lock prevents two owners. Stop radiusd before copying
the database, WAL, and shared-memory files as a consistent backup set.
Rebuild reinterprets retained evidence; it cannot recover deleted evidence.

Ledger format 4 retains complete issued and requested access settings and
their exact equipment encodings. Formats 1–3 upgrade in place. Existing
evidence and unknown legacy fields are preserved. Earlier binaries refuse
format 4; keep a stopped full-state backup and prior runtime for rollback.

## Session interpretation

Start, Interim-Update, and Stop form ordinary sessions. Accounting-On and
Accounting-Off define whole-NAS boundaries; subsystem equivalents use
Called-Station-Id. Reliable event times prevent delayed restart notices from
closing newer sessions. Missing or implausible times remain uncertain.

Tunnel and tunnel-link reports retain their own occurrences and identifiers.
They do not close or charge the parent session again. Unknown status values
remain observations without invented lifecycle effects. IPv6 and opaque
attributes remain bounded report data. A versioned declarative accounting
profile can normalize vendor attributes; profiles execute no code.

Successful local authentication creates an opaque Class reference for the
verified security identifier (SID), membership snapshot, client, policy, and
optional station. The reference and any concurrent reservation commit before
Access-Accept. Retransmissions reuse the exact signed reply and reference.
Class is a correlation receipt, not a bearer credential or logon authority.

Reports without a recognized Class can still form a session. Their asserted
username does not become a verified SID. Ambiguous matches remain unresolved.
Reauthentication can replace the membership snapshot for subsequent evidence;
earlier intervals retain their original attribution. Byte deltas across that
boundary remain approximate because the NAS supplies cumulative snapshots.

Counters retain the full unsigned 64-bit range. Regressions do not refund or
double-charge usage. Missing high words, late reports, inferred ends, and
uncertain boundaries carry warnings. Stale sessions continue to consume
concurrency until Stop, a reliable lifecycle boundary, or configured inferred
expiration. An inferred end is not a factual Stop.

## Permissions and privacy

The local accounting socket checks the actual caller token through the kernel.
Registry management permissions, accounting query permissions, and network
Connect permissions are separate. The default accounting security descriptor
(SD) permits SYSTEM and Administrators. A policy can provide its own
accounting SD; an absent policy falls back to the global descriptor.

Accounting rights are Read (`0x1`), Personal (`0x2`), Usage (`0x4`),
Disconnect
(`0x8`), Correct (`0x10`), and Raw (`0x20`). Personal permits identity fields;
Usage permits counters. Session filtering and pagination apply caller scope
before selecting a page. A principal filter needs Personal authority over
its requested scope. Delegated usage queries do not expose global allowances.

Optional self-service compares the real caller SID with verified session
identity. It provides the caller's rows, history, and usage, without granting
Disconnect, Correct, Raw, or direct database access. A reported username alone
cannot satisfy self-service. Linked views require their separate toggle and
preserve individual session occurrences.

`AccountingRetainNames` and `AccountingRetainAttributes` control future
ingest.
They do not retroactively erase retained data. Raw packet capture is off by
default, has separate age and byte limits, and requires both retention
controls. Authentication proofs, passwords, and known key attributes are
rejected before recording. Treat unknown vendor attributes as private data.

Observation retention removes detailed reports through checkpoints. Summary
retention removes ended personal session views. Quota evidence is separate:
byte rollups and principal intervals remain available for lifetime limits.
Personal history expiry does not reset allowances or erase all SID evidence.
The detail interval samples Interim history views; it does not skip live
counter processing or deduplication evidence in the retained journal.

## Allowances and enforcement

Allowances attach to user or group SIDs, optionally scoped to a policy.
Every applicable allowance consumes the same attributable usage independently.
Allowances never add together. Duplicate membership does not charge a group
twice. A zero maximum denies the corresponding resource.

Dimensions are received bytes, sent bytes, total bytes, total session time,
connected time, and concurrent sessions. Time amounts use milliseconds.
Total session time sums intervals. Connected time unions overlapping
intervals across applicable sessions. Five simultaneous one-hour sessions
consume five session-hours and one connected-hour. Both limits can coexist.

Periods use UTC days, Monday-based weeks, months, or lifetime. Concurrent
limits use lifetime because slots do not reset on a calendar boundary.
Cumulative byte deltas are assigned to the update's event period. A delta
crossing a reset boundary cannot be divided precisely without another report.
Use the uncertainty flags when interpreting those totals.

Admissions reserve concurrent capacity atomically before Access-Accept.
Reauthentication with the same verified account, configured client, policy,
and nonempty station identity reuses one existing active slot. Its reservation
does not charge principals already represented by that session twice. New
group memberships still reserve their own capacity. Without matching station
context, admission cannot assume it is an existing connection.
Reservations expire if no corresponding session follows. Applicable limits
can shorten Session-Timeout and request Disconnect for ongoing sessions.
Reports arrive late and devices can reject Disconnect, so enforcement is
approximate rather than an exact byte cap.

`OnAccountingUnavailable=deny-new` refuses required or limited admissions
during an outage. `allow-new` bypasses that guarantee and increments the
bypass counter. Unconstrained policies without required accounting can
continue ordinary authentication. No mode acknowledges an unrecorded report
or fabricates a durable Class reference. Storage failure does not disconnect
every existing client.

Disconnect records persist selectors, attempts, and outcomes. Requests target
the recorded source address through its configured client and shared secret.
Attempts commit before transmission. ACK, NAK, and timeout outcomes remain
separate from session state. An ACK does not manufacture Stop. General
Change-of-Authorization is outside this implementation.

Repeated requests for an occurrence with a pending, sent, or uncertain
Disconnect return the existing command. The current interface has no explicit
retry command for an uncertain result; it does not silently reset its
attempts.

## Administration and diagnostics

Run `radius accounting init` as an administrator to provision the private
directory. Existing directories and ledger files must already have trusted
owners and private descriptors. SQLite also needs ReadAttributes on its path
prefixes. On a restrictive `/var/state`, grant the service only mask `0x80`
without inheritance; do not grant directory listing or broad data access.
Use the normal port reservation descriptor for the accounting UDP port.

Network packet admission is separate from port binding permission. An
enforcing Flow policy needs to admit incoming accounting traffic to the
configured UDP listener. Disconnect also needs permission for a new outbound
UDP flow from that listener to the configured client's Disconnect port,
conventionally 3799. Scope that exception to the intended server and AP
addresses. Replies to an admitted flow follow its existing Flow judgment.
Enable the NAS's dynamic authorization service separately; a listener or
firewall rule does not enable it on the NAS.

For an existing schema 2 development deployment, provision the `Quotas` and
`AccountingProfiles` collection keys under `Machine\Software\Radius` before
creating their first records, preserving the parent's management permissions.
Fresh `radius config init` creates all collections. This is a one-off
development upgrade, not an automatic schema migration.

Turn on `AccountingEnabled` and set `AccountingListen` under
`Machine\Software\Radius\Settings`. Client records share the existing prefix,
secret, and policy references. `ServiceKind=accounting-only` accepts
accounting for services without Wi-Fi authentication configuration. It does
not implement another authentication protocol. Consult `radiusd.regman` for
the individual controls, defaults, bounds, and restart requirements.

Use `radius accounting status`, `sessions`, `session`, `history`, `usage`,
and `commands` for protected diagnostics. Session pages return a revision and
cursor. Supply both `--after` and `--revision` for the next page; restart the
view if its revision changes. `annotate` records an actor and note.
`correct-end` requires confirmation and can only narrow a stale or inferred
end within the last known evidence bounds. `rebuild --confirm` preserves
stable occurrence IDs, usage evidence, corrections, and command history.
It does not send another Disconnect or replay accounting telemetry.

The GXWI Accounting section displays protected session details, cumulative
traffic history, allowance bars, and health. Allowances and Accounting
Profiles use the same configuration model as CLI editing. Saved settings do
not establish successful daemon activation; inspect health after changes.

eventd receives service health and operational counters only. Accounting
usernames, user SIDs, device addresses, session identifiers, Class references,
and individual traffic measurements remain in the ledger. Metric names have
the fixed `radiusd.accounting` prefix with no personal labels. Provision that
namespace with `radius accounting telemetry-init` after eventd provisioning;
the command preserves existing namespace policy. Telemetry submission is best
effort and is not the authority for limits or accounting facts.

## Qualification

Portable checks cover independent integrity fixtures, semantic retries,
reordered reports, exact counters, principal reservations, overlapping limits,
retention, correction, rebuild, full-storage recovery, and process exit after
commit before reply. Native checks use a NIC-less disposable VM and the
production kernel, without rebuilding the kernel or packages.

A real UniFi/iPhone trial passed session Start, one-minute Interim reports,
Class correlation to the verified account despite an anonymous outer username,
Stop, and fresh reconnect occurrences. It also passed authenticated Disconnect
followed by Stop and automatic reconnection, principal time-allowance
exhaustion with subsequent admission refusal and restoration, and a daemon
restart with retained session/history followed by a continuing AP update.
Stored reports
across three APs retained the same verified identity and closed the old
occurrences. Their one-second timestamps do not establish subsecond handoff
latency, zero packet loss, or uninterrupted application traffic.

Passing fixtures does not qualify every NAS, tunnel implementation, or
vendor profile. Test real equipment for reporting frequency, Class echoing,
counter semantics, roaming, and Disconnect enforcement. A process or VM
crash test does not establish power-loss behavior of every host storage stack.
Full eventd ingestion and production-scale capacity remain separate
qualification limits.
