---
title: Native Integration
description: Service identity, Registry configuration, failure behavior, and disposable-guest qualification of radiusd.
---

`radiusd` is the native adapter around the portable protocol core. It
runs as its own `Identity=Service` account, verifies passwords through
authd, and checks the current network's Connect security descriptor.
It creates no user token or local logon session.

## Build and service identity

Build the raw executable, without packaging or rebuilding the kernel:

```sh
pekit build -j 2 radiusd
```

The native Cargo feature links the matching public `libauth.so.1` and
`libpeios.so.0`. The Pekit target supplies those libraries and SDK
headers from pinned canonical source revisions. A development guest
must load these matching libraries rather than older image copies.

The service must be named `radiusd` and use `Identity=Service`. It
checks its actual token user SID at startup. Trusted authd policy gives
this account the `peios.auth.authenticate` capability. It receives no
`peios.auth.logon` capability and needs no token-creation or impersonation
privileges. `SeChangeNotifyPrivilege` permits ordinary path traversal;
`SeAuditPrivilege` permits operational event emission. The normal UDP
port-reservation descriptor grants its service SID PORT_BIND for each
configured listening port. Use peinit's Notify readiness mode.

The default AuthenticationSecurity descriptor grants this service
ReadGroups and ReadClaim across the namespace. Authenticate remains a
separate capability grant. Administrators can use ordinary claim object
ACEs to restrict sensitive claims. An explicit AuthenticationSecurity
value replaces the default and is never silently broadened.

## Configuration and admission

The component's `radiusd.regman` describes every value under
`Machine\Software\Radius`. Settings define literal UDP listeners and
bounded conversation resources. Clients define source-address prefixes,
protected secret-file references, and allowed network records. Networks
define exact SSIDs, Connect security descriptors, and requested periodic
reauthentication. TLS references an ordered DER certificate chain and
matching protected DER private key.

Most-specific source prefixes select the trusted client. There is no
fallback to another secret. The integrity-checked Called-Station-Id must
contain a valid MAC prefix and exact SSID; NAS identifiers and MAC
addresses do not establish user identity. Continuations retain their
original client, source, and network binding. A changed secret, source
trust definition, SSID, or listener set invalidates affected work.

After PAP, one nonblocking authd operation belongs to the attempt. The
adapter accepts one typed Password prompt and requires a final result
that confirms Password verification. Unsupported prompts, repeated
prompts, unavailable sources, and incomplete verification cannot grant
access. A configurable concurrency limit rejects excess verification
work without an unbounded queue.

Admission uses the verified SID, source groups, permitted typed claims,
and explicit claim coverage. It does not reconstruct identity from a
later username lookup or invent local-session group memberships.
For example, grant Connect to a source's household group SID. An
Everyone ACE matches only when that membership is supplied; the adapter
does not add it. Hidden claims remain unknown. Missing context, device
or local execution requirements, and unsupported SACL auditing deny
admission. The userspace checker conveys no kernel authority.

Current policy is checked immediately before success and key delivery.
Access-Accept carries signed Session-Timeout and Termination-Action
attributes. The default requests reauthentication after one hour.
It does not immediately disconnect existing Wi-Fi stations, and AP
enforcement must be qualified separately.

## Reload and reporting

A bounded worker handles blocking Registry and protected-file reads.
The packet loop continues processing bounded handshakes and expiry.
Observed pending, invalid, unreadable, or unwatched configuration pauses
new admissions and cached success replies. Pending verification results
can wait only within their original deadlines. Recovery validates the
assembled configuration before resuming. Certificate-only renewal
changes new TLS exchanges while existing bounded exchanges continue.

This milestone deliberately uses non-transactional multi-call Registry
reads. Watches and fingerprints detect observed changes; they provide
no atomic-snapshot guarantee. Concurrent edits can form a mixed but
valid configuration. Prepare protected immutable credential files, then
transactionally switch references. Keep old files until safely unused.

`radiusd.evman` defines operational exchange and configuration events.
The inner supplied username is explicitly unverified input; canonical
name and SID appear only after verification. Events contain no
passwords, AP secrets, private keys, or full claim values. Exact
retransmissions do not repeat outcomes. Invalid datagrams are counted
in bounded, rate-limited diagnostics. Event emission failure is reported
without changing a valid admission; successful emission does not prove
durable collection. These events do not replace kernel SACL auditing.

## Disposable guest qualification

The scripts under `tests/native` alter accounts, service definitions,
machine authentication policy, and a port table. Run them only in a
fresh disposable guest, with `PEIOS_DISPOSABLE_RADIUS_TEST=yes`.
They must never run on a developer's normal system.

Use an existing console image and raw component binaries. Mount a
read-only development share as `/mnt/dev`, using the guest's supported
9p synthetic ephemeral policy. Copy the matching raw peinit2, svctl,
authd, lpsd, lps, radiusd, libpeios, and libauth into `/lcl`. Start the
raw peinit2 as PID 1 from an initial shell. Set service library search
paths explicitly: peinit constructs service environments rather than
inheriting the launching shell's environment.

The share contains `native` with the three shell scripts; `bin` with
the independent `eapol_test` and matching OpenSSL runtime dependencies;
and `credentials` with generated root.pem, server.der, intermediate.der,
key.der, secret, and rotated-secret files. The existing interoperability
certificate helper creates suitable development-only certificates.
Secrets are development fixtures, never production credentials.

```sh
export PEIOS_DISPOSABLE_RADIUS_TEST=yes
bash /mnt/dev/native/setup.sh
bash /mnt/dev/native/qualify.sh
```

The independent supplicant runs inside the guest against loopback UDP.
The native service identity, Registry, authd/lpsd verification, supplied
subject admission, and key export are real. Wi-Fi equipment and its
radio link are simulated. The scripts check both TLS versions, matching
MPPE keys, account and policy denials, restricted-claim uncertainty,
invalid-configuration recovery, secret rotation, and source failure.
They capture supplicant output privately because it can contain keys.

The optional `native-events` Cargo example reads the two fixture CPU
rings as the guest administrator. Start it before `qualify.sh`, wait
for `/run/radiusd/events.ready`, and create
`/run/radiusd/qualification.done` afterward. Its zero exit status and
PASS marker verify typed, cataloged payload fields and absence of
unexpected credential or claim fields. It is a qualification tool,
not part of the daemon or a required service privilege.

Portable coordinator tests separately cover concurrent verification
bounds, exact replay, policy changes, preserved deadlines, binding
invalidation, and cancellation. Native SDK tests cover typed claims,
known absence, and missing device or audit context.

Passing these checks is development evidence, not a production release
or a complete security audit. Real UniFi hardware, mobile onboarding,
roaming, and AP reauthentication remain unqualified. Before expanding
the initial feature set, replace the temporary userspace checker with
the planned kernel API and add generic public Registry read snapshots.
