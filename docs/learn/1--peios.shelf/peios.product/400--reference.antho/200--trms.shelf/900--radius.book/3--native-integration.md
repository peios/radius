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
protected secret-file references, and allowed access-policy GUIDs. Access
policies define exact SSIDs, Connect security descriptors, periodic
reauthentication, and an authentication-profile reference. Profiles select
ordered methods and a named server identity. Server identities reference an
ordered DER certificate chain and matching protected DER private key.
All records have stable GUID keys and independent display names. Schema
version 2 requires explicit conversion from the earlier development layout.

Most-specific source prefixes select the trusted client. There is no
fallback to another secret. The integrity-checked Called-Station-Id must
contain a valid MAC prefix and exact SSID; NAS identifiers and MAC
addresses do not establish user identity. Continuations retain their
original client, source, and network binding. A changed secret, source
trust definition, SSID, or listener set invalidates affected work.

Each profile's required `AuthenticationMethods` is an ordered allowed-method
list containing `ttls-pap`, `peap-mschapv2`, or both. All methods share the
access policy's Connect descriptor. Changing a method list invalidates
affected unfinished exchanges and cached replies. Enabling NT storage does
not change the configured methods.

An intentionally disabled client, policy, or profile denies affected
admissions without falling back to other clients or profiles. Otherwise
valid disabled records do not invalidate unrelated policy. These changes do
not disconnect established stations immediately. Missing references remain
invalid even on disabled records.

One nonblocking authd operation belongs to each credential attempt. PAP
uses one typed Password prompt and requires confirmed Password verification.
PEAP requests MSCHAPv2, relays one source-issued challenge and typed
response, and requires confirmed MSCHAPv2 verification with the protocol's
server proof. radiusd receives no reusable NT hash. Unsupported or repeated
prompts, unavailable sources, and incomplete verification cannot grant access.
A configurable concurrency limit rejects excess verification work without
an unbounded queue. NT storage and opportunistic password-side backfilling
are documented with the local principal source, not configured by radiusd.

Admission uses the verified SID, source groups, permitted typed claims,
and explicit claim coverage. It does not reconstruct identity from a
later username lookup or invent local-session group memberships.
For example, grant Connect to a source's household group SID. An
Everyone ACE matches only when that membership is supplied; the adapter
does not add it. Hidden claims remain unknown. Missing context, device,
or local execution requirements deny admission. The stateless kernel query
conveys no token authority. An older kernel fails admission with
`kernel-api-unavailable`; other query errors use `access-check-error`,
independently of wrong credentials and an ordinary policy denial. There is no
userspace evaluator fallback.

Each check supplies the stable Registry network ID and SSID display label in
an `AuditContext` of kind `network`. Invalid UTF-8 in the label is replaced
with U+FFFD; policy binding still uses the original SSID bytes. The fields are
defined as asserted values in radiusd's event catalog fragment. Matching SACL
audit ACEs produce `kacs.audit.subject.checked`
when radiusd holds enabled `SeAuditPrivilege`. The event identifies radiusd's
real caller identity separately from the supplied, hypothetical user SID.
Audit preparation errors fail admission. radiusd's own admission events remain
separate and describe the real service decision.

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
assembled configuration before resuming. Certificate replacement cancels
affected unfinished exchanges and cached replies. Cosmetic name changes
preserve authentication bindings.

Notify readiness means the local status endpoint is ready. An invalid
initial configuration leaves that endpoint available for diagnosis and
repair while authentication is paused. It does not imply active listeners.
The administration program shows saved and effective configuration
separately; it also distinguishes a stopped service from an unreachable or
unauthorized status endpoint. See
[Administration](~peios/reference/radius/administration).

The loader copies Registry configuration through one short read-only
transaction, including key resolution, enumeration, values, and layer
selection.
It releases the snapshot before opening credential files. Capture races and
other read errors discard the complete candidate; the worker retries on its
normal reload cycle and keeps admission paused while configuration is invalid.
Watches and fingerprints detect changes but do not establish read consistency.
Prepare protected immutable credential files, then transactionally switch
references. Keep old files until safely unused; a Registry transaction does
not snapshot filesystem contents.

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

The share contains `native` with the qualification shell scripts; `bin` with
the independent `eapol_test` and matching OpenSSL runtime dependencies;
and `credentials` with generated root.pem, server.der, intermediate.der,
key.der, secret, and rotated-secret files. The existing interoperability
certificate helper creates suitable development-only certificates.
Secrets are development fixtures, never production credentials.
For PEAP qualification, enable EAP-PEAP and EAP-MSCHAPV2 in the independent
supplicant. The supplied builder enables both. An OpenSSL 3 build can also
need its matching legacy provider for the supplicant's MD4 operation;
place `legacy.so` beside the test executable. radiusd does not use that
provider.

```sh
export PEIOS_DISPOSABLE_RADIUS_TEST=yes
bash /mnt/dev/native/setup.sh
bash /mnt/dev/native/qualify.sh
bash /mnt/dev/native/mschapv2.sh
bash /mnt/dev/native/administration.sh
bash /mnt/dev/native/initialize.sh
```

The independent supplicant runs inside the guest against loopback UDP.
The native service identity, Registry, authd/lpsd verification, supplied
subject admission, and key export are real. Wi-Fi equipment and its
radio link are simulated. The scripts check both TLS versions, matching
MPPE keys, account and policy denials, restricted-claim uncertainty,
invalid-configuration recovery, secret rotation, and source failure.
They capture supplicant output privately because it can contain keys.
The MSCHAPv2 sequence also checks method negotiation, both NT controls,
opportunistic backfilling, password changes, and password eligibility.
Administration qualification additionally requires `bin/radius`, matching
`libgxwi.so.1`, and the native-authority example in the development share.
It checks shared profiles, references, renames, disabled isolation, invalid
startup recovery, credential staging, stopped-daemon edits, and real-token
status, Registry, and secret-file authorization. Certificate import checks
also need the corresponding PEM chain and private key in the fixture share.
The initialization script temporarily replaces and restores the disposable
fixture's Registry subtree and credential directory. It verifies fresh setup,
existing-configuration refusal, and enabled-administrator writes without
granting the test token extra privileges.
Set `RADIUS_DEV_RUNTIME=1` when using the replaceable raw-binary layout
at `/lcl/radius-dev/current` rather than copying binaries into `/lcl`.

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
or a complete security audit. Real UniFi/iPhone TTLS/PAP connectivity and
a profile-free iPhone join through PEAP have succeeded in development
trials. Roaming and AP reauthentication enforcement need their own
qualification. The supplied-subject evaluator runs in the kernel;
the loader uses the public Registry read-snapshot API before further feature
expansion.
