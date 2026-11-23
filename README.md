# Peios RADIUS

`radius` is the Peios RADIUS repository. It contains the portable `radius-core`
library, the native Peios `radiusd` daemon, the shared `radius-management`
library, the `radius-policy` PNP adapter, the `radius-authorization` settings
and equipment encoders, the `radius-accounting` ledger,
the CLI/GXWI `radius` program, and a
separate loopback-only `radius-test-server` qualification fixture.

The native adapter uses authd Authenticate without a local logon, reads normal
Registry configuration, checks the network's current Connect SD through
libpeios, and emits operational events. This is a development milestone;
packaging and broader hardware qualification remain separate work. The
TTLS/PAP and PEAP/MSCHAPv2 paths have passed real UniFi/iPhone trials.

The core implements UDP RADIUS authentication with mandatory request integrity,
EAP-TTLSv0/PAP and PEAPv0/EAP-MSCHAPv2 using Rustls/ring, with explicit admission
before success or key delivery. It owns bounded, short-lived conversations rather than hours-long
Wi-Fi sessions. See the [technical reference](docs/learn/1--peios.shelf/peios.product/400--reference.antho/200--trms.shelf/900--radius.book/1--architecture.md).

## Build and test

The administration window requires Rust 1.98.1 or later, matching Peios SDK
headers and libraries, and libgxwi. Its canonical Cargo replacement gives the
SD editor the same Peios bindings as the daemon. With those libraries
on the compiler and runtime search paths:

```sh
cargo +1.98.1 build -p radius --features window --locked
cargo +1.98.1 build -p radiusd --features native --locked
cargo +1.98.1 test --workspace --features radius/window,radiusd/native --locked
cargo +1.98.1 clippy --workspace --all-targets --features radius/window,radiusd/native --locked -- -Dwarnings
```

Four native-policy tests are ignored on a normal host and run explicitly in
the disposable Peios guest. The portable checks need no native libraries:

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked
python3 tools/build-eapol-test.py --out target/test-tools/eapol_test
python3 tests/interop.py --server target/debug/radius-test-server --eapol-test target/test-tools/eapol_test
```

The interoperability gate requires an independent `eapol_test` and OpenSSL. It
fails when either tool is missing. It uses loopback UDP, temporary generated
certificates and fixture credentials; it needs no AP, network changes or user
accounts. Supplicant output can contain secrets, so the runner captures it and
reports only case outcomes. Successful cases require both supplicant success
and actual MPPE key agreement. The server sends a large certificate chain and
both peers use small fragments.

The assignment adapter uses kernel-owned `pnp-core` sources under `vendor/kernel`.
`ORIGIN.json` records the source revision and individual hashes. Refresh them
with `python3 tools/sync-pnp-core.py /path/to/reviewed/kernel`; edit semantic
sources in the kernel repository. The shared extraction preserves packet and
interface entry points and introduces no syscall requirement.

See [Access Assignment](docs/learn/1--peios.shelf/peios.product/400--reference.antho/200--trms.shelf/900--radius.book/7--access-assignment.md)
for explicit default rules, VLAN configuration, typed claims and Explain.

See [Access Profile Settings](docs/learn/1--peios.shelf/peios.product/400--reference.antho/200--trms.shelf/900--radius.book/11--access-profile-settings.md)
for connection, bandwidth, traffic, gateway and management settings, equipment
mappings, exact encodings and enforcement qualification limits. Generate the
Registry reference entries from the shared metadata with
`cargo run -p radius-authorization --example reference -- regman`.

See [Session Controls](docs/learn/1--peios.shelf/peios.product/400--reference.antho/200--trms.shelf/900--radius.book/9--session-controls.md)
for exact-session Disconnect and CoA, device profiles, automatic reevaluation,
independent permissions, evidence and coordinated store migration.

The test-tool builder downloads the pinned upstream wpa_supplicant 2.12 archive,
checks its SHA-256 and builds only `eapol_test`, using two jobs by default. It
requires a C compiler, Make and OpenSSL development files. The source build is
temporary and is removed afterward. It uses GNU C11 because newer compiler/libc
defaults otherwise expose const-qualification errors in this upstream release.
You can instead supply an existing qualified `eapol_test` executable.

Direct component targets, without any packaging:

```sh
pekit test --strict -j 2 unit integration management policy authorization accounting clippy doctests
pekit build --strict -j 2 test_server radiusd radius_cli radius
pekit test --strict -j 2 native native_management administration native_clippy native_management_clippy administration_clippy
```

The raw executable paths are reported by `pekit build`. Pass the harness to the
interoperability runner. No target builds an image, kernel or `pkgs/` package.

The `radius_cli` raw target includes native terminal administration; `radius`
also includes the window. The `accounting` target exercises the ledger with
bundled SQLite, while `native_management` covers its native adapters. The
`policy` target covers the shared PNP adapter.

The developer-only `radius-qualify` program measures synthetic TLS admission
and durable accounting loads and checks storage failure recovery. It opens
no external sockets and uses no native authority. Build it with
`pekit build --strict -j 2 qualify`; run its regressions with
`pekit test --strict -j 2 qualification`. See
[Component Load and Recovery](docs/learn/1--peios.shelf/peios.product/400--reference.antho/200--trms.shelf/900--radius.book/10--component-load-and-recovery.md)
for commands, observed measurements, and their limits. The optional `fuzz/`
scaffolding has not completed an instrumented campaign.

Cargo and Pekit select matching immutable SDK, authentication and GXWI inputs.
Unpublished dependency commits must already be available in the local build
cache until they are published. Do not bypass a Pekit pin mismatch or select
arbitrary library outputs. Final PPK packaging remains separate work in
`pkgs/`; the commands above do not invoke it.

## Administration

Run `radius` for status, `radius --help` for terminal commands, or
`radius --window` for GXWI. Both interfaces use the same operations and actual
caller permissions. Configuration edits work while the daemon is stopped;
its local endpoint provides read-only status. See
[Administration](docs/learn/1--peios.shelf/peios.product/400--reference.antho/200--trms.shelf/900--radius.book/5--administration.md)
for setup, secrets, certificates, permissions, and activation diagnostics.

`radius diagnostics list|show|follow|drops|status` and the GXWI Diagnostics
section read caller-authorized eventd evidence. They show observed attempt
timelines, exact authd operation links, collection limits and missing outcomes.
See [Authentication Diagnostics](docs/learn/1--peios.shelf/peios.product/400--reference.antho/200--trms.shelf/900--radius.book/8--diagnostics.md).

Schema version 2 uses GUID-backed clients, access policies, authentication
profiles, and server identities. The prior development layout needs explicit
conversion before activating these binaries. No permanent migration framework
or automatic live-deployment conversion is included.

## Current boundary

The integration adapter supplies trusted-client/network context derived from
configuration and the actual packet source. The protocol core cannot establish
that trust from NAS attributes. It returns inner credentials or a source-bound
MSCHAPv2 response to the integration, which retains the full verified subject
for that attempt. Reusable NT hashes stay inside the credential source.
`Engine::finish` requires an explicit admission result and current binding;
credential success alone is insufficient.

The fixture compares a single test username/password and supports a forced
admission denial. It does not simulate the complete authd contract. It refuses
non-loopback listeners and has no deployment configuration. Do not use it to
authenticate a real network.

For native configuration and disposable-guest qualification, see
[Native Integration](docs/learn/1--peios.shelf/peios.product/400--reference.antho/200--trms.shelf/900--radius.book/3--native-integration.md),
[radiusd.regman](docs/radiusd.regman), and [radiusd.evman](docs/radiusd.evman).
The manuals are [radiusd(8)](docs/man/radiusd.8) and
[radius(8)](docs/man/radius.8).

`registry.d` holds the Registry seeds the radius package installs: the radiusd
service definition, with automatic startup disabled until
`radius service boot on`, its identity's authd capability and privileges, and reservations of UDP ports
1812 and 1813 for it. `tools/gen-port-seed.py` regenerates the reservations.

For an offline VM with persistent state and replaceable raw binaries, see
[Persistent Development VM](docs/learn/1--peios.shelf/peios.product/400--reference.antho/200--trms.shelf/900--radius.book/4--development-vm.md).

The disposable native `tests/native/mschapv2.sh` gate covers PEAP and TTLS
coexistence, source verification, password changes, and the NT storage and
backfill controls. PEAP uses TLS 1.2; TTLS supports TLS 1.2 and 1.3. A
profile-free iPhone join through PEAP has succeeded in the UniFi development
trial. The UniFi/iPhone trial also passed timed reauthentication and accounting
across AP changes. These checks do not establish radio handoff latency or
uninterrupted application traffic.

Proxying, further EAP methods, resumption, and application SSO are outside this
slice. Network authorization uses the kernel supplied-subject API,
and configuration uses a public read-only Registry snapshot. Referenced
credential files are loaded after that snapshot is released.

The disposable `tests/native/assignment.sh` gate checks VLAN assignments,
conflicting profiles, nested exceptions, direct-edit recovery and claim
disclosure. `tests/native/migrate-policy.sh` checks the schema migration's dry
run, transaction rollback, explicit no-override defaults and authentication.

## Accounting

`radius-accounting` owns the durable ledger, report interpretation, principal
allowances, retention, and durable Disconnect records. The native adapter
authenticates accounting peers and exposes a local token-checked query API.
Successful accounting replies follow a WAL/FULL commit; the authentication
coordinator persists Class correlation and admission reservations before an
Access-Accept. Accounting does not create a logon token or expose credentials.

See [Accounting](docs/learn/1--peios.shelf/peios.product/400--reference.antho/200--trms.shelf/900--radius.book/6--accounting.md)
for storage, privacy, quota semantics, configuration, and qualification limits.
`tests/accounting-fixtures.py` supplies independently calculated integrity
vectors. `tests/native/accounting.sh` provisions a fresh disposable guest;
never run it on an existing deployed machine.

The real UniFi/iPhone accounting trial passed Start, one-minute Interim updates,
Class-based identity correlation, Stop, separate reconnect occurrences, verified
Disconnect with automatic reconnection, principal time-allowance exhaustion and
restoration, and daemon restart with retained history and continuing AP updates.
Stored reports also preserve accounting identity across three APs. Full eventd
ingestion, production-scale capacity, and host power-loss behavior remain
qualification limits; they are not established by these tests.
