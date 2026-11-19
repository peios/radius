---
title: Qualification
description: Running the independent supplicant gate and understanding what its results establish.
---

The interoperability gate tests the protocol core against an independent
OpenSSL-backed supplicant over loopback. It checks the encrypted exchange
and actual exported Wi-Fi key agreement independently of Peios services.

## Running the gate

From the repository root, build the fixture and test tool:

```sh
cargo build --workspace --locked
python3 tools/build-eapol-test.py --out target/test-tools/eapol_test
```

The tool builder requires a C compiler, Make, OpenSSL development files
and network access to the pinned upstream archive. It builds only the
test executable and removes its temporary source tree. An existing
qualified `eapol_test` can be supplied instead.

Run the required gate:

```sh
python3 tests/interop.py --server target/debug/radius-test-server --eapol-test target/test-tools/eapol_test
```

The runner fails if required tools are missing. Successful cases check
both EAP success and MPPE key agreement. It forces TLS 1.2 and TLS 1.3
separately, uses a large certificate chain and small fragments, checks
anonymous and differing outer names, and rejects wrong credentials,
denied admission, untrusted issuers and wrong server names. A loopback
relay duplicates requests and suppresses a reply. Direct packet checks
also verify reply authenticators and discard tampered requests.

The fixture listener rejects non-loopback addresses. Temporary test
credentials and certificates are removed on completion; captured
supplicant output is not printed because it can contain key material.
The fixture uses explicit test credentials and never contacts authd.

## Component checks

```sh
pekit test --strict -j 2 unit integration management policy accounting clippy doctests
pekit build --strict -j 2 test_server radiusd radius_cli radius
pekit test --strict -j 2 native native_management administration native_clippy native_management_clippy administration_clippy
```

These are raw component targets. They do not package files or build a
kernel or image. `radius_cli` builds terminal administration with native
support; `radius` also includes the GXWI window. The native targets supply
matching pinned SDK, authentication and desktop libraries. Cargo and Pekit
must select the same source revision for each imported component; do not
bypass a reported mismatch. Before dependency commits are published, local
qualification needs those exact commits in the build cache.

The host Cargo equivalents are documented in the repository README. Native
host tests do not replace guest qualification: tests marked as requiring a
disposable Peios guest remain ignored on the host. The Rust checks exercise
malformed and truncated packets, duplicate attributes, conversation quotas,
idle and overall deadlines,
binding changes, one-shot admission and rejection without key delivery.

## Native session controls

In a fresh, isolated guest, run `tests/native/setup.sh`, then
`tests/native/session-controls.sh` and `tests/native/automatic-controls.sh`.
Supply the compiled `native-session-controls` example, the native-policy test
binary, and the independent supplicant in `/mnt/dev/bin`, with the fixture
credentials under `/mnt/dev/credentials`. These scripts require
`PEIOS_DISPOSABLE_RADIUS_TEST=yes` and `RADIUS_DEV_RUNTIME=1`. They change
accounts, policy, service definitions, and the ledger; use no deployed state
or LAN interface.

The checks exercise actual caller tokens, separate action and fallback
permissions, protected credential metadata, password revision changes,
maintenance stability, exact-session CoA and Disconnect, forged replies,
durable request IDs, restart, rebuild, and real PEAP/TTLS authentication.
Automatic cases use direct Registry VLAN edits, account disablement, password
replacement with an explicit Disconnect fallback, and opt-in CoA updates.
The generic profile does not claim fresh reauthentication support.

A migration fixture can seed accounts with a previously qualified format-6
lpsd before switching to the new runtime. Set
`RADIUS_QUALIFY_LEGACY_STORE=1` only for that arrangement. Fresh-store checks
do not exercise the old-store upgrade.

## Component load and recovery

The developer-only qualification program measures bounded synthetic loads,
checks overload recovery, and injects storage failures in child processes.
See [Component Load and Recovery](~peios/reference/radius/component-load-and-recovery)
for commands, measurements, and the incomplete instrumented fuzzing gate.

## Limits of the evidence

Passing this gate establishes host-side protocol behavior for the tested
tool and cases. Native qualification is described in
[Native Integration](~peios/reference/radius/native-integration). Neither gate establishes
real AP reauthentication or device onboarding. Those require actual
equipment. A passing suite is not a complete security audit.
