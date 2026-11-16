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
pekit test -j 2 unit clippy doctests
pekit build -j 2 test_server
```

These are raw component targets. They do not package files or build a
kernel or image. The host Cargo equivalents are documented in the
repository README. The Rust checks exercise malformed/truncated packets,
duplicate attributes, conversation quotas, idle and overall deadlines,
binding changes, one-shot admission and rejection without key delivery.

## Limits of the evidence

Passing this gate establishes host-side protocol behavior for the tested
tool and cases. Native qualification is described in
[Native Integration](~peios/reference/radius/native-integration). Neither gate establishes
real AP reauthentication or device onboarding. Those require actual
equipment. A passing suite is not a complete security audit.
