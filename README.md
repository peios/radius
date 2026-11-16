# Peios RADIUS

`radius` is the Peios RADIUS repository. The production daemon will be named
`radiusd`. This first slice provides the portable `radius-core` library and a
separate, loopback-only `radius-test-server` qualification fixture. It does not
yet provide a production daemon, authd/registry integration or service units.

The core implements UDP RADIUS authentication with mandatory request integrity,
EAP-TTLSv0/PAP using Rustls/ring and explicit admission before success or key
delivery. It owns bounded, short-lived conversations rather than hours-long
Wi-Fi sessions. See the [technical reference](docs/learn/1--peios.shelf/peios.product/400--reference.antho/200--trms.shelf/900--radius.book/1--architecture.md).

## Build and test

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

The test-tool builder downloads the pinned upstream wpa_supplicant 2.12 archive,
checks its SHA-256 and builds only `eapol_test`, using two jobs by default. It
requires a C compiler, Make and OpenSSL development files. The source build is
temporary and is removed afterward. It uses GNU C11 because newer compiler/libc
defaults otherwise expose const-qualification errors in this upstream release.
You can instead supply an existing qualified `eapol_test` executable.

Direct component targets, without any packaging:

```sh
pekit test -j 2 unit clippy doctests
pekit build -j 2 test_server
```

The raw harness executable is reported by `pekit build`. Pass it to the same
interoperability runner. No target builds an image, kernel or `pkgs/` package.

## Current boundary

The integration adapter supplies trusted-client/network context derived from
configuration and the actual packet source. The protocol core cannot establish
that trust from NAS attributes. After inner PAP it returns a `Verification`
event, and the integration retains the full verified subject for that attempt.
`Engine::finish` requires an explicit admission result and current binding;
credential success alone is insufficient.

The fixture compares a single test username/password and supports a forced
admission denial. It does not simulate the complete authd contract. It refuses
non-loopback listeners and has no deployment configuration. Do not use it to
authenticate a real network.

Accounting, proxying, additional EAP methods, resumption and application SSO are
outside this slice. Native Peios and real UniFi/device qualification follow the
production integration. The later kernel-backed advisory API milestone remains
required before expanding the initial home-Wi-Fi feature set.
