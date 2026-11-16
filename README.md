# Peios RADIUS

`radius` is the Peios RADIUS repository. It contains the portable `radius-core`
library, the native Peios `radiusd` daemon, and a separate loopback-only
`radius-test-server` qualification fixture.

The native adapter uses authd Authenticate without a local logon, reads normal
Registry configuration, checks the network's current Connect SD through
libpeios, and emits operational events. This is a development milestone;
packaging and broader hardware qualification remain separate work. The
TTLS/PAP path has passed a real UniFi/iPhone trial.

The core implements UDP RADIUS authentication with mandatory request integrity,
EAP-TTLSv0/PAP and PEAPv0/EAP-MSCHAPv2 using Rustls/ring, with explicit admission before success or key
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
pekit build -j 2 radiusd
```

The raw executable paths are reported by `pekit build`. Pass the harness to the
interoperability runner. No target builds an image, kernel or `pkgs/` package.

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

For an offline VM with persistent state and replaceable raw binaries, see
[Persistent Development VM](docs/learn/1--peios.shelf/peios.product/400--reference.antho/200--trms.shelf/900--radius.book/4--development-vm.md).

The disposable native `tests/native/mschapv2.sh` gate covers PEAP and TTLS
coexistence, source verification, password changes, and the NT storage and
backfill controls. PEAP uses TLS 1.2; TTLS supports TLS 1.2 and 1.3. PEAP
onboarding on an actual iPhone remains to be qualified.

Accounting, proxying, further EAP methods, resumption, and application SSO are
outside this slice. The later kernel-backed advisory API and public read-only
Registry snapshot milestone remains required before expanding the initial
home-Wi-Fi feature set.
