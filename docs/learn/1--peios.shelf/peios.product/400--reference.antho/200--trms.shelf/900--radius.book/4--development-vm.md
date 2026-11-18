---
title: Persistent Development VM
description: Persistent machine state and replaceable raw binaries for offline RADIUS development.
---

The helper under `tools/dev-vm` runs a virtual machine (VM) with
persistent machine state. Raw component binaries remain separately
replaceable. The helper runs no package or kernel builds. Offline boot is
the default; optional LAN boot attaches a temporary network interface to
an existing host bridge.

## Boot and storage

`vm.py prepare` extracts the kernel and initramfs from an existing console
ISO. It appends a development hook to the initramfs; the source ISO stays
unchanged. The image must provide the version-2 `rootfs-ready` hook
sequence and the ordinary live-root strategy.

The extra hook mounts a read-only development share. Before starting
peinit, the bootstrap mounts the required ext4 state disk and binds its
directories onto `/var/state` and `/lcl/etc`. The registry hives, local
account store, random seed, machine ID, certificates, secrets, and local
policy therefore survive shutdown. `/run` remains temporary.

Disk creation and first machine initialization are separate explicit
operations. Normal boots never format or seed a disk. Missing, unreadable,
uninitialized, or incomplete required state stops startup before the
registry starts. Bootstrap failure leaves PID 1 waiting with a diagnostic;
it does not start another machine identity.

The host helper serializes runs of one VM and checks the prepared boot
assets. Keep the VM directory private: its state image contains credential
material. Back up the image only after a clean shutdown.

## Preparing a VM

The host needs Python 3.11 or later, QEMU, xorriso, mtools, GNU objcopy,
zstd, cpio, and ext4 filesystem tools. The console image supplies the
guest shell, mount tools, security-descriptor seeder, and registry service.
QEMU uses two CPUs and 1536 MiB of memory, with hardware acceleration when
available and software emulation otherwise.

From the workspace root, prepare the existing console image:

```sh
python3 radius/tools/dev-vm/vm.py --vm local/radius-dev-vm \
    prepare local/isos/console.iso
python3 radius/tools/dev-vm/vm.py --vm local/radius-dev-vm create-state
```

Disk creation exclusively creates a 512 MiB sparse file and refuses an
existing file. Boot preparation also refuses existing boot assets.

Build raw targets directly in their component repositories. Assemble the
reported outputs into a directory with these entries:

| Entries | Raw targets |
|---|---|
| `bin/peinit2`, `bin/svctl` | peinit: `peinit2 svctl` |
| `bin/authd`, `bin/lpsd`, `bin/lps` | authd: `authd lpsd lps` |
| `bin/radiusd` | radius: `radiusd` |
| `lib/libauth.so.1` | authd: `libauth` |
| `lib/libpeios.so.0` | peios-sdk: `libpeios` |

Administration development adds `bin/radius` and `lib/libgxwi.so.1`, built
from the RADIUS `radius` target and GXWI `libgxwi` target. Stage both
together;
partial administration sets are rejected before publication. The window
also needs a running GXWI desktop; the CLI does not.

For a complete desktop, build `gxwi-server` as the static musl target
specified by GXWI's `build.gcsl`. Its restricted token cannot open a dynamic
loader or arbitrary shared libraries. Build the other desktop programs using
their component recipes. Install `libgxwi.so.1` in the guest's ordinary
library search path as well as supplying it to development services. A user
session has no service-specific `LD_LIBRARY_PATH`; a wrapper around RADIUS
alone does not make the taskbar and launcher load successfully.

LAN development adds `bin/netd`, `bin/net`, and `lib/libnetd.so.1`, built
with netd's raw `netd`, `net`, and `libnetd` targets. Stage all three
together. Partial network sets are rejected before publication. Once a
VM has a saved network attachment, every boot requires these files,
including offline boots, because its service definition persists.

Use matching SDK and authd revisions. The helper checks complete files,
checksums, and guest loader dependencies; those checks do not prove ABI
compatibility. Build-cache warnings about mismatched imported source
revisions require investigation before selecting the outputs.

For an assembled directory at `local/radius-runtime`, stage and boot it:

```sh
python3 radius/tools/dev-vm/vm.py --vm local/radius-dev-vm \
    stage initial local/radius-runtime
python3 radius/tools/dev-vm/vm.py --vm local/radius-dev-vm \
    run initial --initialize
```

Use `run initial` without `--initialize` on subsequent boots. Successful
startup reports that persistent state is mounted, followed by peinit's
ordinary boot messages and the console shell.

## Updating development binaries

Stage every update under a different set name. Staging copies every required
files before publishing the set and does not alter the running VM.
Existing set names cannot be overwritten.

For a configured development VM, activate a staged set from its console:

```sh
bash /mnt/dev/activate.sh update-name
```

Activation copies and verifies the set before stopping services. It stops
radiusd if active, then lpsd and authd, and netd if active. It switches the
selected set, restarts netd if needed, starts lpsd and its authd dependency,
and restarts radiusd if it was active. A set that omits network binaries
cannot replace a running netd.
Service definitions must use `/lcl/radius-dev/current/bin` and explicitly
select `/lcl/radius-dev/current/lib` for library loading. Running PID 1
changes only on the next boot. Select the desired set in the next host
`run` command; runtime activation does not change the host boot selection.

A missing or damaged staged set leaves running services untouched. A
failure after services stop remains visible and requires correction or
activation of the previous set; activation promises no automatic rollback.
Old sets remain available until deliberately removed while the VM is off.

## Qualifying the desktop

Successful sign-in and a desktop document do not establish that the shell
and management window work. With RADIUS open on Overview, run this additional
check from the host:

```sh
python3 radius/tools/dev-vm/check-desktop.py https://10.10.0.111:7780 \
    --certificate-sha256 "$GXWI_CERT_SHA256" \
    --administrator-file local/radius-administrator.json \
    --unprivileged-file local/radius-user.json
```

Supply the actual development VM address and its certificate's SHA-256
fingerprint, obtained from its console. Each private JSON file contains
`username` and `password` fields. Keep these files outside the repository and
restrict their permissions. The check pins the server certificate before
sending credentials; it never prints passwords, session cookies, or app-origin
secrets.

The check signs in as both accounts and uses the desktop's HTTP and WebSocket
protocols to verify a shell-owned taskbar panel, launcher overlay and declared
RADIUS window. It reads the app's rendered Overview: the administrator must
see Running and active saved configuration, while the non-administrator must
be denied configuration and status access. Both accounts need permission to
sign in through GXWI. This does not change configuration or group membership.
It can start or rejoin those users' desktop sessions; close them through the
ordinary desktop controls after qualification.

This protocol check does not verify browser layout, input or accessibility.
Inspect those separately in a browser. It also does not replace independent
supplicant tests or the real AP assignment and reauthentication trial.

Shut down through the matching control tool:

```sh
LD_LIBRARY_PATH=/lcl/radius-dev/current/lib \
    /lcl/radius-dev/current/bin/svctl shutdown poweroff
```

## LAN attachment

LAN mode requires a separately configured persistent Ethernet bridge on
the host, NetworkManager, and permission to control network connections.
The launcher never moves the host's physical Ethernet configuration.
Preparing or changing the bridge is a separate administrative action;
preserve the host's addressing identity and prepare a rollback before
activating that change.

Save a stable virtual MAC address and the bridge/TAP names once:

```sh
python3 radius/tools/dev-vm/vm.py --vm local/radius-dev-vm \
    configure-lan --bridge br-peios
```

This command writes `network.json` beside the state image. It refuses an
existing file, so ordinary setup cannot replace the virtual MAC. The
configuration belongs to this VM and should accompany its state disk.

Configure the guest's `radius-dev-lan` netd profile and a matching
interface rule through the ordinary network registry settings. Static
addressing requires the address/prefix, gateway, and DNS settings; it
does not require a DHCP reservation. Do not copy addresses from another
network into this profile.

Stage a complete runtime set containing the network programs and library.
Boot it offline first to provision the service:

```sh
python3 radius/tools/dev-vm/vm.py --vm local/radius-dev-vm run lan-initial
```

In the guest, apply the prepared profile and rule, then run:

```sh
bash /mnt/dev/provision-network.sh
```

The provisioning helper creates the persistent netd state directory if
absent and configures the ordinary SYSTEM netd service using the raw
executable. It preserves existing network profiles and rules. An existing
netd definition retains its unrelated settings. The service starts at
boot and publishes network readiness through its normal control APIs.

For a VM prepared by an earlier helper version, copy the updated
`activate.sh` and `provision-network.sh` into its host `share` directory
before provisioning. No initramfs or kernel rebuild is required.

After a clean shutdown, boot with the LAN attachment:

```sh
python3 radius/tools/dev-vm/vm.py --vm local/radius-dev-vm \
    run lan-initial --lan
```

The launcher creates a temporary NetworkManager TAP profile owned by the
invoking user and connects it to the configured bridge. QEMU uses that
TAP and the saved virtual MAC. Existing TAP names are rejected. Shutdown
or a failed QEMU launch removes the temporary profile and device while
leaving the host bridge in place. The profile is not saved to disk.

Check `net status` in the guest for the matched profile, saved address,
gateway, and routed readiness. Check reachability from another LAN
machine. Routed readiness reports configured state; it does not prove
that the gateway or a remote service answers. The host must remain
connected after the VM shuts down and its TAP disappears.

LAN attachment does not expand radiusd's trusted-client configuration or
replace the offline fixture's deny-all network policy. Real AP clients,
certificates, and network admission require separate provisioning.

## Offline qualification fixture

`tests/dev-vm/prepare.py` prepares inputs from authd's standard policy
seeds and the existing protocol-test certificate helper. Run it only for
a fresh offline VM. The guest fixture refuses an existing account store
or authentication policy and creates a development account, group,
registry marker, and loopback-only radiusd configuration. It supplies
fixed test credentials and a Connect descriptor that denies all access.
It is not real-network provisioning.

```sh
python3 radius/tests/dev-vm/prepare.py \
    --vm local/radius-dev-vm --authd authd
```

In the freshly initialized guest:

```sh
PEIOS_OFFLINE_VM_PROOF=yes bash /mnt/dev/proof-setup.sh
PEIOS_OFFLINE_VM_PROOF=yes bash /mnt/dev/proof-check.sh save
```

After binary activation and again after a clean shutdown and normal boot:

```sh
PEIOS_OFFLINE_VM_PROOF=yes bash /mnt/dev/proof-check.sh check
```

The check requires all three services active and compares the machine ID,
account domain and security identifiers, groups, configuration, policy,
and hashes of the account store and protected credentials. Its PASS
marker establishes offline persistence and activation, not a real Wi-Fi
connection. Certificate onboarding, a LAN address, UniFi integration,
and production credentials require separate provisioning and qualification.
