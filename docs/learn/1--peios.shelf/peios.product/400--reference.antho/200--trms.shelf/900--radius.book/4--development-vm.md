---
title: Persistent Development VM
description: Persistent machine state and replaceable raw binaries for offline RADIUS development.
---

The helper under `tools/dev-vm` runs an offline virtual machine (VM) with
persistent machine state. Raw component binaries remain separately
replaceable. The helper runs no package or kernel builds and creates no
host network interface.

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

Stage every update under a different set name. Staging copies all eight
files before publishing the set and does not alter the running VM.
Existing set names cannot be overwritten.

For a configured development VM, activate a staged set from its console:

```sh
bash /mnt/dev/activate.sh update-name
```

Activation copies and verifies the set before stopping services. It stops
radiusd if active, then lpsd and authd; switches the selected set; starts
lpsd and its authd dependency; and restarts radiusd if it was active.
Service definitions must use `/lcl/radius-dev/current/bin` and explicitly
select `/lcl/radius-dev/current/lib` for library loading. Running PID 1
changes only on the next boot. Select the desired set in the next host
`run` command; runtime activation does not change the host boot selection.

A missing or damaged staged set leaves running services untouched. A
failure after services stop remains visible and requires correction or
activation of the previous set; activation promises no automatic rollback.
Old sets remain available until deliberately removed while the VM is off.

Shut down through the matching control tool:

```sh
LD_LIBRARY_PATH=/lcl/radius-dev/current/lib \
    /lcl/radius-dev/current/bin/svctl shutdown poweroff
```

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
