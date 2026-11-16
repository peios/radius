#!/usr/bin/sh
# Appended development-only hook; original root assembly runs first.
set -eu
mkdir -p /mnt/rootfs/mnt/dev
mount -t 9p -o trans=virtio,version=9p2000.L,ro,policy=synth-ephemeral dev /mnt/rootfs/mnt/dev
cp -p /usr/libexec/prelude/radius-dev-boot /mnt/rootfs/run/radius-dev-boot
cp -p /usr/bin/seed-sd /mnt/rootfs/lcl/libexec/radius-dev-seed-sd
