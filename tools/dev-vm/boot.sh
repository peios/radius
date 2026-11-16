#!/bin/bash
# Runs as PID 1 after prelude's ordinary root assembly, before peinit/loregd.
set -euo pipefail
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
fail() {
    echo "RADIUS DEV VM: startup stopped: $*" >&2
    # PID 1 must not exit and panic or silently start a replacement machine.
    while :; do sleep 3600; done
}
trap 'fail "bootstrap command failed at line $LINENO"' ERR
[[ $$ == 1 ]] || fail 'bootstrap must be PID 1'
[[ -b /dev/vda ]] || fail 'required state disk /dev/vda is missing'
mkdir -p /mnt/state
mount -t ext4 -o rw /dev/vda /mnt/state || fail 'cannot mount required state disk'
initialize=no
while read -r -a words; do
    for word in "${words[@]}"; do
        [[ $word != radiusdev.initialize=1 ]] || initialize=yes
    done
done < /proc/cmdline
if [[ $initialize == yes ]]; then
    [[ ! -e /mnt/state/layout ]] || fail 'state is already initialized; omit --initialize'
    # Explicit first initialization only. Ordinary boots never re-seed SDs.
    /lcl/libexec/radius-dev-seed-sd /mnt/state
    mkdir /mnt/state/state /mnt/state/etc
    cp -a /lcl/etc/. /mnt/state/etc/
    printf 'radius-dev-state-v1\n' > /mnt/state/layout
    sync
fi
[[ -r /mnt/state/layout ]] || fail 'state is unreadable or uninitialized; explicit initialization required'
[[ $(cat /mnt/state/layout) == radius-dev-state-v1 ]] || fail 'unrecognized state layout'
[[ -d /mnt/state/state && -d /mnt/state/etc ]] || fail 'state layout is incomplete'
if [[ $initialize == no ]]; then
    [[ -s /mnt/state/etc/machine-id && -s /mnt/state/state/loregd/Machine.hive && -s /mnt/state/state/loregd/Users.hive ]] \
        || fail 'existing machine identity or Registry hive is missing'
    if [[ -d /mnt/state/state/lpsd ]]; then
        [[ -s /mnt/state/state/lpsd/principals ]] || fail 'existing account store is missing'
    fi
fi
mkdir -p /var/state /lcl/etc
mount --bind /mnt/state/state /var/state
mount --bind /mnt/state/etc /lcl/etc
read -r selected < /mnt/dev/selection
[[ $selected =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || fail 'invalid runtime set name'
bash /mnt/dev/activate.sh "$selected" --boot
echo "RADIUS DEV VM: persistent state mounted; starting peinit with set $selected"
export LD_LIBRARY_PATH=/lcl/radius-dev/current/lib
exec /lcl/radius-dev/current/bin/peinit2
