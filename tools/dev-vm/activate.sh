#!/bin/bash
# Copy a complete immutable host set into the live root before switching.
set -euo pipefail
[[ $# -ge 1 && $# -le 2 ]] || { echo 'usage: activate.sh SET [--boot]' >&2; exit 2; }
selected=$1
[[ $selected =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || exit 2
mode=${2:-update}
[[ $mode == --boot || $mode == update ]] || exit 2
runtime=/lcl/radius-dev
source=/mnt/dev/sets/$selected
mkdir -p "$runtime/sets"
if [[ ! -d $runtime/sets/$selected ]]; then
    pending=$runtime/sets/.pending
    [[ ! -e $pending ]] || { echo 'an incomplete activation needs inspection' >&2; exit 1; }
    mkdir "$pending"
    trap 'rm -rf -- "$pending"' EXIT
    cp -R "$source/." "$pending/"
    (cd "$pending" && sha256sum -c SHA256SUMS)
    # Development executables are public; mutable machine state stays separate.
    /lcl/libexec/radius-dev-seed-sd -r --sddl 'O:SYG:SYD:P(A;OICI;GA;;;SY)(A;OICI;GRGX;;;WD)' "$pending"
    mv "$pending" "$runtime/sets/$selected"
    trap - EXIT
else
    (cd "$runtime/sets/$selected" && sha256sum -c SHA256SUMS)
fi
# Resolve dependencies before stopping any running service. Build/source ABI
# compatibility remains the caller's responsibility; checksums are not an ABI test.
for program in peinit2 svctl authd lpsd lps radiusd; do
    /lib64/ld-linux-x86-64.so.2 --library-path "$runtime/sets/$selected/lib" \
        --list "$runtime/sets/$selected/bin/$program" > /dev/null
done
[[ ! -e $runtime/current.next && ! -L $runtime/current.next ]] || exit 1
ctl=$runtime/current/bin/svctl
had_radius=no
if [[ $mode == update ]]; then
    export LD_LIBRARY_PATH=$runtime/current/lib
    if [[ $("$ctl" status radiusd 2>/dev/null) == *'radiusd: active'* ]]; then
        had_radius=yes
        "$ctl" stop radiusd
    fi
    "$ctl" stop lpsd
    "$ctl" stop authd
fi
ln -s "sets/$selected" "$runtime/current.next"
mv -Tf "$runtime/current.next" "$runtime/current"
if [[ $mode == update ]]; then
    export LD_LIBRARY_PATH=$runtime/current/lib
    "$ctl" start lpsd
    [[ $had_radius == no ]] || "$ctl" start radiusd
    echo 'RADIUS DEV VM: services restarted; running PID 1 changes on the next boot'
fi
