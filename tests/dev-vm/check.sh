#!/bin/bash
# Save/compare the offline fixture's persistent identities and protected data.
set -euo pipefail
[[ ${PEIOS_OFFLINE_VM_PROOF:-} == yes ]] || exit 2
export PATH=/lcl/radius-dev/current/bin:$PATH
export LD_LIBRARY_PATH=/lcl/radius-dev/current/lib
for service in authd lpsd radiusd; do
    status=$(svctl status "$service")
    [[ $status == *"$service: active"* ]]
done
snapshot() {
    cat /lcl/etc/machine-id
    lps domain
    lps show radius-dev-proof
    lps group list
    reg get Machine/Software/RadiusDevProof Marker
    reg get Machine/Software/Radius/Networks/proof ConnectSecurity
    sha256sum /var/state/lpsd/principals /var/state/radius/secrets/*
}
case ${1:-} in
save)
    mkdir /var/state/dev-vm-proof
    snapshot > /var/state/dev-vm-proof/before
    echo 'RADIUS DEV VM: baseline saved'
    ;;
check)
    snapshot > /run/dev-vm-proof-after
    [[ $(sha256sum < /var/state/dev-vm-proof/before) == $(sha256sum < /run/dev-vm-proof-after) ]]
    echo 'PASS RADIUS DEV VM: identity, account, groups, policy, credentials and configuration preserved'
    ;;
*) exit 2 ;;
esac
