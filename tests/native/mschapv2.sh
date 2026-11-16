#!/bin/bash
# Run after setup.sh in a fresh disposable guest, with independent eapol_test.
set -euo pipefail
[[ ${PEIOS_DISPOSABLE_RADIUS_TEST:-} == yes ]] || exit 2
export PATH=/lcl/bin:$PATH LD_LIBRARY_PATH=/lcl/lib
if [[ ${RADIUS_DEV_RUNTIME:-0} == 1 ]]; then
    export PATH=/lcl/radius-dev/current/bin:$PATH LD_LIBRARY_PATH=/lcl/radius-dev/current/lib
fi
root=Machine/Software/Radius
client() { bash /mnt/dev/native/client.sh "$@"; }
peap() { client "$1" 1.2 "${2:-dev-radius}" "${3:-development-only-password}" "${4:-accept}" Home PEAP; }
present() {
    local expected=$1 _attempt detail
    for _attempt in {1..50}; do
        detail=$(lps show dev-radius)
        if [[ $detail == *"NT hash"*"$expected"* ]]; then return; fi
        sleep 0.1
    done
    echo "NT material did not become $expected" >&2
    exit 1
}
reg set "$root/AuthenticationProfiles/33333333-3333-4333-8333-333333333333" AuthenticationMethods multi:peap-mschapv2,ttls-pap
sleep 1
present present
peap peap-source-password
peap peap-username-case DEV-RADIUS
client ttls-negotiated-alternative 1.2
client ttls-tls13-alternative 1.3
peap peap-wrong-password dev-radius wrong reject
peap peap-unknown dev-unknown development-only-password reject
peap peap-disabled dev-disabled development-only-password reject
lps group remove dev-radius household
peap peap-no-network-admission dev-radius development-only-password reject
lps group add dev-radius household
lps policy dev-radius key
peap peap-password-policy-disabled dev-radius development-only-password reject
client pap-password-policy-disabled 1.2 dev-radius development-only-password reject
lps policy dev-radius password
peap peap-password-policy-restored

reg set -p Machine/Software/Lpsd StoreNtHashes dword:0
present absent
peap peap-storage-disabled dev-radius development-only-password reject
client pap-with-storage-disabled 1.2
present absent
reg set Machine/Software/Lpsd BackfillNtHashes dword:0
reg set Machine/Software/Lpsd StoreNtHashes dword:1
sleep 1
client pap-backfill-disabled 1.2
present absent
peap peap-missing-nt dev-radius development-only-password reject
reg set Machine/Software/Lpsd BackfillNtHashes dword:1
sleep 1
client pap-opportunistic-backfill 1.2
present present
peap peap-after-backfill

printf 'replacement-fixture-password\nreplacement-fixture-password\n' | lps password dev-radius
peap peap-old-password-rejected dev-radius development-only-password reject
peap peap-new-password dev-radius replacement-fixture-password
client pap-new-password 1.2 dev-radius replacement-fixture-password
printf 'development-only-password\ndevelopment-only-password\n' | lps password dev-radius
reg set Machine/Software/Lpsd StoreNtHashes sz:invalid
sleep 1
peap peap-invalid-storage-policy dev-radius development-only-password reject
client pap-with-invalid-legacy-policy 1.2
reg set Machine/Software/Lpsd StoreNtHashes dword:1
sleep 1
peap peap-policy-recovered

reg set "$root/AuthenticationProfiles/33333333-3333-4333-8333-333333333333" AuthenticationMethods multi:ttls-pap
sleep 1
peap peap-method-removed dev-radius development-only-password reject
client pap-after-peap-removal 1.2
reg set "$root/AuthenticationProfiles/33333333-3333-4333-8333-333333333333" AuthenticationMethods multi:peap-mschapv2,ttls-pap
sleep 1
peap peap-method-restored
echo 'NATIVE RADIUS: PEAP and NT lifecycle qualification passed'
