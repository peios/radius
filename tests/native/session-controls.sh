#!/bin/bash
set -euo pipefail
[[ ${PEIOS_DISPOSABLE_RADIUS_TEST:-} == yes && ${RADIUS_DEV_RUNTIME:-} == 1 ]]
export PATH=/lcl/radius-dev/current/bin:$PATH LD_LIBRARY_PATH=/lcl/radius-dev/current/lib
root=Machine/Software/Radius
[[ ! -e /var/state/radius/accounting/ledger.db ]]
sid=S-1-5-80-1653768611-2164381495-1902105107-3452022516-881820819
probe=/mnt/dev/bin/native-session-controls
client() { bash /mnt/dev/native/client.sh "$@"; }
# setup.sh initially uses the qualified v6 source, so upgrade real persisted
# accounts instead of only qualifying a newly created v7 store.
svctl stop radiusd
if [[ ${RADIUS_QUALIFY_LEGACY_STORE:-0} == 1 ]]; then
    svctl stop lpsd
    cp -a /var/state/lpsd/principals /var/state/lpsd/principals-v6-before
    svctl definition edit lpsd --unset Arguments --set Arguments=-c \
        --set 'Arguments=export LD_LIBRARY_PATH=/lcl/radius-dev/current/lib; exec /lcl/radius-dev/current/bin/lpsd'
    svctl start lpsd
fi
"$probe" binding /run/binding-baseline save
svctl restart lpsd
"$probe" binding /run/binding-baseline same
echo 'PASS NATIVE CONTROLS: credential reference survives source restart'
lps policy dev-radius key
"$probe" binding /run/binding-baseline empty
lps policy dev-radius password
"$probe" binding /run/binding-baseline same
reg set -p Machine/Software/Lpsd StoreNtHashes dword:0
sleep 1
"$probe" binding /run/binding-baseline same
reg set Machine/Software/Lpsd StoreNtHashes dword:1
printf 'replacement-fixture-password\nreplacement-fixture-password\n' | lps password dev-radius
"$probe" binding /run/binding-baseline changed
printf 'development-only-password\ndevelopment-only-password\n' | lps password dev-radius
"$probe" binding /run/binding-baseline changed
radius accounting init
sd allow /var/state "$sid:0x80" --flags none
radius config set AccountingEnabled=1 AccountingListen=127.0.0.1:18130 AccountingBatchMilliseconds=100 DynamicAuthorizationEventHints=0
radius policy set 22222222-2222-4222-8222-222222222222 --set 'SessionControl={"vlan_disconnect":false,"revoke_access":false,"password_reauthenticate":false}'
radius access-profile set 55555555-5555-4555-8555-555555555555 --set VlanId=20
radius profile set 33333333-3333-4333-8333-333333333333 --set AuthenticationMethods=peap-mschapv2,ttls-pap
ports=Machine/System/Network/TcpIp/PortReservations
reg set "$ports" udp:18130 hex:010004801400000020000000000000002c00000001010000000000051200000001010000000000051200000002004400020000000000280001000000010600000000000550000000a381926237d7018113d25f71f4aec1cd93848f340000140000000010010100000000000512000000
"$probe" seed
svctl start radiusd
sleep 2
"$probe" start
"$probe" transport
reg set "$root/AccessPolicies/22222222-2222-4222-8222-222222222222" AccountingSecurity 'sz:O:SYG:SYD:(A;;0xff;;;SY)(A;;0xb;;;S-1-5-21-1-2-3-778)(A;;0x83;;;S-1-5-21-1-2-3-779)'
sleep 2
"$probe" scoped
radius policy set 22222222-2222-4222-8222-222222222222 --set 'SessionControl={"vlan_disconnect":false,"revoke_access":false,"password_reauthenticate":false,"fallback":["disconnect"]}'
sleep 2
"$probe" fallback
svctl restart radiusd
sleep 2
radius accounting sessions > /run/control-sessions-after
radius accounting rebuild --confirm
radius accounting sessions > /run/control-sessions-rebuilt
client accounting-peap 1.2 dev-radius development-only-password accept Home PEAP
client accounting-ttls12 1.2
client accounting-ttls13 1.3
client accounting-wrong-password 1.2 dev-radius wrong reject Home PEAP
/mnt/dev/bin/native-policy --ignored --test-threads=1
echo 'PASS NATIVE CONTROLS: native service, credential lifecycle, permissions, wire protocol, rebuild and real EAP qualification complete'
