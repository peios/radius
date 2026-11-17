#!/bin/bash
# Fresh, NIC-less guest only. Never use against an existing deployed machine.
set -euo pipefail
[[ ${PEIOS_DISPOSABLE_RADIUS_TEST:-} == yes ]] || exit 2
export PATH=/lcl/radius-dev/current/bin:$PATH
export LD_LIBRARY_PATH=/lcl/radius-dev/current/lib
root=Machine/Software/Radius
sid=S-1-5-80-1653768611-2164381495-1902105107-3452022516-881820819
[[ ! -e /var/state/radius/accounting ]]
if reg get "$root/Settings" >/dev/null 2>&1; then exit 2; fi
reg new -p Machine/Software
radius config init
radius accounting init
sd allow /var/state "$sid:0x80" --flags none
cp /mnt/dev/accounting/secret /var/state/radius/credentials/accounting-secret
sd set /var/state/radius/credentials/accounting-secret "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;${sid})"
client=$root/Clients/11111111-1111-4111-8111-111111111111
policy=$root/AccessPolicies/22222222-2222-4222-8222-222222222222
reg new -p "$client"
reg new -p "$policy"
reg set "$client" Name sz:Fixture
reg set "$client" Enabled dword:1
reg set "$client" Addresses multi:127.0.0.1
reg set "$client" SecretFile sz:/var/state/radius/credentials/accounting-secret
reg set "$client" Policies multi:22222222-2222-4222-8222-222222222222
reg set "$policy" Name sz:Accounting
reg set "$policy" Enabled dword:1
reg set "$policy" ServiceKind sz:accounting-only
radius config set AccountingEnabled=1 AccountingListen=127.0.0.1:18130 AccountingBatchMilliseconds=100
ports=Machine/System/Network/TcpIp/PortReservations
reg new -p "$ports"
reg set "$ports" @ hex:010004801400000020000000000000002c00000001010000000000051200000001010000000000051200000002001c00010000000000140000000010010100000000000512000000
for port in 1812 18130; do
    reg set "$ports" "udp:$port" hex:010004801400000020000000000000002c00000001010000000000051200000001010000000000051200000002004400020000000000280001000000010600000000000550000000a381926237d7018113d25f71f4aec1cd93848f340000140000000010010100000000000512000000
done
/mnt/dev/bin/native-accounting seed
reg set -p "Machine/Generic/Authn/Policy/$sid" Privileges multi:SeChangeNotifyPrivilege,SeAuditPrivilege
svctl definition create authd --set ImagePath=/bin/bash --set Arguments=-c \
    --set 'Arguments=export LD_LIBRARY_PATH=/lcl/radius-dev/current/lib; exec /lcl/radius-dev/current/bin/authd >/run/authd-output 2>&1' \
    --set Identity=SYSTEM --set Readiness=Notify --set Provides=authn \
    --set RequiredPrivileges=SeChangeNotifyPrivilege --set RequiredPrivileges=SeCreateTokenPrivilege \
    --set RequiredPrivileges=SeTcbPrivilege --set RequiredPrivileges=SeRestorePrivilege --set RequiredPrivileges=SeAuditPrivilege
svctl start authd
svctl definition create radiusd --set ImagePath=/bin/bash --set Arguments=-c \
    --set 'Arguments=export LD_LIBRARY_PATH=/lcl/radius-dev/current/lib; exec /lcl/radius-dev/current/bin/radiusd >/run/radiusd/output 2>&1' \
    --set Identity=Service --set RuntimeDirectories=radiusd --set Readiness=Notify \
    --set RequiredPrivileges=SeChangeNotifyPrivilege --set RequiredPrivileges=SeAuditPrivilege
svctl start radiusd
sleep 2
radius accounting status
for name in start retry unverified tampered; do
    /mnt/dev/bin/native-accounting udp "/mnt/dev/accounting/$name.request" "/mnt/dev/accounting/$name.response"
done
radius accounting sessions
/mnt/dev/bin/native-accounting authority
svctl restart radiusd
sleep 2
/mnt/dev/bin/native-accounting udp /mnt/dev/accounting/retry.request /mnt/dev/accounting/retry.response
radius accounting sessions
radius accounting rebuild --confirm
radius accounting sessions
radius config set AccountingSelfService=1
sleep 2
/mnt/dev/bin/native-accounting self
radius config set AccountingSelfService=0
reg set "$policy" AccountingSecurity 'sz:O:SYG:SYD:(A;;0x3f;;;SY)(A;;0x3f;;;BA)(A;;0x7;;;S-1-5-21-1-2-3-778)'
sleep 2
/mnt/dev/bin/native-accounting delegated
/mnt/dev/bin/native-accounting disconnect
svctl stop radiusd
mv /var/state/radius/accounting /var/state/radius/accounting-held
svctl start radiusd
sleep 2
/mnt/dev/bin/native-accounting udp /mnt/dev/accounting/start.request /mnt/dev/accounting/tampered.response
radius accounting status
mv /var/state/radius/accounting-held /var/state/radius/accounting
sleep 4
/mnt/dev/bin/native-accounting udp /mnt/dev/accounting/retry.request /mnt/dev/accounting/retry.response
echo 'PASS NATIVE ACCOUNTING: independent packets, durable retry after restart, replay and actual authority'
