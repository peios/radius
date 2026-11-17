#!/bin/bash
# Fixture only: replaces machine authentication policy in a disposable guest.
set -euo pipefail
[[ ${PEIOS_DISPOSABLE_RADIUS_TEST:-} == yes ]] || { echo 'Requires a fresh disposable guest.' >&2; exit 2; }
runtime=/lcl
daemon_dir=/lcl/sbin
if [[ ${RADIUS_DEV_RUNTIME:-0} == 1 ]]; then
    runtime=/lcl/radius-dev/current
    daemon_dir=$runtime/bin
fi
export PATH=$runtime/bin:$PATH LD_LIBRARY_PATH=$runtime/lib
policy=Machine/Generic/Authn/Policy
radius_sid=S-1-5-80-1653768611-2164381495-1902105107-3452022516-881820819
lpsd_sid=S-1-5-80-4242895835-3884168475-4287610261-1596539771-2019494472
auth_cap=S-1-15-3-815189116-3587081081-2225730562-134748649-517842195-1560836879-2444240241-858498395
logon_cap=S-1-15-3-2664559683-3984555773-3951455780-2774143311-388146908-3231209892-793332285-791810559
reg new -p Machine/Software/Authd/Sources/lpsd
reg set Machine/Software/Authd/Sources/lpsd MayAssertForeignMemberships dword:1
reg set Machine/Software/Authd/Sources/lpsd UnixIDBase dword:1000000
reg set Machine/Software/Authd/Sources/lpsd UnixIDCount dword:1000000
reg set -p "$policy/Everyone" Privileges multi:SeChangeNotifyPrivilege
reg set -p "$policy/$lpsd_sid" Privileges multi:SeChangeNotifyPrivilege,SeAuditPrivilege
reg set "$policy/$lpsd_sid" Integrity sz:System
reg set -p "$policy/$radius_sid" Capabilities multi:peios.auth.authenticate
reg set "$policy/$radius_sid" Privileges multi:SeChangeNotifyPrivilege,SeAuditPrivilege
reg set "$policy" AuthenticationSecurity "sz:O:SYG:SYD:(A;;0xf;;;SY)(A;;0x1;;;${auth_cap})(A;;0x2;;;${logon_cap})(A;;0xc;;;${radius_sid})"
mkdir -p /var/state/lpsd /var/state/radius/secrets
sd set /var/state/lpsd "O:${lpsd_sid}G:${lpsd_sid}D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;${lpsd_sid})"
sd set /var/state/radius "O:SYG:SYD:P(A;OICI;GA;;;SY)(A;OICI;GRGX;;;${radius_sid})"
sd set /var/state/radius/secrets "O:SYG:SYD:P(A;OICI;GA;;;SY)(A;OICI;GRGX;;;${radius_sid})"
for name in secret server.der intermediate.der key.der; do
    cp "/mnt/dev/credentials/$name" "/var/state/radius/secrets/$name"
done
svctl definition create authd --set ImagePath=/bin/bash --set Arguments=-c \
    --set "Arguments=export LD_LIBRARY_PATH=$runtime/lib; exec $daemon_dir/authd >/run/authd.log 2>&1" \
    --set Identity=SYSTEM --set Readiness=Notify --set Provides=authn \
    --set RequiredPrivileges=SeChangeNotifyPrivilege --set RequiredPrivileges=SeCreateTokenPrivilege \
    --set RequiredPrivileges=SeTcbPrivilege --set RequiredPrivileges=SeRestorePrivilege --set RequiredPrivileges=SeAuditPrivilege
svctl definition create lpsd --set ImagePath=/bin/bash --set Arguments=-c \
    --set "Arguments=export LD_LIBRARY_PATH=$runtime/lib; exec $daemon_dir/lpsd" --set Identity=Service \
    --set RuntimeDirectories=lpsd --set Requires=authd --set Readiness=Notify \
    --set RequiredPrivileges=SeChangeNotifyPrivilege --set RequiredPrivileges=SeAuditPrivilege
svctl start lpsd
printf 'development-only-password\ndevelopment-only-password\n' | lps add dev-radius --home /home/dev-radius --shell /bin/bash
printf 'development-only-password\ndevelopment-only-password\n' | lps add dev-disabled --disabled --shell /bin/bash
lps add dev-none --no-password --no-prompt --shell /bin/bash
lps group create household
lps group add dev-radius household
lps claim set dev-radius Department string Engineering
group_sid=
group_listing=$(lps group list)
while read -r name _rid _gid _members sid _description; do
    if [[ $name == household ]]; then group_sid=$sid; fi
done <<< "$group_listing"
[[ $group_sid == S-1-* ]] || { echo 'Missing fixture group SID.' >&2; exit 1; }
root=Machine/Software/Radius
reg new -p "$root/Settings"
reg set "$root/Settings" SchemaVersion dword:3
reg new -p "$root/AuthenticationProfiles/33333333-3333-4333-8333-333333333333"
reg set "$root/AuthenticationProfiles/33333333-3333-4333-8333-333333333333" Name sz:Passwords
reg set "$root/AuthenticationProfiles/33333333-3333-4333-8333-333333333333" Enabled dword:1
reg set "$root/AuthenticationProfiles/33333333-3333-4333-8333-333333333333" AuthenticationMethods multi:ttls-pap
reg set "$root/AuthenticationProfiles/33333333-3333-4333-8333-333333333333" ServerIdentity sz:44444444-4444-4444-8444-444444444444
reg new -p "$root/ServerIdentities/44444444-4444-4444-8444-444444444444"
reg new -p "$root/Clients/11111111-1111-4111-8111-111111111111"
reg new -p "$root/AccessPolicies/22222222-2222-4222-8222-222222222222"
reg set "$root/Clients/11111111-1111-4111-8111-111111111111" Name sz:APs
reg set "$root/Clients/11111111-1111-4111-8111-111111111111" Enabled dword:1
reg set "$root/AccessPolicies/22222222-2222-4222-8222-222222222222" Name sz:Home
reg set "$root/AccessPolicies/22222222-2222-4222-8222-222222222222" Enabled dword:1
reg set "$root/AccessPolicies/22222222-2222-4222-8222-222222222222" ReauthenticateSeconds dword:3600
reg set "$root/AccessPolicies/22222222-2222-4222-8222-222222222222" AuthenticationProfile sz:33333333-3333-4333-8333-333333333333
reg set "$root/ServerIdentities/44444444-4444-4444-8444-444444444444" Name sz:Default
reg set "$root/Settings" Listen multi:0.0.0.0:18120
reg set "$root/Settings" FragmentBytes dword:128
reg set "$root/ServerIdentities/44444444-4444-4444-8444-444444444444" CertificateFiles multi:/var/state/radius/secrets/server.der,/var/state/radius/secrets/intermediate.der
reg set "$root/ServerIdentities/44444444-4444-4444-8444-444444444444" PrivateKeyFile sz:/var/state/radius/secrets/key.der
reg set "$root/Clients/11111111-1111-4111-8111-111111111111" Addresses multi:10.0.2.0/24,127.0.0.1
reg set "$root/Clients/11111111-1111-4111-8111-111111111111" SecretFile sz:/var/state/radius/secrets/secret
reg set "$root/Clients/11111111-1111-4111-8111-111111111111" Policies multi:22222222-2222-4222-8222-222222222222
reg set "$root/AccessPolicies/22222222-2222-4222-8222-222222222222" SSID sz:Home
reg set "$root/AccessPolicies/22222222-2222-4222-8222-222222222222" ConnectSecurity "sz:O:SYG:SYD:(A;;0x1;;;${group_sid})"
# Explicit default assignment preserves the existing no-VLAN behavior.
access_profile=$root/AccessProfiles/55555555-5555-4555-8555-555555555555
assignment_rule=$root/AccessPolicies/22222222-2222-4222-8222-222222222222/Rules/66666666-6666-4666-8666-666666666666
reg new -p "$access_profile"
reg set "$access_profile" Name sz:Default
reg set "$access_profile" Enabled dword:1
reg new -p "$assignment_rule"
reg set "$assignment_rule" Name sz:Default
reg set "$assignment_rule" Actions 'multi:ASSIGN(55555555-5555-4555-8555-555555555555)'
# A fresh fixture image can have no port table. The required default is
# SYSTEM-only; radiusd receives PORT_BIND only for its explicit test UDP port.
# These self-relative SDs encode O:SYG:SYD:(A;;GA;;;SY) and the same
# descriptor plus (A;;0x1;;;radius_sid), respectively.
ports=Machine/System/Network/TcpIp/PortReservations
reg new -p "$ports"
reg set "$ports" @ hex:010004801400000020000000000000002c00000001010000000000051200000001010000000000051200000002001c00010000000000140000000010010100000000000512000000
reg set "$ports" udp:18120 hex:010004801400000020000000000000002c00000001010000000000051200000001010000000000051200000002004400020000000000280001000000010600000000000550000000a381926237d7018113d25f71f4aec1cd93848f340000140000000010010100000000000512000000
# Registry administration remains SYSTEM-only; radiusd receives read rights.
for key in "$root/AccessProfiles" "$access_profile" "$root/AccessPolicies/22222222-2222-4222-8222-222222222222/Rules" "$assignment_rule" "$root" "$root/Settings" "$root/ServerIdentities/44444444-4444-4444-8444-444444444444" "$root/Clients" "$root/Clients/11111111-1111-4111-8111-111111111111" "$root/AccessPolicies" "$root/AuthenticationProfiles" "$root/AuthenticationProfiles/33333333-3333-4333-8333-333333333333" "$root/ServerIdentities" "$root/AccessPolicies/22222222-2222-4222-8222-222222222222"; do
    reg sd "$key" --set "O:SYG:SYD:P(A;OICI;GA;;;SY)(A;OICI;GR;;;${radius_sid})"
done
svctl definition create radiusd --set ImagePath=/bin/bash --set Arguments=-c \
    --set "Arguments=export LD_LIBRARY_PATH=$runtime/lib; exec $daemon_dir/radiusd >/run/radiusd/output 2>&1" \
    --set Identity=Service --set RuntimeDirectories=radiusd --set Requires=lpsd --set Readiness=Notify \
    --set RequiredPrivileges=SeChangeNotifyPrivilege --set RequiredPrivileges=SeAuditPrivilege
mkdir -p /var/state/radius/credentials
sd set /var/state/radius/credentials "O:SYG:SYD:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GRGX;;;${radius_sid})"
svctl start radiusd
status=$(svctl status radiusd)
[[ $status == *'radiusd: active'* ]] || { echo 'radiusd did not reach readiness' >&2; exit 1; }
echo 'NATIVE RADIUS: service ready'
