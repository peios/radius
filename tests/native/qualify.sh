#!/bin/bash
# Run only after setup.sh in the same fresh disposable guest.
set -euo pipefail
[[ ${PEIOS_DISPOSABLE_RADIUS_TEST:-} == yes ]] || exit 2
export PATH=/lcl/bin:$PATH LD_LIBRARY_PATH=/lcl/lib
if [[ ${RADIUS_DEV_RUNTIME:-0} == 1 ]]; then
    export PATH=/lcl/radius-dev/current/bin:$PATH LD_LIBRARY_PATH=/lcl/radius-dev/current/lib
fi
radius_sid=S-1-5-80-1653768611-2164381495-1902105107-3452022516-881820819
auth_cap=S-1-15-3-815189116-3587081081-2225730562-134748649-517842195-1560836879-2444240241-858498395
logon_cap=S-1-15-3-2664559683-3984555773-3951455780-2774143311-388146908-3231209892-793332285-791810559
policy=Machine/Generic/Authn/Policy
root=Machine/Software/Radius
client() { bash /mnt/dev/native/client.sh "$@"; }
group_sid=
listing=$(lps group list)
while read -r name _rid _gid _members sid rest; do
    [[ $name == household ]] && group_sid=$sid
done <<< "$listing"
[[ $group_sid == S-1-* ]] || exit 1
# Exercise the compiled default: disclosure is granted to radiusd, while its
# attested token still carries Authenticate only. This fixture changes machine
# policy solely inside this disposable VM, never on the developer's host.
reg del -y "$policy" AuthenticationSecurity
client default-tls12 1.2
client default-tls13 1.3
client wrong-password 1.2 dev-radius wrong reject
client disabled 1.2 dev-disabled development-only-password reject
client unknown 1.2 dev-unknown development-only-password reject
client no-credential 1.2 dev-none development-only-password reject
client wrong-ssid 1.2 dev-radius development-only-password drop Other
lps group remove dev-radius household
client removed-group 1.2 dev-radius development-only-password reject
lps group add dev-radius household
reg set "$root/Networks/home" ConnectSecurity "sz:O:SYG:SYD:(XA;;0x1;;;${group_sid};(@User.Department == \"Engineering\"))"
sleep 1
client disclosed-claim 1.2
# Explicit policy keeps Authenticate but withholds every claim. Hidden values
# must stay unknown; neither a positive nor a negative rule may grant access.
reg set "$policy" AuthenticationSecurity "sz:O:SYG:SYD:(A;;0xf;;;SY)(A;;0x1;;;${auth_cap})(A;;0x2;;;${logon_cap})(A;;0x4;;;${radius_sid})"
client restricted-positive-claim 1.2 dev-radius development-only-password reject
reg set "$root/Networks/home" ConnectSecurity "sz:O:SYG:SYD:(XA;;0x1;;;${group_sid};(!Exists @User.Secret))"
sleep 1
client restricted-negative-claim 1.2 dev-radius development-only-password reject
reg del -y "$policy" AuthenticationSecurity
client complete-known-absence 1.2
reg set "$root/Networks/home" ConnectSecurity "sz:O:SYG:SYD:(A;;0x1;;;${group_sid})S:(AU;SA;0x1;;;${group_sid})"
sleep 1
client audit-requirement 1.2 dev-radius development-only-password reject
reg set "$root/Networks/home" ConnectSecurity "sz:O:SYG:SYD:(A;;0x1;;;${group_sid})"
reg set "$root/Settings" MaxVerifications dword:0
sleep 1
client invalid-configuration 1.2 dev-radius development-only-password drop
reg set "$root/Settings" MaxVerifications dword:32
sleep 1
client recovered-configuration 1.2
# Prepare a new protected immutable secret file before publishing its reference.
cp /mnt/dev/credentials/rotated-secret /var/state/radius/secrets/rotated-secret
reg set "$root/Clients/aps" SecretFile sz:/var/state/radius/secrets/rotated-secret
sleep 1
client old-secret-after-rotation 1.2 dev-radius development-only-password drop
reg set "$root/Clients/aps" SecretFile sz:/var/state/radius/secrets/secret
sleep 1
client restored-secret 1.2
svctl stop lpsd
client unavailable-source 1.2 dev-radius development-only-password reject
svctl start lpsd
client recovered-source 1.2
echo 'NATIVE RADIUS: fixture sequence passed'
