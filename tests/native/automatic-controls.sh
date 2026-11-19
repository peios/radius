#!/bin/bash
set -euo pipefail
[[ ${PEIOS_DISPOSABLE_RADIUS_TEST:-} == yes && ${RADIUS_DEV_RUNTIME:-} == 1 ]]
export PATH=/lcl/radius-dev/current/bin:$PATH LD_LIBRARY_PATH=/lcl/radius-dev/current/lib
probe=/mnt/dev/bin/native-session-controls
policy=22222222-2222-4222-8222-222222222222
profile=55555555-5555-4555-8555-555555555555
root=Machine/Software/Radius
radius config set DynamicAuthorizationIntervalSeconds=1
radius policy set "$policy" --set 'SessionControl={"vlan_disconnect":true,"revoke_access":true,"password_reauthenticate":true,"fallback":["disconnect"]}'
sleep 2
"$probe" automatic-disconnect > /run/automatic-vlan-result & listener=$!
reg set "$root/AccessProfiles/$profile" VlanId dword:30
wait "$listener"
cat /run/automatic-vlan-result
radius access-profile set "$profile" --set VlanId=20
sleep 2
"$probe" automatic-disconnect > /run/automatic-disabled-result & listener=$!
lps disable dev-radius
wait "$listener"
cat /run/automatic-disabled-result
lps enable dev-radius
sleep 2
"$probe" automatic-disconnect > /run/automatic-password-result & listener=$!
printf 'development-only-password\ndevelopment-only-password\n' | lps password dev-radius
wait "$listener"
cat /run/automatic-password-result
radius policy set "$policy" --set 'SessionControl={"vlan_disconnect":false,"revoke_access":false,"password_reauthenticate":false,"update_authorization":true}'
sleep 2
"$probe" automatic-update > /run/automatic-update-result & listener=$!
reg set "$root/AccessProfiles/$profile" VlanId dword:30
wait "$listener"
cat /run/automatic-update-result
radius policy set "$policy" --set Name=Renamed
sleep 2
echo 'PASS NATIVE CONTROLS: activated direct Registry VLAN edit, account disable, password replacement fallback and opt-in authorization update'
