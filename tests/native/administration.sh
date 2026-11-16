#!/bin/bash
# Administration qualification after setup.sh in a fresh disposable guest.
set -euo pipefail
[[ ${PEIOS_DISPOSABLE_RADIUS_TEST:-} == yes ]] || exit 2
export PATH=/lcl/radius-dev/current/bin:$PATH LD_LIBRARY_PATH=/lcl/radius-dev/current/lib
export RADIUS_DEV_RUNTIME=1
root=Machine/Software/Radius
client_id=11111111-1111-4111-8111-111111111111
policy_id=22222222-2222-4222-8222-222222222222
profile_id=33333333-3333-4333-8333-333333333333
identity_id=44444444-4444-4444-8444-444444444444
umask 077
failure=/run/radiusd/admin-failure
trap 'rm -f "$failure"' EXIT
reject() { if "$@" >"$failure" 2>&1; then echo "Unexpected success: $1 $2" >&2; exit 1; fi; }
guid() { [[ $1 =~ \"id\":\"([0-9a-f-]{36})\" ]] || return 1; printf '%s' "${BASH_REMATCH[1]}"; }
state() { radius --json status; }
await_state() { local wanted=$1; for ((i=0;i<40;i++)); do local status; status=$(state); [[ $status == *"\"daemon\":\"$wanted\""* ]] && return; sleep 0.1; done; echo "Did not reach state $wanted" >&2; return 1; }
client() { bash /mnt/dev/native/client.sh "$@"; }
group_sid=
listing=$(lps group list)
while read -r name _rid _gid _members sid rest; do [[ $name != household ]] || group_sid=$sid; done <<< "$listing"
[[ $group_sid == S-1-* ]]
connect="O:SYG:SYD:(A;;0x1;;;${group_sid})"
await_state active
radius config check > /dev/null
reject radius config set MaxVerifications=0
reject radius config set Listen=127.0.0.1:0
radius config set IdleTimeoutSeconds=31 > /dev/null
radius config set IdleTimeoutSeconds=30 > /dev/null
radius policy set "$policy_id" --set Name=Household > /dev/null
[[ $(radius --json client show "$client_id") == *"$policy_id"* ]]
client admin-renamed-policy 1.2
echo 'PASS RADIUS ADMIN: rename preserves references and authentication'

alternate=$(radius --json profile create Alternate --set AuthenticationMethods=ttls-pap --set ServerIdentity="$identity_id")
alternate_id=$(guid "$alternate")
other=$(radius --json policy create Other --set SSID=Other --set AuthenticationProfile="$alternate_id" --set "ConnectSecurity=$connect")
other_id=$(guid "$other")
radius client set "$client_id" --set Policies="$policy_id,$other_id" > /dev/null
reject radius profile delete "$alternate_id"
reject radius policy delete "$other_id"
radius profile disable "$alternate_id" > /dev/null
sleep 1
client admin-disabled-profile-unrelated-policy 1.2
client admin-disabled-profile-denied 1.2 dev-radius development-only-password drop Other
radius profile enable "$alternate_id" > /dev/null
sleep 1
client admin-enabled-profile 1.2 dev-radius development-only-password accept Other
echo 'PASS RADIUS ADMIN: shared profiles, disabled isolation, reference deletion guard'

reject radius policy set "$policy_id" --set AuthenticationProfile=77777777-7777-4777-8777-777777777777
reg set "$root/AccessPolicies/$policy_id" AuthenticationProfile sz:77777777-7777-4777-8777-777777777777 > /dev/null
await_state invalid
[[ $(state) == *'77777777-7777-4777-8777-777777777777'* ]]
client admin-invalid-reference-paused 1.2 dev-radius development-only-password drop
radius policy set "$policy_id" --set AuthenticationProfile="$profile_id" > /dev/null
await_state active
client admin-reference-repaired 1.2
echo 'PASS RADIUS ADMIN: direct Registry inconsistency is diagnosed and repairable'

# A failed initial candidate must leave the management endpoint available.
reg set "$root/AccessPolicies/$policy_id" AuthenticationProfile sz:77777777-7777-4777-8777-777777777777 > /dev/null
await_state invalid
radius service restart > /dev/null
# The old process retains its effective fingerprint while invalid; a new one
# has never activated any configuration. Wait for that distinct startup state.
for ((i=0;i<80;i++)); do
    status=$(state)
    [[ $status == *'"daemon":"invalid"'* && $status == *'"effective_fingerprint":null'* ]] && break
    sleep 0.1
done
[[ $status == *'"daemon":"invalid"'* && $status == *'"effective_fingerprint":null'* ]]
[[ $(state) == *'77777777-7777-4777-8777-777777777777'* ]]
radius policy set "$policy_id" --set AuthenticationProfile="$profile_id" > /dev/null
await_state active
client admin-invalid-start-repaired 1.2
echo 'PASS RADIUS ADMIN: invalid startup remains locally diagnosable and repairable'

generated=$(radius --json client create Generated --set Addresses=192.0.2.1 --set Policies="$policy_id")
generated_id=$(guid "$generated")
secret=$(radius client secret "$generated_id" show)
[[ ${#secret} == 48 && $generated != *"$secret"* ]]
radius client secret "$generated_id" generate > /dev/null
replacement=$(radius client secret "$generated_id" show)
[[ ${#replacement} == 48 && $secret != "$replacement" ]]
unset secret replacement
radius client delete "$generated_id" > /dev/null
echo 'PASS RADIUS ADMIN: generated and replaced secrets are explicit-only output'

imported=$(radius --json identity create Imported --set CertificateFiles=/mnt/dev/credentials/server.pem,/mnt/dev/credentials/intermediate.pem --set PrivateKeyFile=/mnt/dev/credentials/server.key)
imported_id=$(guid "$imported")
[[ $(radius --json identity inspect "$imported_id") == *radius.test* ]]
before=$(ls -1 /var/state/radius/credentials | wc -l)
reject radius identity import "$imported_id" --set CertificateFiles=/mnt/dev/credentials/server.pem --set PrivateKeyFile=/mnt/dev/credentials/secret
after=$(ls -1 /var/state/radius/credentials | wc -l)
[[ $before == "$after" ]]
radius identity delete "$imported_id" > /dev/null
echo 'PASS RADIUS ADMIN: PEM import, certificate inspection, invalid replacement preservation'

radius client set "$client_id" --set Policies="$policy_id" > /dev/null
radius policy delete "$other_id" > /dev/null
radius profile delete "$alternate_id" > /dev/null
radius service boot off > /dev/null
[[ $(state) == *'"start_at_boot":false'* ]]
radius service boot on > /dev/null
radius service stop > /dev/null
await_state stopped
radius policy set "$policy_id" --set ReauthenticateSeconds=2400 > /dev/null
radius service start > /dev/null
await_state active
client admin-stopped-edit-restarted 1.2
radius policy set "$policy_id" --set ReauthenticateSeconds=3600 > /dev/null
echo 'PASS RADIUS ADMIN: stopped-daemon editing and separate boot/service state'

PEIOS_DISPOSABLE_RADIUS_TEST=yes /mnt/dev/bin/native-authority
echo 'NATIVE RADIUS: administration qualification passed'
