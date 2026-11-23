#!/bin/bash
# Run after setup.sh in a fresh offline disposable guest.
set -euo pipefail
[[ ${PEIOS_DISPOSABLE_RADIUS_TEST:-} == yes && ${RADIUS_DEV_RUNTIME:-} == 1 ]] || exit 2
export PATH=/lcl/radius-dev/current/bin:$PATH LD_LIBRARY_PATH=/lcl/radius-dev/current/lib
root=Machine/Software/Radius
profile=55555555-5555-4555-8555-555555555555
policy=22222222-2222-4222-8222-222222222222
client_id=11111111-1111-4111-8111-111111111111
umask 077
facts=/run/radiusd/richer-facts.json
failure=/run/radiusd/richer-failure
trap 'rm -f "$facts" "$failure"' EXIT
reject() { if "$@" >"$failure" 2>&1; then echo "Unexpected success: $1 $2" >&2; exit 1; fi; }
await_state() { local wanted=$1 status; for ((i=0;i<80;i++)); do status=$(radius --json status); [[ $status == *"\"daemon\":\"$wanted\""* ]] && return; sleep 0.1; done; echo "Expected $wanted" >&2; return 1; }
client() { bash /mnt/dev/native/client.sh "$@"; }
guid() { [[ $1 =~ \"id\":\"([0-9a-f-]{36})\" ]] || return 1; printf '%s' "${BASH_REMATCH[1]}"; }
await_state active
reg new -p "$root/DynamicAuthorizationProfiles"
template=$(radius --json dynamic-profile template wispr)
equipment=$(radius --json dynamic-profile create "Synthetic WISPr" --set "Definition=$template")
equipment_id=$(guid "$equipment")
radius client set "$client_id" --set "DynamicAuthorizationProfile=$equipment_id" >/dev/null
radius access-profile set "$profile" --set VlanId=20 \
    --set IdleTimeoutSeconds=120 --set SessionTimeoutSeconds=300 \
    --set DownloadBitsPerSecond=10000000 --set UploadBitsPerSecond=2000000 \
    --set AccountingInterimSeconds=60 \
    --set 'FilterRules=["permit in 6 from any to assigned 80,443"]' >/dev/null
printf '{"values":{"Client.Id":[{"type":"string","value":"%s"}]},"claim_coverage":"filtered"}\n' "$client_id" >"$facts"
result=$(radius --json policy explain "$policy" --facts "$facts")
[[ $result == *'"state":"encoded"'* && $result == *'"enforcement_verified":false'* && $result == *'"DownloadBitsPerSecond":10000000'* ]]
await_state active
client richer-ttls12 1.2
client richer-ttls13 1.3
client richer-wrong-password 1.2 dev-radius wrong reject
echo 'PASS RICHER PROFILES: actual Registry, equipment mapping, full selection, TLS and keys'

reject radius access-profile set "$profile" --set IdleTimeoutSeconds=0
reject radius access-profile set "$profile" --set ReauthenticateSeconds=600
reject radius access-profile set "$profile" --set FramedIpv6Prefix=2001:db8::1/64
reject radius access-profile set "$profile" --set 'Extensions={"State":"forged"}'
radius access-profile set "$profile" --set DownloadBitsPerSecond=18446744073709551615 >/dev/null
[[ $(radius --json access-profile show "$profile") == *'18446744073709551615'* ]]
result=$(radius --json policy explain "$policy" --facts "$facts")
[[ $result == *'"state":"unsupported-or-invalid"'* ]]
client richer-overflow-refused 1.2 dev-radius development-only-password reject
radius access-profile set "$profile" --set DownloadBitsPerSecond=10000000 >/dev/null
sleep 1
client richer-overflow-recovered 1.2
echo 'PASS RICHER PROFILES: exact u64 storage and incompatible equipment range refuse admission'

# A direct Registry edit bypasses the form but never the loader's type check.
reg set "$root/AccessProfiles/$profile" IdleTimeoutSeconds sz:120
await_state invalid
client richer-wrong-registry-type 1.2 dev-radius development-only-password drop
reg set "$root/AccessProfiles/$profile" IdleTimeoutSeconds dword:120
await_state active
radius access-profile unset "$profile" DownloadBitsPerSecond >/dev/null
radius access-profile unset "$profile" UploadBitsPerSecond >/dev/null
radius access-profile unset "$profile" SessionTimeoutSeconds >/dev/null
radius access-profile unset "$profile" VlanId >/dev/null
await_state active
svctl restart radiusd
await_state active
client richer-restart-and-clear 1.2
/mnt/dev/bin/native-policy --ignored --test-threads=1
echo 'RADIUS_RICHER_PROFILES_GUEST_COMPLETE'
