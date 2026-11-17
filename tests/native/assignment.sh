#!/bin/bash
# Run after setup.sh in a fresh disposable guest, never on the deployed VM.
set -euo pipefail
[[ ${PEIOS_DISPOSABLE_RADIUS_TEST:-} == yes ]] || exit 2
export PATH=/lcl/radius-dev/current/bin:$PATH LD_LIBRARY_PATH=/lcl/radius-dev/current/lib
export RADIUS_DEV_RUNTIME=1
root=Machine/Software/Radius
policy=22222222-2222-4222-8222-222222222222
profile=55555555-5555-4555-8555-555555555555
default=66666666-6666-4666-8666-666666666666
facts=/run/radiusd/assignment-facts.json
failure=/run/radiusd/assignment-failure
umask 077
trap 'rm -f "$facts" "$failure"' EXIT
printf '{"values":{},"claim_coverage":"filtered"}\n' > "$facts"
reject() { if "$@" >"$failure" 2>&1; then echo "Unexpected success: $1 $2" >&2; exit 1; fi; }
guid() { [[ $1 =~ \"id\":\"([0-9a-f-]{36})\" ]] || return 1; printf '%s' "${BASH_REMATCH[1]}"; }
await_state() { local wanted=$1 status; for ((i=0;i<60;i++)); do status=$(radius --json status); [[ $status == *"\"daemon\":\"$wanted\""* ]] && return; sleep 0.1; done; echo "Expected $wanted" >&2; return 1; }
client() { bash /mnt/dev/native/client.sh "$@"; }
await_state active
radius access-profile set "$profile" --set VlanId=20 >/dev/null
sleep 1
await_state active
result=$(radius --json policy explain "$policy" --facts "$facts")
[[ $result == *'"vlan":20'* && $result == *'"hypothetical":true'* && $result == *'"full_admission_checked":false'* ]]
client assignment-vlan-tls12 1.2
client assignment-vlan-tls13 1.3
reject radius access-profile set "$profile" --set VlanId=0
radius access-profile unset "$profile" VlanId >/dev/null
sleep 1
await_state active
[[ $(radius --json policy explain "$policy" --facts "$facts") == *'"vlan":null'* ]]
client assignment-no-override 1.2
echo 'PASS RADIUS ASSIGNMENT: native selection, VLAN success, unset and typed validation'

other=$(radius --json access-profile create Other --set VlanId=30)
other_id=$(guid "$other")
conflict=$(radius --json rule create Conflict --set Policy="$policy" --set "Actions=ASSIGN($other_id)")
conflict_id=$(guid "$conflict")
sleep 1
await_state active
[[ $(radius --json policy explain "$policy" --facts "$facts") == *conflicting-profiles* ]]
client assignment-conflict 1.2 dev-radius development-only-password reject
reject radius access-profile delete "$other_id"
radius rule set "$default" --set Priority=1 >/dev/null
sleep 1
client assignment-priority 1.2
radius rule unset "$default" Priority >/dev/null
radius rule delete "$conflict_id" >/dev/null
radius access-profile delete "$other_id" >/dev/null
sleep 1
client assignment-conflict-recovered 1.2
echo 'PASS RADIUS ASSIGNMENT: conflicts affect attempts, priorities and deletion guards'

child=$(radius --json rule create Exception --set Policy="$policy" --set Parent="$default" --set Actions=REJECT)
child_id=$(guid "$child")
sleep 1
client assignment-exception 1.2 dev-radius development-only-password reject
reject radius rule delete "$default"
reg set "$root/AccessPolicies/$policy/Rules/$default/$child_id" Subject.Typo.Equal sz:bad >/dev/null
await_state invalid
radius rule unset "$child_id" Subject.Typo.Equal >/dev/null
await_state active
radius rule delete "$child_id" >/dev/null
sleep 1
client assignment-repaired-condition 1.2
echo 'PASS RADIUS ASSIGNMENT: nested exceptions and malformed direct edits are repairable'

radius rule set "$default" --set Actions=NULL >/dev/null
absent=$(radius --json rule create KnownAbsence --set Policy="$policy" --set Parent="$default" \
    --set Subject.Claim.Secret.Boolean.Present=0 --set "Actions=ASSIGN($profile)")
absent_id=$(guid "$absent")
sleep 1
client assignment-known-absence 1.2
auth_policy=Machine/Generic/Authn/Policy
radius_sid=S-1-5-80-1653768611-2164381495-1902105107-3452022516-881820819
auth_cap=S-1-15-3-815189116-3587081081-2225730562-134748649-517842195-1560836879-2444240241-858498395
logon_cap=S-1-15-3-2664559683-3984555773-3951455780-2774143311-388146908-3231209892-793332285-791810559
reg set "$auth_policy" AuthenticationSecurity "sz:O:SYG:SYD:(A;;0xf;;;SY)(A;;0x1;;;${auth_cap})(A;;0x2;;;${logon_cap})(A;;0x4;;;${radius_sid})" >/dev/null
client assignment-withheld-is-unknown 1.2 dev-radius development-only-password reject
reg set "$auth_policy" AuthenticationSecurity "sz:O:SYG:SYD:(A;;0xf;;;SY)(A;;0x1;;;${auth_cap})(A;;0x2;;;${logon_cap})(A;;0xc;;;${radius_sid})" >/dev/null
radius rule set "$default" --set "Actions=ASSIGN($profile)" >/dev/null
radius rule delete "$absent_id" >/dev/null
sleep 1
client assignment-disclosure-restored 1.2
echo 'NATIVE RADIUS: assignment qualification passed'
