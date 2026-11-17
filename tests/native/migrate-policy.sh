#!/bin/bash
# Schema migration qualification, only inside the disposable setup.sh guest.
set -euo pipefail
[[ ${PEIOS_DISPOSABLE_RADIUS_TEST:-} == yes ]] || exit 2
export PATH=/lcl/radius-dev/current/bin:$PATH LD_LIBRARY_PATH=/lcl/radius-dev/current/lib
export RADIUS_DEV_RUNTIME=1
root=Machine/Software/Radius
policy=22222222-2222-4222-8222-222222222222
snapshot=/run/radius-policy-migration.backup
output=/run/radius-policy-migration.output
[[ ! -e $snapshot ]]
umask 077
reg backup "$root" "$snapshot" >/dev/null
svctl stop radiusd >/dev/null
restore() {
    svctl stop radiusd >/dev/null 2>&1 || true
    reg del -r -y "$root" >/dev/null
    reg new -p "$root" >/dev/null
    reg restore -y "$root" "$snapshot" >/dev/null
    svctl start radiusd >/dev/null
    rm -f "$snapshot" "$output"
}
trap restore EXIT
reg del -r -y "$root/AccessProfiles" >/dev/null
reg del -r -y "$root/AccessPolicies/$policy/Rules" >/dev/null
reg set "$root/Settings" SchemaVersion dword:2 >/dev/null
before=$(radius --json config show)
/mnt/dev/bin/migrate-policy-v3 >"$output"
[[ $(radius --json config show) == "$before" ]]
echo 'PASS RADIUS MIGRATION: dry run leaves schema and objects unchanged'

# Refuse an existing structural container without committing the AccessProfiles
# container created earlier in the transaction.
reg new "$root/AccessPolicies/$policy/Rules" >/dev/null
if /mnt/dev/bin/migrate-policy-v3 --apply >"$output" 2>&1; then exit 1; fi
if reg ls "$root/AccessProfiles" >"$output" 2>&1; then exit 1; fi
[[ $(radius --json config show) == "$before" ]]
reg del -y "$root/AccessPolicies/$policy/Rules" >/dev/null
echo 'PASS RADIUS MIGRATION: conflicting container aborts the whole transaction'

/mnt/dev/bin/migrate-policy-v3 --apply >"$output"
radius config check >/dev/null
after=$(radius --json config show)
[[ $after == *'"SchemaVersion":{"type":"number","value":3}'* ]]
[[ $after != *'"VlanId"'* ]]
if /mnt/dev/bin/migrate-policy-v3 --apply >"$output" 2>&1; then exit 1; fi
[[ $(radius --json config show) == "$after" ]]
svctl start radiusd >/dev/null
sleep 2
bash /mnt/dev/native/client.sh migrated-default 1.2
echo 'PASS RADIUS MIGRATION: atomic explicit defaults, no VLAN override, rerun refusal and authentication'
