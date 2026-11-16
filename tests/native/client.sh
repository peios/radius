#!/bin/bash
# Independent OpenSSL-backed supplicant inside the disposable guest. Only
# qualification markers reach the console; its full output can contain keys.
set -euo pipefail
[[ ${PEIOS_DISPOSABLE_RADIUS_TEST:-} == yes ]] || exit 2
name=${1:?case name}
tls=${2:-1.2}
user=${3:-dev-radius}
password=${4:-development-only-password}
expected=${5:-accept}
ssid=${6:-Home}
export LD_LIBRARY_PATH=/lcl/lib
phase='tls_disable_tlsv1_3=1'
if [[ $tls == 1.3 ]]; then phase='tls_disable_tlsv1_2=1 tls_disable_tlsv1_3=0'; fi
umask 077
config=/run/radiusd/supplicant.conf
output=/run/radiusd/supplicant.output
trap 'rm -f "$config" "$output"' EXIT
cat >"$config" <<EOF
network={
    key_mgmt=IEEE8021X
    eap=TTLS
    identity="$user"
    anonymous_identity="anonymous"
    password="$password"
    ca_cert="/mnt/dev/credentials/root.pem"
    domain_suffix_match="radius.test"
    phase1="$phase"
    phase2="auth=PAP"
    fragment_size=128
}
EOF
secret=$(</mnt/dev/credentials/secret)
status=0
/mnt/dev/bin/eapol_test -c "$config" -a 127.0.0.1 -p 18120 -s "$secret" -t 8 -r 0 \
    -N "30:s:aa-bb-cc-dd-ee-ff:$ssid" >"$output" 2>&1 || status=$?
success=no
keys=no
version=no
failed=no
while IFS= read -r line; do
    [[ $line == SUCCESS ]] && success=yes
    [[ $line == *'MPPE keys OK: 1  mismatch: 0'* ]] && keys=yes
    [[ $line == *"TLSv$tls"* ]] && version=yes
    [[ $line == *'EAP authentication failed'* ]] && failed=yes
done <"$output"
if [[ $expected == accept ]]; then
    [[ $status == 0 && $success == yes && $keys == yes && $version == yes ]]
elif [[ $expected == reject ]]; then
    [[ $status != 0 && $success == no && $failed == yes ]]
elif [[ $expected == drop ]]; then
    [[ $status != 0 && $success == no ]]
else
    exit 2
fi
rm -f "$config" "$output"
printf 'PASS NATIVE RADIUS: %s\n' "$name"
