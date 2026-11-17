#!/bin/bash
# Fresh administration setup, restoring the disposable fixture afterward.
set -euo pipefail
[[ ${PEIOS_DISPOSABLE_RADIUS_TEST:-} == yes ]] || exit 2
export PATH=/lcl/radius-dev/current/bin:$PATH LD_LIBRARY_PATH=/lcl/radius-dev/current/lib
lps show dev-radius >/dev/null
root=Machine/Software/Radius
snapshot=/run/radius-initialize-$$.backup
previous=/var/state/radius-initialize-$$
[[ -d /var/state/radius && ! -e $snapshot && ! -e $previous ]]
reg backup "$root" "$snapshot" >/dev/null
mv /var/state/radius "$previous"
restore() {
    reg del -r -y "$root" >/dev/null 2>&1 || true
    reg new -p "$root" >/dev/null
    reg restore -y "$root" "$snapshot" >/dev/null
    rm -rf /var/state/radius
    mv "$previous" /var/state/radius
    rm "$snapshot"
}
trap restore EXIT
reg del -r -y "$root" >/dev/null
radius config init >/dev/null
radius config check >/dev/null
before=$(radius --json config show)
[[ $before == *'"objects":[]'* && $before == *'"SchemaVersion":{"type":"number","value":3}'* ]]
if radius config init >/dev/null 2>&1; then
    echo 'Initialization unexpectedly replaced existing configuration' >&2
    exit 1
fi
[[ $(radius --json config show) == "$before" ]]
# The authority probe also needs an existing, protected fixture secret to test
# deny-only reads. It creates and removes its own administrator-owned secret.
cp -a "$previous/secrets" /var/state/radius/secrets
PEIOS_ADMIN_WRITABLE_FIXTURE=yes /mnt/dev/bin/native-authority
echo 'PASS RADIUS ADMIN: fresh initialization, protected directories, existing-config refusal, administrator edits'
