#!/bin/bash
# Run only in an explicitly disposable qualification guest.
# The caller stages eventd and native-diagnostics alongside the raw RADIUS
# runtime. An explicit SYSTEM override isolates query tests when service-account
# ingestion is unavailable. It does not qualify normal deployment policy.
set -euo pipefail
export PEIOS_DISPOSABLE_RADIUS_TEST=yes RADIUS_DEV_RUNTIME=1
export PATH=/lcl/radius-dev/current/bin:$PATH
export LD_LIBRARY_PATH=/lcl/radius-dev/current/lib
if [[ ${RADIUS_DIAGNOSTICS_RESUME:-0} != 1 ]]; then bash /mnt/dev/native/setup.sh; fi
event_sid=S-1-5-80-1963885778-1835409261-1671587836-2279113866-1994761124
reg new -p Machine/System/eventd
for pair in EventStorePath:events LogStorePath:logs MetricStorePath:metrics; do
    reg set Machine/System/eventd "${pair%%:*}" "sz:/var/state/eventd/${pair#*:}"
done
for pair in QuerySocketPath:query LogSocketPath:log MetricSocketPath:metric; do
    reg set Machine/System/eventd "${pair%%:*}" "sz:/run/eventd/${pair#*:}.sock"
done
reg set -p "Machine/Generic/Authn/Policy/$event_sid" Privileges multi:SeChangeNotifyPrivilege,SeAuditPrivilege,SeSecurityPrivilege
reg set "Machine/Generic/Authn/Policy/$event_sid" Integrity sz:System
mkdir -p /var/state/eventd
sd set /var/state/eventd "O:SYG:SYD:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GA;;;$event_sid)"
mkdir -p /var/state/eventd/events /var/state/eventd/logs /var/state/eventd/metrics
for path in /var/state/eventd/events /var/state/eventd/logs /var/state/eventd/metrics; do
    sd set "$path" "O:SYG:SYD:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GA;;;$event_sid)"
done
eventd --prepare-security
if [[ ${RADIUS_DIAGNOSTICS_RESUME:-0} != 1 ]]; then
svctl definition create eventd --set ImagePath=/bin/bash --set Arguments=-c \
    --set 'Arguments=export LD_LIBRARY_PATH=/lcl/radius-dev/current/lib; exec /lcl/radius-dev/current/bin/eventd >/run/eventd/output 2>&1' \
    --set Identity=Service --set RuntimeDirectories=eventd --set Requires=authd --set Readiness=Notify \
    --set RequiredPrivileges=SeChangeNotifyPrivilege --set RequiredPrivileges=SeAuditPrivilege --set RequiredPrivileges=SeSecurityPrivilege
fi
identity=${RADIUS_DIAGNOSTICS_EVENTD_IDENTITY:-Service}
[[ $identity == Service || $identity == SYSTEM ]]
svctl definition edit eventd --set "Identity=$identity"
svctl start eventd
[[ $(svctl status eventd) == *'eventd: active'* ]]
svctl start lpsd
svctl start radiusd
bash /mnt/dev/native/client.sh diagnostics-ttls12 1.2
bash /mnt/dev/native/client.sh diagnostics-ttls13 1.3
bash /mnt/dev/native/client.sh diagnostics-wrong-password 1.2 dev-radius wrong reject
reg set Machine/Software/Radius/AuthenticationProfiles/33333333-3333-4333-8333-333333333333 AuthenticationMethods multi:peap-mschapv2,ttls-pap
sleep 1
bash /mnt/dev/native/client.sh diagnostics-peap 1.2 dev-radius development-only-password accept Home PEAP
sleep 2
/mnt/dev/bin/native-diagnostics
# Admission survives an unavailable history service and omitted stage records.
svctl stop eventd
bash /mnt/dev/native/client.sh diagnostics-eventd-unavailable 1.2
svctl start eventd
reg set Machine/Software/Radius/Settings DiagnosticsMaxStages dword:4
reg set Machine/Software/Radius/Settings DiagnosticsEventsPerSecond dword:1
sleep 1
bash /mnt/dev/native/client.sh diagnostics-budget-limited 1.2
echo 'PASS RADIUS DIAGNOSTICS: authentication unaffected by eventd outage and local emission bounds'
echo 'RADIUS_DIAGNOSTICS_GUEST_COMPLETE'
