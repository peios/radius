#!/bin/bash
# Qualification fixture ONLY: a newly initialized offline development VM.
# This is not the provisioning script for a real UniFi deployment.
set -euo pipefail
[[ ${PEIOS_OFFLINE_VM_PROOF:-} == yes ]] || exit 2
[[ $(cat /mnt/state/layout) == radius-dev-state-v1 ]] || exit 2
export PATH=/lcl/radius-dev/current/bin:$PATH
export LD_LIBRARY_PATH=/lcl/radius-dev/current/lib
[[ ! -e /var/state/lpsd/principals ]] || { echo 'proof requires an unprovisioned account store' >&2; exit 1; }
if reg get Machine/Generic/Authn/Policy >/dev/null 2>&1; then
    echo 'proof refuses to replace existing authentication policy' >&2
    exit 1
fi
reg apply -y /mnt/dev/proof-policy/authd-policy.reg
reg apply -y /mnt/dev/proof-policy/lpsd-authd-registration.reg
lpsd_sid=S-1-5-80-4242895835-3884168475-4287610261-1596539771-2019494472
radius_sid=S-1-5-80-1653768611-2164381495-1902105107-3452022516-881820819
mkdir -p /var/state/lpsd /var/state/radius/secrets
sd set /var/state/lpsd "O:${lpsd_sid}G:${lpsd_sid}D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;${lpsd_sid})"
sd set /var/state/radius "O:SYG:SYD:P(A;OICI;GA;;;SY)(A;OICI;GRGX;;;${radius_sid})"
sd set /var/state/radius/secrets "O:SYG:SYD:P(A;OICI;GA;;;SY)(A;OICI;GRGX;;;${radius_sid})"
reg set -p "Machine/Generic/Authn/Policy/$radius_sid" Capabilities multi:peios.auth.authenticate
reg set "Machine/Generic/Authn/Policy/$radius_sid" Privileges multi:SeChangeNotifyPrivilege,SeAuditPrivilege
svctl definition create authd --set ImagePath=/bin/bash --set Arguments=-c \
    --set 'Arguments=export LD_LIBRARY_PATH=/lcl/radius-dev/current/lib; exec /lcl/radius-dev/current/bin/authd' \
    --set Identity=SYSTEM --set Readiness=Notify --set Provides=authn \
    --set RequiredPrivileges=SeChangeNotifyPrivilege --set RequiredPrivileges=SeCreateTokenPrivilege \
    --set RequiredPrivileges=SeTcbPrivilege --set RequiredPrivileges=SeRestorePrivilege --set RequiredPrivileges=SeAuditPrivilege
svctl definition create lpsd --set ImagePath=/bin/bash --set Arguments=-c \
    --set 'Arguments=export LD_LIBRARY_PATH=/lcl/radius-dev/current/lib; exec /lcl/radius-dev/current/bin/lpsd' \
    --set Identity=Service --set RuntimeDirectories=lpsd --set Requires=authd --set Readiness=Notify \
    --set Triggers=boot:settled --set RequiredPrivileges=SeChangeNotifyPrivilege --set RequiredPrivileges=SeAuditPrivilege
svctl start lpsd
printf 'offline-vm-proof-only\noffline-vm-proof-only\n' | lps add radius-dev-proof --shell /bin/bash
lps group create radius-dev-proof-group
lps group add radius-dev-proof radius-dev-proof-group
reg set -p Machine/Software/RadiusDevProof Marker sz:survives-reboot
for file in server.der intermediate.der key.der secret; do
    cp "/mnt/dev/proof-credentials/$file" "/var/state/radius/secrets/$file"
done
root=Machine/Software/Radius
reg new -p "$root/Settings"
reg new -p "$root/TLS"
reg new -p "$root/Clients/loopback"
reg new -p "$root/Networks/proof"
reg set "$root/Settings" Listen multi:127.0.0.1:18120
reg set "$root/TLS" CertificateFiles multi:/var/state/radius/secrets/server.der,/var/state/radius/secrets/intermediate.der
reg set "$root/TLS" PrivateKeyFile sz:/var/state/radius/secrets/key.der
reg set "$root/Clients/loopback" Addresses multi:127.0.0.1
reg set "$root/Clients/loopback" SecretFile sz:/var/state/radius/secrets/secret
reg set "$root/Clients/loopback" Networks multi:proof
reg set "$root/Networks/proof" SSID sz:OfflineProof
reg set "$root/Networks/proof" ConnectSecurity 'sz:O:SYG:SYD:'
# The proof tests service readiness/restart, not network admission.
ports=Machine/System/Network/TcpIp/PortReservations
reg new -p "$ports"
reg set "$ports" @ hex:010004801400000020000000000000002c00000001010000000000051200000001010000000000051200000002001c00010000000000140000000010010100000000000512000000
reg set "$ports" udp:18120 hex:010004801400000020000000000000002c00000001010000000000051200000001010000000000051200000002004400020000000000280001000000010600000000000550000000a381926237d7018113d25f71f4aec1cd93848f340000140000000010010100000000000512000000
for key in "$root" "$root/Settings" "$root/TLS" "$root/Clients" "$root/Clients/loopback" "$root/Networks" "$root/Networks/proof"; do
    reg sd "$key" --set "O:SYG:SYD:P(A;OICI;GA;;;SY)(A;OICI;GR;;;${radius_sid})"
done
svctl definition create radiusd --set ImagePath=/bin/bash --set Arguments=-c \
    --set 'Arguments=export LD_LIBRARY_PATH=/lcl/radius-dev/current/lib; exec /lcl/radius-dev/current/bin/radiusd' \
    --set Identity=Service --set RuntimeDirectories=radiusd --set Requires=lpsd --set Readiness=Notify \
    --set Triggers=boot:settled --set RequiredPrivileges=SeChangeNotifyPrivilege --set RequiredPrivileges=SeAuditPrivilege
svctl start radiusd
echo 'RADIUS DEV VM: offline proof fixture ready'
