#!/bin/bash
# Enable the ordinary netd service in an existing development VM.
# Network profiles/rules remain administrator-owned, including the static IP.
set -euo pipefail
export PATH=/lcl/radius-dev/current/bin:$PATH
export LD_LIBRARY_PATH=/lcl/radius-dev/current/lib
[[ -f /lcl/radius-dev/current/bin/netd && -f /lcl/radius-dev/current/lib/libnetd.so.1 ]]
reg get Machine/System/Network/Profiles/radius-dev-lan > /dev/null
if [[ ! -e /var/state/netd ]]; then
    mkdir /var/state/netd
    sd set /var/state/netd 'O:SYG:SYD:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)'
fi
# Preserve unrelated service settings. Change only the development executable
# location when a netd definition already exists.
if svctl definition show netd > /dev/null 2>&1; then
    svctl definition edit netd --set ImagePath=/bin/bash --set Arguments=-c \
        --set 'Arguments=export LD_LIBRARY_PATH=/lcl/radius-dev/current/lib; exec /lcl/radius-dev/current/bin/netd'
else
    svctl definition create netd --set ImagePath=/bin/bash --set Arguments=-c \
        --set 'Arguments=export LD_LIBRARY_PATH=/lcl/radius-dev/current/lib; exec /lcl/radius-dev/current/bin/netd' \
        --set Identity=SYSTEM --set Triggers=boot --set Provides=network --set Readiness=Notify \
        --set RuntimeDirectories=netd --set RestartPolicy=Always
fi
svctl start netd
net status
