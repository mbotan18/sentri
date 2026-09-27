#!/bin/sh
# payload.sh — a SIMULATED container compromise for the sentri demo.
#
# It masquerades as the normal app for a moment, then performs actions a benign
# file-reading workload would never do. Everything here is INERT and safe — the
# point is the SYSCALLS these actions make, which the trained baseline never saw:
#
#   * network "phone home": socket() + connect()  (like malware beaconing to C2)
#   * file tampering:        chmod()               (like arming a dropped binary)
#
# Safety notes:
#   - 198.51.100.7 is TEST-NET-2 (RFC 5737), reserved for documentation and NOT
#     routable, so the connection goes nowhere. `-w 1` bounds the attempt to ~1s.
#   - chmod targets a scratch file in /tmp, not anything real.

# 1) Look like the normal app for a beat.
cat /etc/os-release > /tmp/work

# 2) "Phone home" — opens a socket and attempts an outbound connection.
echo | nc -w 1 198.51.100.7 4444

# 3) Tamper with a file's permissions.
chmod 777 /tmp/work

echo "payload: done"
