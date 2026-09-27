#!/bin/sh
# normal_workload.sh — a benign "app" used to TRAIN the baseline and to show a
# clean monitored run (no alerts). It only reads a couple of config files a few
# times and writes to /tmp — pure file I/O and process spawning, deliberately
# NO networking, NO permission changes, NO ptrace. Whatever syscalls this makes
# become the "normal" profile for the image.
i=0
while [ "$i" -lt 5 ]; do
	cat /etc/os-release > /tmp/work
	cat /etc/passwd >> /tmp/work
	i=$((i + 1))
done
echo "app: healthy"
