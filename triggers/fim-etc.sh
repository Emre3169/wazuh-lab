#!/usr/bin/env bash
# Trigger the file integrity dashboard (PLAN.md §4). Runs ON the VM (setup/run-remote.sh).
#
# Usage: sudo ./fim-etc.sh
#   create, modify (diff shown), chmod and delete /etc/wazuh-lab-test.conf, then append a
#   comment to /etc/hosts and restore it byte for byte. Realtime FIM on /etc must be on
#   (setup/configure.sh). Every change is reverted before the script exits.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "run with sudo" >&2
  exit 1
fi

TEST=/etc/wazuh-lab-test.conf
HOSTS_BAK=$(mktemp)
cp -a /etc/hosts "$HOSTS_BAK"
restore() {   # only touches files that still differ, so a clean run adds no extra FIM events
  cmp -s "$HOSTS_BAK" /etc/hosts || cp -a "$HOSTS_BAK" /etc/hosts
  rm -f "$HOSTS_BAK"
  [[ ! -e $TEST ]] || rm -f "$TEST"
}
trap restore EXIT

step() { echo "  CHANGED     $*"; sleep 5; }   # realtime FIM needs a moment between events

START=$(date -u +%FT%TZ)
echo "== FIM changes under /etc ($START)"
printf 'lab_setting = 1\n' > "$TEST";            step "created $TEST"
printf 'lab_setting = 2\nnew_line = yes\n' > "$TEST"; step "modified $TEST (report_changes shows the diff)"
chmod 600 "$TEST";                               step "chmod 600 $TEST"
rm -f "$TEST";                                   step "deleted $TEST"
printf '# wazuh-lab FIM test %s\n' "$START" >> /etc/hosts; step "appended a comment to /etc/hosts"
cp -a "$HOSTS_BAK" /etc/hosts;                   step "restored /etc/hosts"

if cmp -s "$HOSTS_BAK" /etc/hosts; then echo "  OK          /etc/hosts identical to before"; fi

cat <<EOF
== check (since $START)
  Dashboard: File Integrity Monitoring > agent ubuntu-lab (Events)
  Expected:  554 added, 550 modified (with diff), 550 for chmod, 553 deleted; 550 x2 for /etc/hosts
  On the VM: sudo python3 -c 'import json,sys; [print(a["rule"]["id"], a["syscheck"]["event"], a["syscheck"]["path"]) for a in map(json.loads, open("/var/ossec/logs/alerts/alerts.json")) if a["timestamp"] >= sys.argv[1] and "syscheck" in a]' $START
EOF
