#!/usr/bin/env bash
# Trigger the "failed logins" dashboard (PLAN.md §4). Runs on the Mac.
#
# Usage: triggers/failed-ssh.sh [--burst N]
#   1. from the Mac: one login as a bogus user, one as emre with a throwaway (wrong) key,
#      6 s apart so ufw's `limit OpenSSH` (6 new connections / 30 s) is never hit
#   2. on the VM, against 127.0.0.1: N bogus-user attempts (default 10) to trip the
#      brute-force rule; loopback is exempt from the ufw limit
# The throwaway keys are generated fresh and deleted afterwards. The real lab key is
# never offered: these connections don't use the lab ssh config.
set -euo pipefail

VM_IP=${LAB_VM_IP:-192.168.64.2}
HOST=${LAB_HOST:-ubuntu-lab}
SSH_CONFIG=${LAB_SSH_CONFIG:-$HOME/Developer/hardening-lab/.ssh/config}
BURST=10
if [[ ${1:-} == --burst ]]; then BURST=${2:?--burst needs a number}; fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
ssh-keygen -q -t ed25519 -N '' -C wazuh-lab-throwaway -f "$TMP/wrong"

# No config, no agent, only the throwaway key, never write known_hosts.
BAD=(-F /dev/null -o IdentitiesOnly=yes -o IdentityAgent=none -i "$TMP/wrong"
  -o BatchMode=yes -o ConnectTimeout=10
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)

attempt() { # attempt <label> <user>
  if ssh "${BAD[@]}" "$2@$VM_IP" true 2> /dev/null; then
    echo "  UNEXPECTED  $1: login succeeded"
    exit 1
  fi
  echo "  OK          $1: refused (as intended)"
}

START=$(date -u +%FT%TZ)
echo "== from the Mac ($START)"
attempt "bogus user 'nosuchuser'" nosuchuser
sleep 6
attempt "user 'emre' with a wrong key" emre
sleep 6

echo "== burst of $BURST bogus-user attempts on the VM (loopback)"
ssh -F "$SSH_CONFIG" -o BatchMode=yes "$HOST" "bash -s" <<EOF
set -eu
t=\$(mktemp -d); trap 'rm -rf "\$t"' EXIT
ssh-keygen -q -t ed25519 -N '' -f "\$t/k"
for i in \$(seq 1 $BURST); do
  ssh -F /dev/null -o IdentitiesOnly=yes -o IdentityAgent=none -i "\$t/k" -o BatchMode=yes \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
    "labbrute\$i@127.0.0.1" true 2> /dev/null || true
done
echo "  OK          \$(sudo grep -c 'Invalid user labbrute' /var/log/auth.log) 'Invalid user labbrute*' lines in auth.log"
EOF

cat <<EOF
== check (since $START)
  Dashboard: Threat Hunting (or Security events) > agent ubuntu-lab
  Query:     rule.groups:authentication_failed OR rule.id:(5710 OR 5712 OR 5716 OR 5760 OR 100100)
  Expected:  5710 invalid user, 5716/5760 or 100100 failed publickey, 5712 brute force (burst)
  On the VM: sudo python3 -c 'import json,sys; [print(a["rule"]["id"], a["rule"]["description"]) for a in map(json.loads, open("/var/ossec/logs/alerts/alerts.json")) if a["timestamp"] >= sys.argv[1]]' $START | sort | uniq -c
EOF
