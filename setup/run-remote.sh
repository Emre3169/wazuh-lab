#!/usr/bin/env bash
# Run a wazuh-lab script on ubuntu-lab with sudo (PLAN.md §1). Runs on the Mac; bash 3.2 compatible.
#
# Usage: setup/run-remote.sh [--detach | --wait] <script> [args...]
#   (default)  copy the script to ~/wazuh-lab on the VM and run it, streaming output
#   --detach   copy and start it under nohup; output -> ~/wazuh-lab/<name>.log, exit code -> <name>.rc
#   --wait     poll a detached run every 60 s, at most 30 checks; exits with its exit code
#              (124 if still running after 30 checks; it is left running)
#
# Uses the hardening-lab ssh config (read-only) over one multiplexed connection, so
# ufw's `limit OpenSSH` (6 new connections / 30 s) never trips.
set -euo pipefail

HOST=${LAB_HOST:-ubuntu-lab}
SSH_CONFIG=${LAB_SSH_CONFIG:-$HOME/Developer/hardening-lab/.ssh/config}
REMOTE_DIR=wazuh-lab

MODE=run
case ${1:-} in
  --detach) MODE=detach; shift ;;
  --wait) MODE=wait; shift ;;
esac
if [[ $# -lt 1 ]]; then
  echo "usage: $0 [--detach | --wait] <script> [args...]" >&2
  exit 2
fi
SCRIPT=$1
shift
NAME=$(basename "$SCRIPT")

SSH_OPTS=(-F "$SSH_CONFIG"
  -o BatchMode=yes -o ConnectTimeout=10
  -o ServerAliveInterval=30 -o ServerAliveCountMax=6
  -o ControlMaster=auto -o "ControlPath=/tmp/wazuh-ssh-$(id -u)-%C" -o ControlPersist=120)

close_master() { ssh "${SSH_OPTS[@]}" -O exit "$HOST" 2> /dev/null || true; }
trap close_master EXIT

# sshd may still be starting after a VM boot: at most 10 tries, 10 s apart. Each failed
# try is a new connection, and ufw's limit rejects a 7th within 30 s, so never go faster.
tries=0
until ssh "${SSH_OPTS[@]}" "$HOST" true 2> /dev/null; do
  tries=$((tries + 1))
  if [[ $tries -ge 10 ]]; then
    echo "cannot reach $HOST after 10 tries" >&2
    exit 1
  fi
  sleep 10
done

if [[ $MODE == wait ]]; then
  for i in $(seq 1 30); do
    status=$(ssh "${SSH_OPTS[@]}" "$HOST" \
      "cat ~/$REMOTE_DIR/$NAME.rc 2> /dev/null || echo RUNNING; tail -n 1 ~/$REMOTE_DIR/$NAME.log 2> /dev/null")
    rc=$(printf '%s\n' "$status" | head -1)
    last=$(printf '%s\n' "$status" | sed -n 2p)
    if [[ $rc != RUNNING ]]; then
      echo "== $NAME finished with exit code $rc; last 25 log lines:"
      ssh "${SSH_OPTS[@]}" "$HOST" "tail -n 25 ~/$REMOTE_DIR/$NAME.log"
      exit "$rc"
    fi
    echo "check $i/30 $(date +%H:%M:%S): running | $last"
    if [[ $i -lt 30 ]]; then sleep 60; fi
  done
  echo "$NAME still running after 30 checks; left running. Re-run: $0 --wait $NAME" >&2
  exit 124
fi

[[ -f $SCRIPT ]] || { echo "no such script: $SCRIPT" >&2; exit 2; }
ssh "${SSH_OPTS[@]}" "$HOST" "mkdir -p ~/$REMOTE_DIR"
scp "${SSH_OPTS[@]}" -q "$SCRIPT" "$HOST:$REMOTE_DIR/$NAME"

ARGS=""
for a in "$@"; do ARGS="$ARGS $(printf '%q' "$a")"; done

if [[ $MODE == detach ]]; then
  ssh "${SSH_OPTS[@]}" "$HOST" "bash -s" <<EOF
cd ~/$REMOTE_DIR || exit 1
rm -f $NAME.rc
nohup setsid bash -c 'sudo bash ./$NAME$ARGS > $NAME.log 2>&1; echo \$? > $NAME.rc' > /dev/null 2>&1 < /dev/null &
echo "started $NAME$ARGS on $HOST (log: ~/$REMOTE_DIR/$NAME.log)"
EOF
  exit 0
fi

echo "== $HOST: sudo ./$NAME$ARGS"
set +e
ssh "${SSH_OPTS[@]}" "$HOST" "cd ~/$REMOTE_DIR && sudo bash ./$NAME$ARGS"
rc=$?
set -e
echo "== $NAME exited $rc"
exit $rc
