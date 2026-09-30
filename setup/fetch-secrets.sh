#!/usr/bin/env bash
# Move wazuh-install-files.tar from the VM to secrets/ on the Mac (PLAN.md §2). Runs on the Mac.
#
# Usage: setup/fetch-secrets.sh
#   secrets/wazuh-install-files.tar   the assistant's tar (certs + passwords), mode 600
#   secrets/wazuh-passwords.txt       extracted from the tar, mode 600
#   secrets/README                    sha256 and date
# The VM copy is deleted only after the local copy verifies. Prints paths, never passwords.
set -euo pipefail
umask 077

REPO=$(cd "$(dirname "$0")/.." && pwd)
HOST=${LAB_HOST:-ubuntu-lab}
SSH_CONFIG=${LAB_SSH_CONFIG:-$HOME/Developer/hardening-lab/.ssh/config}
REMOTE_TAR=wazuh-lab/wazuh-install-files.tar
OUT=$REPO/secrets
TAR=$OUT/wazuh-install-files.tar
PW=$OUT/wazuh-passwords.txt

SSH_OPTS=(-F "$SSH_CONFIG" -o BatchMode=yes -o ConnectTimeout=10
  -o ControlMaster=auto -o "ControlPath=/tmp/wazuh-ssh-$(id -u)-%C" -o ControlPersist=60)
trap 'ssh "${SSH_OPTS[@]}" -O exit "$HOST" 2> /dev/null || true' EXIT

mkdir -p "$OUT"
chmod 700 "$OUT"
git -C "$REPO" check-ignore -q "$TAR" || { echo "ERROR: $TAR is not gitignored; refusing" >&2; exit 1; }

if ! ssh "${SSH_OPTS[@]}" "$HOST" "sudo test -f ~/$REMOTE_TAR"; then
  if [[ -s $TAR ]]; then
    echo "OK  already fetched: $TAR (not on the VM any more)"
    exit 0
  fi
  echo "ERROR: ~/$REMOTE_TAR not found on $HOST and no local copy" >&2
  exit 1
fi

ssh "${SSH_OPTS[@]}" "$HOST" "sudo cat ~/$REMOTE_TAR" > "$TAR.part"
tar -tf "$TAR.part" | grep -q 'wazuh-install-files/wazuh-passwords.txt' \
  || { rm -f "$TAR.part"; echo "ERROR: fetched tar has no wazuh-passwords.txt" >&2; exit 1; }
remote_sum=$(ssh "${SSH_OPTS[@]}" "$HOST" "sudo sha256sum ~/$REMOTE_TAR" | cut -d' ' -f1)
local_sum=$(shasum -a 256 "$TAR.part" | cut -d' ' -f1)
[[ $remote_sum == "$local_sum" ]] || { rm -f "$TAR.part"; echo "ERROR: checksum mismatch" >&2; exit 1; }

mv "$TAR.part" "$TAR"
chmod 600 "$TAR"
tar -xOf "$TAR" wazuh-install-files/wazuh-passwords.txt > "$PW"
chmod 600 "$PW"
printf 'wazuh-install-files.tar sha256 %s\nfetched %s from %s:~/%s\n' \
  "$local_sum" "$(date -u +%FT%TZ)" "$HOST" "$REMOTE_TAR" > "$OUT/README"

ssh "${SSH_OPTS[@]}" "$HOST" "sudo rm -f ~/$REMOTE_TAR"
echo "OK  $TAR (sha256 ${local_sum:0:16}…)"
echo "OK  $PW"
echo "OK  removed the copy on $HOST"
