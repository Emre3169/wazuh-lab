#!/usr/bin/env bash
# ufw rules for Wazuh on ubuntu-lab (PLAN.md §2). Runs ON the VM. Idempotent.
#
# Usage: sudo ./firewall.sh [--dry-run] [--remove]
#   443/tcp   dashboard         from the Mac (MAC_IP, default 192.168.64.1)
#   1514/tcp  agent events      from the UTM subnet (SUBNET, default 192.168.64.0/24)
#   1515/tcp  agent enrollment  from the UTM subnet
#   9200 (indexer) and 55000 (API) are never opened; both stay on localhost.
set -euo pipefail

MAC_IP=${MAC_IP:-192.168.64.1}
SUBNET=${SUBNET:-192.168.64.0/24}
DRY_RUN=0
REMOVE=0
for a in "$@"; do
  case $a in
    -n|--dry-run) DRY_RUN=1 ;;
    --remove) REMOVE=1 ;;
    *) echo "usage: sudo $0 [--dry-run] [--remove]" >&2; exit 2 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "run with sudo" >&2
  exit 1
fi

ok()      { printf '  %-13s %s\n' OK "$*"; }
would()   { printf '  %-13s %s\n' 'WOULD CHANGE' "$*"; }
changed() { printf '  %-13s %s\n' CHANGED "$*"; }

RULES=(
  "$MAC_IP|443|wazuh dashboard"
  "$SUBNET|1514|wazuh agent events"
  "$SUBNET|1515|wazuh agent enrollment"
)

added=$(ufw show added)
for r in "${RULES[@]}"; do
  IFS='|' read -r src port comment <<< "$r"
  spec=(from "$src" to any port "$port" proto tcp)
  present=0
  grep -qF "ufw allow ${spec[*]}" <<< "$added" && present=1
  if ((REMOVE)); then
    if ((present == 0)); then ok "no rule for $port from $src"
    elif ((DRY_RUN)); then would "delete allow $port/tcp from $src"
    else ufw delete allow "${spec[@]}" > /dev/null; changed "deleted allow $port/tcp from $src"; fi
  else
    if ((present)); then ok "allow $port/tcp from $src ($comment)"
    elif ((DRY_RUN)); then would "allow $port/tcp from $src ($comment)"
    else ufw allow "${spec[@]}" comment "$comment" > /dev/null; changed "allow $port/tcp from $src ($comment)"; fi
  fi
done

# Guard: nothing may expose the indexer or the API.
for p in 9200 55000; do
  if grep -qE "port $p( |$)" <<< "$(ufw show added)"; then
    printf '  %-13s %s\n' WARN "a ufw rule mentions port $p; it should stay closed"
  else
    ok "port $p not opened"
  fi
done

echo "== ufw status"
ufw status numbered | sed 's/^/  /'
