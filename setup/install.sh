#!/usr/bin/env bash
# Wazuh 4.14 all-in-one install on ubuntu-lab (PLAN.md §2). Runs ON the VM.
#
# Usage: sudo ./install.sh --preflight   checks only; installs nothing
#        sudo ./install.sh --install     preflight, wazuh-install.sh -a -i, heap cap, disable repo
#        sudo ./install.sh --uninstall   wazuh-install.sh -u (the assistant's own cleanup)
#
# Passwords are never printed: installer output and /var/log/wazuh-install.log are
# redacted. The real passwords stay in ./wazuh-install-files.tar (root-only) until
# setup/fetch-secrets.sh moves them to the Mac.
set -euo pipefail
umask 022   # hardening-lab sets UMASK 027; Wazuh's files must stay readable by its service users

WAZUH_MINOR=4.14
INSTALLER_URL=https://packages.wazuh.com/$WAZUH_MINOR/wazuh-install.sh
ARM64_INDEX=https://packages.wazuh.com/4.x/apt/dists/stable/main/binary-arm64/Packages.gz
HEAP=2g
WORK=$(pwd)
SERVICES=(wazuh-indexer wazuh-manager wazuh-dashboard filebeat)

MODE=""
case ${1:-} in
  --preflight|--install|--uninstall) MODE=${1#--} ;;
  *) echo "usage: sudo $0 --preflight | --install | --uninstall" >&2; exit 2 ;;
esac

if [[ $EUID -ne 0 ]]; then
  echo "run with sudo" >&2
  exit 1
fi

N_FAIL=0
pass() { printf '  %-5s %s\n' OK "$*"; }
warn() { printf '  %-5s %s\n' WARN "$*"; }
fail() { N_FAIL=$((N_FAIL + 1)); printf '  %-5s %s\n' FAIL "$*"; }
info() { printf '  %-5s %s\n' INFO "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# Replace anything after "password:" / "password=" with a placeholder.
redact() { sed -uE 's/(pass(word|wd)?[^:=]*[:=][[:space:]]*).+/\1<redacted>/I'; }

do_preflight() {
  echo "== preflight"
  local arch mem_kb mem_gb free_gb p host maxmap

  arch=$(uname -m)
  if [[ $arch == aarch64 ]]; then pass "arch $arch"; else fail "arch $arch (expected aarch64)"; fi

  mem_kb=$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)
  mem_gb=$((mem_kb / 1024 / 1024))
  if ((mem_kb < 3900000)); then fail "RAM ${mem_gb} GB (< 4 GB minimum)"
  elif ((mem_kb < 7800000)); then warn "RAM ~$((mem_kb / 1000000)) GB (8 GB recommended; heap will be capped at $HEAP, installer runs with -i)"
  else pass "RAM ${mem_gb} GB"; fi

  free_gb=$(df -BG --output=avail / | tail -1 | tr -dc 0-9)
  if ((free_gb >= 20)); then pass "disk ${free_gb} GB free on /"; else fail "disk ${free_gb} GB free on / (< 20 GB)"; fi

  for p in 443 1514 1515 9200 55000; do
    if [[ -n $(ss -Hltn "sport = :$p") ]]; then fail "port $p already in use"; else pass "port $p free"; fi
  done

  host=$(hostname)
  if getent hosts "$host" > /dev/null; then pass "hostname $host resolves ($(getent hosts "$host" | awk '{ print $1; exit }'))"
  else fail "hostname $host does not resolve (indexer certificates need it)"; fi

  if [[ $(dpkg-query -W -f='${Package} ${Status}\n' 'wazuh-*' 2> /dev/null) == *'install ok installed'* ]]; then
    if [[ $MODE == install ]]; then fail "Wazuh packages already installed (use --uninstall first)"
    else warn "Wazuh packages already installed"; fi
  else
    pass "no Wazuh packages installed"
  fi

  if curl -fsSI --max-time 15 "$INSTALLER_URL" > /dev/null; then pass "installer reachable: $INSTALLER_URL"
  else fail "cannot reach $INSTALLER_URL"; fi

  if curl -sSI --max-time 15 https://cti.wazuh.com > /dev/null 2>&1; then pass "cti.wazuh.com reachable (vulnerability feed)"
  else warn "cti.wazuh.com not reachable; vulnerability detection will have no feed"; fi

  # Every package the assistant installs must exist for arm64 at $WAZUH_MINOR.
  local index pkg ver
  if index=$(curl -fsS --max-time 30 "$ARM64_INDEX" | gunzip 2> /dev/null); then
    for pkg in wazuh-indexer wazuh-manager wazuh-dashboard; do
      ver=$(awk -v p="$pkg" '$1 == "Package:" { cur = $2 } $1 == "Version:" && cur == p { print $2 }' <<< "$index" \
        | grep "^$WAZUH_MINOR\." | sort -V | tail -1)
      if [[ -n $ver ]]; then pass "arm64 package $pkg $ver"; else fail "no arm64 $pkg $WAZUH_MINOR.x in the Wazuh repo"; fi
    done
    if grep -qx 'Package: filebeat' <<< "$index"; then pass "arm64 package filebeat present"
    else fail "no arm64 filebeat in the Wazuh repo"; fi
  else
    fail "cannot fetch $ARM64_INDEX"
  fi

  maxmap=$(sysctl -n vm.max_map_count)
  info "vm.max_map_count=$maxmap (indexer needs >= 262144; its package sets it)"
  info "time synced: $(timedatectl show -p NTPSynchronized --value 2> /dev/null || echo unknown)"
  info "ufw: $(ufw status | head -1)"

  echo "== preflight: $N_FAIL failed"
  ((N_FAIL == 0))
}

fetch_installer() {
  if [[ ! -f $WORK/wazuh-install.sh ]]; then
    curl -fsS -o "$WORK/wazuh-install.sh" "$INSTALLER_URL"
  fi
  info "installer sha256 $(sha256sum "$WORK/wazuh-install.sh" | cut -c1-16)…"
}

wait_port() { # wait_port <port> <tries>: 5 s apart
  local i
  for ((i = 1; i <= $2; i++)); do
    [[ -n $(ss -Hltn "sport = :$1") ]] && return 0
    sleep 5
  done
  return 1
}

# Not named install(): that would shadow /usr/bin/install, which this function uses.
do_install() {
  do_preflight || die "preflight failed; nothing installed"
  echo "== install (wazuh-install.sh -a -i), 10-20 minutes"
  fetch_installer
  cd "$WORK"
  set +e
  bash ./wazuh-install.sh -a -i 2>&1 | redact
  local rc=${PIPESTATUS[0]}
  set -e
  if [[ -f /var/log/wazuh-install.log ]]; then
    sed -i -E 's/(pass(word|wd)?[^:=]*[:=][[:space:]]*).+/\1<redacted>/I' /var/log/wazuh-install.log
  fi
  if ((rc != 0)); then
    echo "installer exited $rc. Fallback: sudo ./install.sh --uninstall, then retry once;"
    echo "if it fails again, follow the manual step-by-step install (PLAN.md §7)."
    exit "$rc"
  fi
  [[ -f $WORK/wazuh-install-files.tar ]] || die "installer succeeded but $WORK/wazuh-install-files.tar is missing"
  chmod 600 "$WORK/wazuh-install-files.tar"
  pass "credentials in $WORK/wazuh-install-files.tar (root-only; run setup/fetch-secrets.sh)"

  echo "== indexer heap -> $HEAP"
  install -d -m 755 /etc/wazuh-indexer/jvm.options.d
  printf -- '-Xms%s\n-Xmx%s\n' "$HEAP" "$HEAP" > /etc/wazuh-indexer/jvm.options.d/lab-heap.options
  chmod 644 /etc/wazuh-indexer/jvm.options.d/lab-heap.options
  systemctl restart wazuh-indexer
  wait_port 9200 36 || die "indexer did not come back on 9200 within 3 minutes"
  # The JVM honours the last -Xmx on its command line; jvm.options.d comes after jvm.options.
  info "indexer running with $(tr '\0' '\n' < /proc/"$(systemctl show -p MainPID --value wazuh-indexer)"/cmdline | grep '^-Xmx' | tail -1)"

  echo "== disable the Wazuh apt repo (pin 4.14)"
  if [[ -f /etc/apt/sources.list.d/wazuh.list ]]; then
    sed -i 's/^deb /#deb /' /etc/apt/sources.list.d/wazuh.list
    apt-get update -qq
    pass "wazuh.list commented out"
  fi

  echo "== services"
  local s bad=0
  for s in "${SERVICES[@]}"; do
    if systemctl is-active -q "$s"; then pass "$s active"; else fail "$s $(systemctl is-active "$s")"; bad=1; fi
  done
  free -m | awk 'NR <= 2'
  ((bad == 0)) || exit 1
  echo "dashboard: https://$(hostname -I | awk '{ print $1 }')  (user admin; password in wazuh-install-files.tar)"
}

do_uninstall() {
  fetch_installer
  cd "$WORK"
  bash ./wazuh-install.sh -u 2>&1 | redact
}

"do_$MODE"
