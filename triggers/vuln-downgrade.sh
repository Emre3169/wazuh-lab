#!/usr/bin/env bash
# Trigger the vulnerability detection dashboard (PLAN.md §4). Runs ON the VM (setup/run-remote.sh).
#
# Usage: sudo ./vuln-downgrade.sh [--package rsync] [--no-restart]
#        sudo ./vuln-downgrade.sh --revert [--package rsync]
#   Installs the Ubuntu *release* build of a package (known CVEs, fixed later in -security),
#   puts it on apt-mark hold so unattended-upgrades can't fix it mid-demo, and restarts
#   wazuh-manager so syscollector re-inventories packages at once.
#   --revert removes the hold and upgrades it again (or purges it if we installed it).
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

PKG=rsync
REVERT=0
RESTART=1
while (($#)); do
  case $1 in
    --package) PKG=${2:?--package needs a name}; shift ;;
    --revert) REVERT=1 ;;
    --no-restart) RESTART=0 ;;
    *) echo "usage: sudo $0 [--revert] [--package NAME] [--no-restart]" >&2; exit 2 ;;
  esac
  shift
done

if [[ $EUID -ne 0 ]]; then
  echo "run with sudo" >&2
  exit 1
fi

STATE_DIR=/var/lib/wazuh-lab
STATE=$STATE_DIR/vuln-$PKG.state   # "installed-before=yes|no"
ok()      { printf '  %-13s %s\n' OK "$*"; }
changed() { printf '  %-13s %s\n' CHANGED "$*"; }
die()     { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

installed_version() { dpkg-query -W -f='${Version}' "$PKG" 2> /dev/null || true; }

restart_manager() {
  ((RESTART)) || return 0
  systemctl restart wazuh-manager
  changed "wazuh-manager restarted (syscollector rescans packages on start)"
}

if ((REVERT)); then
  echo "== revert $PKG"
  [[ -f $STATE ]] || die "no state file $STATE; nothing to revert"
  apt-mark unhold "$PKG" > /dev/null
  changed "apt-mark unhold $PKG"
  if grep -q 'installed-before=yes' "$STATE"; then
    apt-get update -qq
    apt-get install -y -qq --only-upgrade "$PKG" > /dev/null
    changed "$PKG upgraded to $(installed_version)"
  else
    apt-get purge -y -qq "$PKG" > /dev/null
    changed "$PKG purged (it wasn't installed before the demo)"
  fi
  rm -f "$STATE"
  restart_manager
  exit 0
fi

. /etc/os-release
CODENAME=$VERSION_CODENAME
apt-get update -qq
# The version published in the plain release pocket (e.g. "noble/main"), not -updates/-security.
REL=$(apt-cache madison "$PKG" | awk -F'|' -v c=" $CODENAME/" 'index($3, c) { gsub(/ /, "", $2); print $2; exit }')
[[ -n $REL ]] || die "no $CODENAME release-pocket version of $PKG found"
CUR=$(installed_version)
CAND=$(apt-cache policy "$PKG" | awk '/Candidate:/ { print $2 }')

echo "== downgrade $PKG for the demo"
echo "  installed: ${CUR:-none}   release: $REL   latest: $CAND"
[[ $REL != "$CAND" ]] || die "$PKG release version is the latest; pick a package with a security update"

if [[ $CUR == "$REL" ]]; then
  ok "$PKG already at release version $REL"
else
  mkdir -p "$STATE_DIR"
  [[ -f $STATE ]] || echo "installed-before=$([[ -n $CUR ]] && echo yes || echo no)" > "$STATE"
  apt-get install -y -qq --allow-downgrades "$PKG=$REL" > /dev/null
  changed "$PKG ${CUR:-none} -> $REL"
fi
apt-mark hold "$PKG" > /dev/null
ok "$PKG on hold (unattended-upgrades won't touch it)"
restart_manager

cat <<EOF
== check
  Dashboard: Vulnerability Detection > agent ubuntu-lab > Inventory, filter package.name: $PKG
  Expect CVEs for $PKG $REL with the fixed version $CAND. The first feed sync after install
  can take up to an hour; later scans show up within minutes of the restart.
  Revert:    sudo ./vuln-downgrade.sh --revert
EOF
