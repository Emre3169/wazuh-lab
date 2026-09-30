#!/usr/bin/env bash
# Wazuh manager configuration for the lab (PLAN.md §3). Runs ON the VM. Idempotent.
#
# Usage: sudo ./configure.sh [--dry-run] [--no-restart]
#   FIM:   /etc realtime + report_changes + check_all; no diffs for shadow, gshadow, ssh host keys
#   Vulns: vulnerability-detection enabled, index-status yes, feed update every 60m;
#          syscollector package inventory every 1h
#   Logs:  /var/log/auth.log (syslog) and /var/log/audit/audit.log (audit)
#   Rules: local rule 100100 for "Failed publickey" only if no stock rule matches it
#
# ossec.conf is backed up to ossec.conf.lab-<timestamp>, validated with the daemons'
# -t config test, and restored automatically if validation fails.
set -euo pipefail
umask 022

OSSEC=/var/ossec
CONF=$OSSEC/etc/ossec.conf
LOCAL_RULES=$OSSEC/etc/rules/local_rules.xml
DRY_RUN=0
RESTART=1
for a in "$@"; do
  case $a in
    -n|--dry-run) DRY_RUN=1 ;;
    --no-restart) RESTART=0 ;;
    *) echo "usage: sudo $0 [--dry-run] [--no-restart]" >&2; exit 2 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "run with sudo" >&2
  exit 1
fi
[[ -f $CONF ]] || { echo "ERROR: $CONF not found; run install.sh first" >&2; exit 1; }

ok()      { printf '  %-13s %s\n' OK "$*"; }
would()   { printf '  %-13s %s\n' 'WOULD CHANGE' "$*"; }
changed() { printf '  %-13s %s\n' CHANGED "$*"; }
note()    { printf '  %-13s %s\n' NOTE "$*"; }
die()     { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

DIRTY=0
NEW=$(mktemp)
trap 'rm -f "$NEW"' EXIT

echo "== ossec.conf"
# Python edits the XML (ossec.conf has several top-level <ossec_config> blocks, so it is
# wrapped in a synthetic root). Prints OK/CHANGE lines; writes the result to $NEW.
python3 - "$CONF" "$NEW" "$DRY_RUN" <<'PY'
import re, sys
import xml.etree.ElementTree as ET

src, dst, dry = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
text = open(src, encoding="utf-8").read()
parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
root = ET.fromstring("<lab_root>" + text + "</lab_root>", parser=parser)
changes = 0

def say(status, msg):
    print(f"  {status:<13} {msg}")

def change(msg):
    global changes
    changes += 1
    say("WOULD CHANGE" if dry else "CHANGED", msg)

def first(path):
    for block in root.findall("ossec_config"):
        el = block.find(path)
        if el is not None:
            return el
    return None

def sub(parent, tag, text, indent):
    el = ET.SubElement(parent, tag)
    el.text = text
    # keep the file readable: put the new element on its own line
    if len(parent) > 1:
        parent[-2].tail = "\n" + indent
    el.tail = "\n" + indent[:-2]
    return el

def ensure_text(parent, tag, value, label, indent="    "):
    el = parent.find(tag)
    if el is not None and (el.text or "").strip() == value:
        say("OK", f"{label} = {value}")
        return
    if el is None:
        sub(parent, tag, value, indent)
    else:
        el.text = value
    change(f"{label} = {value}")

# --- FIM (syscheck) ---------------------------------------------------------
sc = first("syscheck")
if sc is None:
    sys.exit("no <syscheck> block in ossec.conf")
want = {"realtime": "yes", "report_changes": "yes", "check_all": "yes"}
etc = [d for d in sc.findall("directories") if (d.text or "").strip() == "/etc"]
for d in sc.findall("directories"):
    parts = [p.strip() for p in (d.text or "").split(",")]
    if "/etc" in parts and len(parts) > 1:
        d.text = ",".join(p for p in parts if p != "/etc")
        change(f"syscheck: split /etc out of <directories>{','.join(parts)}</directories>")
if etc:
    d = etc[0]
    if all(d.get(k) == v for k, v in want.items()):
        say("OK", "syscheck /etc realtime report_changes check_all")
    else:
        for k, v in want.items():
            d.set(k, v)
        change("syscheck /etc realtime report_changes check_all")
else:
    d = sub(sc, "directories", "/etc", "    ")
    for k, v in want.items():
        d.set(k, v)
    change("syscheck /etc realtime report_changes check_all (new entry)")

existing_nodiff = {(n.text or "").strip() for n in sc.findall("nodiff")}
for path, attrs in [("/etc/shadow", {}), ("/etc/gshadow", {}),
                    (r"^/etc/ssh/ssh_host_.*_key$", {"type": "sregex"})]:
    if path in existing_nodiff:
        say("OK", f"syscheck nodiff {path}")
    else:
        n = sub(sc, "nodiff", path, "    ")
        for k, v in attrs.items():
            n.set(k, v)
        change(f"syscheck nodiff {path} (no diffs of secrets in alerts)")

existing_ignore = {(i.text or "").strip() for i in sc.findall("ignore")}
for path in ["/etc/mtab", "/etc/adjtime"]:
    if path in existing_ignore:
        say("OK", f"syscheck ignore {path}")
    else:
        sub(sc, "ignore", path, "    ")
        change(f"syscheck ignore {path}")

# --- vulnerability detection -------------------------------------------------
vd = first("vulnerability-detection")
if vd is None:
    sys.exit("no <vulnerability-detection> block (expected in Wazuh >= 4.8)")
ensure_text(vd, "enabled", "yes", "vulnerability-detection enabled")
ensure_text(vd, "index-status", "yes", "vulnerability-detection index-status")
ensure_text(vd, "feed-update-interval", "60m", "vulnerability-detection feed-update-interval")

syscol = None
for block in root.findall("ossec_config"):
    for w in block.findall("wodle"):
        if w.get("name") == "syscollector":
            syscol = w
            break
    if syscol is not None:
        break
if syscol is None:
    sys.exit("no syscollector wodle in ossec.conf")
ensure_text(syscol, "disabled", "no", "syscollector disabled")
ensure_text(syscol, "interval", "1h", "syscollector interval")
ensure_text(syscol, "packages", "yes", "syscollector packages")

# --- log collection ------------------------------------------------------------
locations = {}
for block in root.findall("ossec_config"):
    for lf in block.findall("localfile"):
        loc = (lf.findtext("location") or "").strip()
        locations[loc] = (lf.findtext("log_format") or "").strip()
target = root.findall("ossec_config")[-1]
for loc, fmt in [("/var/log/auth.log", "syslog"), ("/var/log/audit/audit.log", "audit")]:
    if locations.get(loc) == fmt:
        say("OK", f"localfile {loc} ({fmt})")
        continue
    lf = sub(target, "localfile", None, "  ")
    lf.text = "\n    "
    f = ET.SubElement(lf, "log_format"); f.text = fmt; f.tail = "\n    "
    l = ET.SubElement(lf, "location"); l.text = loc; l.tail = "\n  "
    change(f"localfile {loc} ({fmt})")

out = ET.tostring(root, encoding="unicode")
out = re.sub(r"^<lab_root>", "", out)
out = re.sub(r"</lab_root>$", "", out)
# ElementTree escapes ">" in text; a bare ">" is valid XML and is what Wazuh's parser expects.
out = out.replace("&gt;", ">")
open(dst, "w", encoding="utf-8").write(out)
print(f"  {'':<13} {changes} ossec.conf change(s)")
PY

if cmp -s "$CONF" "$NEW"; then
  ok "ossec.conf already configured"
else
  DIRTY=1
  if ((DRY_RUN)); then
    would "ossec.conf (diff below)"
    diff -u "$CONF" "$NEW" | tail -n +3 | sed 's/^/      /' || true
  else
    BACKUP=$CONF.lab-$(date -u +%Y%m%dT%H%M%SZ)
    cp -a "$CONF" "$BACKUP"
    cat "$NEW" > "$CONF"   # keeps ossec.conf's owner (root:wazuh) and mode
    for d in wazuh-analysisd wazuh-syscheckd wazuh-logcollector wazuh-modulesd; do
      if ! "$OSSEC/bin/$d" -t > /dev/null 2>&1; then
        cp -a "$BACKUP" "$CONF"
        "$OSSEC/bin/$d" -t || true
        die "$d -t rejected the new config; ossec.conf restored from $BACKUP"
      fi
    done
    changed "ossec.conf (backup $BACKUP; config test passed)"
  fi
fi

echo "== local rule for 'Failed publickey'"
SAMPLE="$(date '+%b %e %H:%M:%S') $(hostname) sshd[4242]: Failed publickey for emre from 192.168.64.1 port 50000 ssh2: ED25519 SHA256:labtestlabtestlabtestlabtestlabtestlabtest"
if grep -q 'id="100100"' "$LOCAL_RULES" 2> /dev/null; then
  ok "rule 100100 already in local_rules.xml"
else
  # wazuh-logtest reads lines from stdin; take the rule it reports for the sample.
  lt=$(printf '%s\n' "$SAMPLE" | timeout 30 "$OSSEC/bin/wazuh-logtest" 2>&1 || true)
  rid=$(grep -oE "id: '[0-9]+'" <<< "$lt" | tail -1 | tr -dc 0-9)
  lvl=$(grep -oE "level: '[0-9]+'" <<< "$lt" | tail -1 | tr -dc 0-9)
  if [[ -n $rid && ${lvl:-0} -ge 5 ]]; then
    ok "stock rule $rid (level $lvl) already matches failed publickey; no local rule needed"
  elif ((DRY_RUN)); then
    DIRTY=1
    would "add rule 100100 (stock match: ${rid:-none}, level ${lvl:-n/a})"
  else
    DIRTY=1
    cp -a "$LOCAL_RULES" "$LOCAL_RULES.lab-$(date -u +%Y%m%dT%H%M%SZ)"
    cat >> "$LOCAL_RULES" <<'EOF'

<!-- wazuh-lab: sshd public key rejected (wrong key). Needs sshd LogLevel VERBOSE. -->
<group name="local,sshd,authentication_failed,">
  <rule id="100100" level="5">
    <if_sid>5700</if_sid>
    <match>Failed publickey</match>
    <description>sshd: public key authentication failed (wrong key).</description>
    <group>authentication_failed,</group>
  </rule>
</group>
EOF
    if ! "$OSSEC/bin/wazuh-analysisd" -t > /dev/null 2>&1; then
      cp -a "$(ls -t "$LOCAL_RULES".lab-* | head -1)" "$LOCAL_RULES"
      die "analysisd rejected rule 100100; local_rules.xml restored"
    fi
    changed "rule 100100 added (stock match was ${rid:-none}, level ${lvl:-n/a})"
  fi
fi

if ((DIRTY && RESTART && !DRY_RUN)); then
  systemctl restart wazuh-manager
  for i in $(seq 1 24); do
    systemctl is-active -q wazuh-manager && break
    sleep 5
  done
  systemctl is-active -q wazuh-manager || die "wazuh-manager not active after restart"
  changed "wazuh-manager restarted"
elif ((DIRTY && DRY_RUN)); then
  would "restart wazuh-manager"
fi
