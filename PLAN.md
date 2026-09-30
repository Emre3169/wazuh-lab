# Wazuh Lab Plan

A single-node Wazuh 4.14 install (manager + indexer + dashboard) on the existing
**ubuntu-lab** VM. It demonstrates three detections end to end: **failed logins**,
**vulnerability detection** (patch status) and **file integrity**. The first agent is the
manager's own; a Windows 11 ARM64 agent comes later.

- **Target:** ubuntu-lab, Ubuntu 24.04.5 ARM64, 4 vCPU, 6 GB RAM, 40 GB disk, 192.168.64.2.
- **Starting state:** already hardened by hardening-lab (Lynis 78). ufw allows only rate-limited
  SSH, password SSH is off, auditd is on, NOPASSWD sudo is on.
- **Access:** `ssh -F ~/Developer/hardening-lab/.ssh/config ubuntu-lab`. This repo reuses that
  config and doesn't copy the key.

## Principles

- **Pin the version.** Download from `packages.wazuh.com/4.14/`, then turn off the Wazuh apt
  repo afterwards, so a routine `apt upgrade` can't half-upgrade the stack.
- **Take a snapshot first.** Before installing, `utmctl clone ubuntu-lab --name
  ubuntu-lab-hardened` so we can get back to "hardened, no Wazuh". That's a new clone and
  doesn't touch `ubuntu-lab-clean`.
- **Open ports to named sources only.** Allow the Wazuh ports from the UTM subnet or the Mac,
  never "Anywhere".
- **Keep secrets out of git.** `wazuh-install-files.tar` and every password live in
  `secrets/`, which is gitignored before the first commit.
- **Every trigger is a script that prints how to check it.** Each one says which dashboard,
  which rule ID and which search query shows the result.

## 1. Repo layout

```
wazuh-lab/
├── PLAN.md
├── README.md                   what, quick start, where the password is, lab caveats
├── THEORY-OF-OPERATIONS.md     how Wazuh works here (outline in §6)
├── .gitignore                  secrets/, *.tar, .env
├── setup/
│   ├── install.sh              runs ON the VM: preflight, wazuh-install.sh -a, heap cap, disable repo
│   ├── firewall.sh             runs ON the VM: ufw rules for 443/1514/1515
│   ├── configure.sh            runs ON the VM: FIM, vulnerability detection, log collection (idempotent, backs up ossec.conf)
│   ├── run-remote.sh           runs on the Mac: scp + sudo over ssh (same pattern as hardening-lab)
│   └── fetch-secrets.sh        runs on the Mac: scp wazuh-install-files.tar -> secrets/ (chmod 600)
├── triggers/
│   ├── failed-ssh.sh           bogus user + wrong key + burst
│   ├── fim-etc.sh              create/modify/delete under /etc, then revert
│   └── vuln-downgrade.sh       downgrade a leaf package, then --revert
├── docs/
│   └── network-diagram.md      Mermaid: Mac, UTM NAT, ubuntu-lab components, windows-lab, ports
├── screenshots/                one PNG per dashboard (before and after trigger)
└── secrets/                    gitignored: install tar, passwords
```

## 2. Install

**Preflight** (`install.sh` checks these and stops if one fails):
- `uname -m` is `aarch64`
- at least 4 GB RAM and 20 GB free disk
- ports 443, 1514, 1515, 9200 and 55000 are free
- `hostname` resolves (the indexer certificates depend on it)

**Install:**
```sh
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash wazuh-install.sh -a -i     # -i: skip the hardware check (we have 6 GB; 8 GB is recommended)
```
- **Timing:** run it over SSH with output logged to `setup/install.log` on the VM. It takes
  10–20 minutes. `run-remote.sh` uses a keepalive so SSH doesn't drop.
- **After it finishes:** `sed -i 's/^deb /#deb /' /etc/apt/sources.list.d/wazuh.list && apt
  update`.

**Indexer memory** (the key setting on a 6 GB VM):
- Set `-Xms2g -Xmx2g` in `/etc/wazuh-indexer/jvm.options.d/lab-heap.options`, then restart
  wazuh-indexer.
- Budget: indexer about 2.5 GB (heap plus off-heap), manager about 0.7 GB, dashboard about
  0.5 GB, OS about 0.8 GB. That leaves roughly 1.5 GB of headroom.
- Check that `vm.max_map_count` is at least 262144. The indexer package sets it; our
  `99-zz-lab.conf` doesn't override it.

**Firewall** (`firewall.sh`):

| Port | Service | Allowed from |
|------|---------|--------------|
| 443/tcp | Dashboard | 192.168.64.1 (the Mac) |
| 1514/tcp | Agent events | 192.168.64.0/24 (UTM subnet) |
| 1515/tcp | Agent enrollment | 192.168.64.0/24 |
| 55000/tcp | Wazuh API | **not opened**; the dashboard reaches it on localhost |
| 9200/tcp | Indexer | **never opened**; stays on localhost |

**Admin password:**
- The assistant writes `wazuh-install-files.tar`, which contains `wazuh-passwords.txt`, to the
  directory it ran from.
- `fetch-secrets.sh` copies it to `secrets/` on the Mac with mode 600, then deletes the copy
  on the VM. Its SHA256 is recorded in `secrets/README` (also gitignored).
- **Never committed:** `.gitignore` covers `secrets/` and `*.tar`. Before each commit,
  `git diff --cached | grep -i password` must return nothing. The dashboard password goes in
  your password manager, not in README.md.

## 3. Configuration (`configure.sh`)

It edits `/var/ossec/etc/ossec.conf` with a backup and a `wazuh-control restart`, and it's
idempotent (it checks for a marker comment).

- **File integrity (FIM):**
  - `<directories realtime="yes" report_changes="yes" check_all="yes">/etc</directories>`
  - `<nodiff>` for `/etc/shadow`, `/etc/gshadow` and `/etc/ssh/ssh_host_*_key`. Without it,
    `report_changes` would copy password hashes and private keys into alerts.
  - Ignore `/etc/mtab` and `/etc/adjtime`, which change constantly.
  - Keep the default scheduled scan (12 h) as a safety net for realtime.
- **Vulnerability detection:** `<vulnerability-detection><enabled>yes</enabled>
  <index-status>yes</index-status><feed-update-interval>60m</feed-update-interval>`.
  - Since 4.8 it uses the Wazuh CTI feed plus the syscollector package inventory; there's no
    per-OS provider config. Ubuntu 24.04 is covered.
  - The first feed download needs outbound HTTPS to `cti.wazuh.com` and can take a while.
  - Set the syscollector package scan to 1 h, down from 1 d, so downgrades show up quickly.
- **SSH authentication logs:**
  - `/var/log/auth.log` still exists on 24.04 Server, via rsyslog. Confirm the default
    `<localfile>` entry covers it; add `journald` collection only if rsyslog is absent.
  - hardening-lab set sshd to `LogLevel VERBOSE`, so failed publickey attempts are logged too.
- **Bonus, no extra work:** `/var/log/audit/audit.log` from hardening-lab's auditd rules. The
  default decoders pick it up if we add the localfile entry, which is useful in the theory doc.

## 4. Triggers

| Script | What it does | Expected result |
|--------|--------------|-----------------|
| `failed-ssh.sh` | **Run from the Mac:** SSH as `nosuchuser` (bogus user) and as `emre` with a throwaway key (wrong key), spaced 6 s apart. **Run on the VM against 127.0.0.1:** a burst of 10 bogus-user attempts, because ufw's `limit` rule blocks bursts from outside and loopback is exempt. | rule 5710 (invalid user), 5760-range (auth failed), 5712 (brute force). Local rule 100100 is added if "Failed publickey" has no stock rule |
| `fim-etc.sh` | Create `/etc/wazuh-lab-test.conf`, edit it (with the diff shown in the alert), `chmod` it, delete it. Also appends a comment to `/etc/hosts` and reverts it. | rules 554 (added), 550 (modified, with diff), 553 (deleted) |
| `vuln-downgrade.sh` | Downgrades `rsync` to the 24.04 release build (which has known CVEs, fixed in noble-security) and puts it on `apt-mark hold`, so unattended-upgrades can't quietly fix it mid-demo. Waits for the next syscollector scan. `--revert` removes the hold and upgrades it. | new entries in the Vulnerability Detection dashboard for `rsync`, with CVE, severity and fixed version |

Every trigger prints the dashboard path, the rule IDs and a search query, e.g.
`rule.groups:authentication_failed AND agent.name:ubuntu-lab`. Screenshots go in
`screenshots/<trigger>-{before,after}.png`.

## 5. Windows agent (later; nothing built now)

Once windows-lab exists on the same UTM subnet:
```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.X-1.msi -OutFile $env:TEMP\wazuh-agent.msi
msiexec.exe /i $env:TEMP\wazuh-agent.msi /q WAZUH_MANAGER="192.168.64.2" WAZUH_AGENT_NAME="windows-lab" WAZUH_AGENT_GROUP="default"
NET START WazuhSvc
```
- **Version:** match the manager's exact 4.14.x; an agent must not be newer than its manager.
- **Traffic:** it enrolls on 1515 and sends events on 1514, which the ufw rules already allow
  from the subnet.
- **Planned Windows triggers:** failed RDP or local logins (event 4625), FIM on
  `C:\Windows\System32\drivers\etc`, and missing KBs in the vulnerability data.

## 6. THEORY-OF-OPERATIONS.md outline

1. **Components:**
   - agent: logcollector, syscheck, syscollector, rootcheck
   - manager: remoted, authd, analysisd, the vulnerability detector, filebeat-style shipping
   - indexer (OpenSearch)
   - dashboard
2. **Data flow:** event → agent → 1514 (AES) → remoted → analysisd (decoders, then rules) →
   `alerts.json` → indexer (`wazuh-alerts-*`) → dashboard. Enrollment goes over 1515.
3. **Ports and trust:** the table from §2. Indexer certificates come from the install tar.
   Explain why 9200 stays local.
4. **Rules and alerts:** decoder, rule match, level, groups. Also frequency rules (5712), how
   local rules extend the stock set (100100), and the alert level threshold.
5. **The three dashboards:** for each one, the data source, what triggers it, the rule IDs and
   the query.
   - failed logins: auth.log → sshd decoder → 5710/5712/5760
   - FIM: syscheck realtime via inotify → 550/553/554, with the diff
   - vulnerabilities: syscollector inventory × CTI feed → `wazuh-states-vulnerabilities-*`
6. **Interaction with hardening-lab:**
   - ufw limit shapes the brute-force demo
   - `LogLevel VERBOSE` enables the publickey-failure alerts
   - auditd feeds extra events
   - unattended-upgrades explains why `apt-mark hold` is needed for the demo

## 7. Risks

| Risk | Mitigation |
|------|------------|
| **RAM.** The recommended size for all-in-one is 8 GB; we have 6. The indexer can be OOM-killed, or the dashboard shows "server not ready". | 2 GB heap cap. Stop the other VMs during installs. Check `free -m` and `journalctl -u wazuh-indexer` first. If it still doesn't fit, raise the VM to 8 GB (the Mac has 16), which is a VM config change and needs your approval. |
| **arm64 packages.** Officially supported since 4.x, but individual arm64 builds occasionally lag x86. | Preflight downloads the package list for `4.14` and checks that arm64 `.deb` files exist before installing. If any is missing, drop to the latest 4.13 that has all three. |
| **ufw.** Rules that are too tight block agents; the limit rule blocks trigger bursts. | Test with `ss -tlnp` and `nc -vz` from the Mac for each port. Run the burst trigger over loopback. |
| **Hardening side effects.** The `UMASK 027` and core-dump settings could affect the Wazuh services or their files; `snapd` being masked doesn't matter. | Run `install.sh` in a fresh sudo session. If a service fails, check file ownership under `/var/ossec` and `/etc/wazuh-*` first. |
| **Install assistant fails partway** (certificates, a download timeout, a health check). | `wazuh-install.sh -u` uninstalls everything, then retry once with `-o` (overwrite). If it fails again, use the manual step-by-step install from the docs: indexer (certificates, `node.name`, `securityadmin`), then manager and filebeat, then dashboard. Worst case, reset from the `ubuntu-lab-hardened` clone. |
| **Vulnerability feed:** slow first download, or blocked outbound access. | Check `curl -I https://cti.wazuh.com` from the VM first. The dashboard can show nothing for about an hour on the first run, so don't mistake that for a failure. |
| **Windows agent on ARM64.** The Windows MSI is built for x86/x64; native ARM64 support is unclear. | Confirm on Wazuh's packages list before the Windows step. It probably runs under Windows' x64 emulation. |
| **Disk.** 40 GB, with about 4 GB used. Indexes grow. | No retention policy (dropped from scope). Check `df -h /` when the lab is resumed; delete old `wazuh-alerts-*` indices by hand if needed. |

## Build order (next steps, after approval)

1. `.gitignore` and the layout. 2. `install.sh`, dry-run preflight only. 3. Clone
   `ubuntu-lab-hardened`. 4. Install. 5. Firewall. 6. Configure. 7. Triggers, with
   screenshots. 8. THEORY-OF-OPERATIONS.md and the Mermaid diagram. 9. Windows agent, once
   windows-lab exists.
