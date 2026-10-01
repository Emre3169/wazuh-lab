# wazuh-lab

A single-node Wazuh SIEM lab on an Apple Silicon Mac. It watches a hardened Ubuntu VM and a
hardened Windows VM, and has a repeatable trigger for every detection it demonstrates.
The VMs and their hardening come from the companion repo **hardening-lab**.

- **Design:** [PLAN.md](PLAN.md)
- **How it works, with observed results:** [THEORY-OF-OPERATIONS.md](THEORY-OF-OPERATIONS.md)
- **Network and ports:** [docs/network-diagram.md](docs/network-diagram.md)

## What's running

| Component | Where | Details |
|-----------|-------|---------|
| Wazuh **manager 4.14.8** (all-in-one: manager, indexer, dashboard, filebeat) | ubuntu-lab, 192.168.64.2 (Ubuntu 24.04.5 ARM64, 6 GB) | indexer heap capped at 2 GB; Wazuh apt repo turned off so it stays on 4.14 |
| **Agent 000**, the manager watching itself | ubuntu-lab | FIM on `/etc` in real time, `auth.log`, `audit.log`, syscollector |
| **Agent 001**, `windows-lab` | 192.168.64.3 (Windows 11 Pro ARM64, build 26300) | Wazuh agent 4.14.8 (x86 MSI under emulation), enrolled over 1515, events over 1514 |
| Dashboard | https://192.168.64.2 | reachable from the Mac only (ufw), user `admin`; the password is in `secrets/` (gitignored), never in this repo |

The dashboard's Endpoints page lists only agent 001. The manager's own agent 000 is active
but is never shown there.

## The three dashboards, and what fired

| Dashboard | Agent | Rule IDs observed | Trigger |
|-----------|-------|-------------------|---------|
| **Failed logins** | ubuntu-lab | **5710** non-existent user (×21), **5716** auth failed / wrong key (×2), **5712** brute force (×1) | `triggers/failed-ssh.sh` |
| | windows-lab | **60122** logon failure, unknown user or bad password (event 4625, sub-status `0xc0000064`) | `triggers/windows-failed-logon.ps1` |
| **File integrity** | ubuntu-lab | **554** added, **550** modified (with diff), **553** deleted, under `/etc` | `triggers/fim-etc.sh` |
| | windows-lab | **554** / **550** / **553** in `C:\Windows\System32\drivers\etc` | `triggers/windows-fim.ps1` |
| **Vulnerability detection** | windows-lab | **CVE-2023-1386** (High, 7.8) and **CVE-2021-20255** (Medium, 5.5), both in the QEMU guest agent 109.1.0 | found by itself after enrollment |
| | ubuntu-lab | none (see Known limitation) | `triggers/vuln-downgrade.sh` |

Bonus: the Windows agent's SCA module evaluates the CIS Microsoft Windows 11 Enterprise
Benchmark v3.0.0 (rules 19004–19009).

## Running the triggers

All commands run from the repo root on the Mac. SSH goes through
`~/Developer/hardening-lab/.ssh/config`. Each trigger prints the dashboard, the rule IDs and a
query to check.

```sh
# ubuntu-lab: failed SSH logins (bogus user + wrong key from the Mac, a 10-attempt burst on the VM)
triggers/failed-ssh.sh

# ubuntu-lab: FIM under /etc (realtime; everything is reverted)
setup/run-remote.sh triggers/fim-etc.sh

# ubuntu-lab: downgrade rsync to a vulnerable build and hold it; undo with --revert
setup/run-remote.sh triggers/vuln-downgrade.sh
setup/run-remote.sh triggers/vuln-downgrade.sh --revert
```

On windows-lab, copy the scripts once, then run them over SSH (elevated PowerShell):

```sh
H="ssh -F $HOME/Developer/hardening-lab/.ssh/config -o WarnWeakCrypto=no windows-lab"
scp -F ~/Developer/hardening-lab/.ssh/config triggers/windows-*.ps1 windows-lab:C:/wazuh-lab/

# 6 failed SMB logons as a user that doesn't exist -> event 4625 -> rule 60122
$H 'Set-ExecutionPolicy -Scope Process Bypass -Force; & C:\wazuh-lab\windows-failed-logon.ps1'

# FIM in drivers\etc. The default agent config scans it every 12 h, so force a scan from the
# manager after each step to see 554, then 550, then 553:
for s in create modify delete; do
  $H "Set-ExecutionPolicy -Scope Process Bypass -Force; & C:\wazuh-lab\windows-fim.ps1 -Step $s"
  ssh -F ~/Developer/hardening-lab/.ssh/config ubuntu-lab 'sudo /var/ossec/bin/agent_control -r -u 001'
  sleep 40   # stays under ubuntu-lab's ufw SSH rate limit
done
```

ubuntu-lab rate-limits SSH (`ufw limit`, 6 new connections in 30 s). Keep loops slow, or reuse
one connection; `setup/run-remote.sh` does that for you.

## Known limitation: no vulnerability scan of the manager itself

Wazuh 4.14.8 never scans the manager's own packages (agent 000).
- **Debug log:** `Vulnerability scanner in manager still disabled`.
- **Not the cause:** the feed (9.9 GB, downloaded cleanly), the indexer connection and the
  credentials were each ruled out one by one.
- **The agent path works:** windows-lab produced its 2 CVEs within minutes of enrolling.
- **So:** ubuntu-lab's rsync downgrade doesn't show up.
- **For Linux coverage,** enroll another VM (for example `ubuntu-lab-hardened`) as a regular
  agent.

The full diagnosis is in THEORY-OF-OPERATIONS.md §7.

## Screenshots

| File | Shows |
|------|-------|
| [screenshots/agents.jpeg](screenshots/agents.jpeg) | Endpoints: agent 001 windows-lab, 192.168.64.3, Windows 11 Pro, v4.14.8, active |
| [screenshots/failed-logins-after.jpeg](screenshots/failed-logins-after.jpeg) | Threat Hunting, `rule.groups:authentication_failed`: 5710 on ubuntu-lab |
| [screenshots/fim-after.jpeg](screenshots/fim-after.jpeg) | File Integrity Monitoring events on ubuntu-lab: 554 / 550 / 553 under `/etc` |
| [screenshots/windows-logons.jpeg](screenshots/windows-logons.jpeg) | Threat Hunting, `agent.name:windows-lab AND rule.id:60122`: 2 logon failures |
| [screenshots/windows-events.jpeg](screenshots/windows-events.jpeg) | Threat Hunting, all windows-lab events: 981 in 24 h (process creation, time changes, …) |
| [screenshots/vuln-windows.jpeg](screenshots/vuln-windows.jpeg) | Vulnerability Detection inventory: the two QEMU guest agent CVEs on windows-lab |

## Layout

```
setup/      install.sh, firewall.sh, configure.sh, run-remote.sh, fetch-secrets.sh (Ubuntu manager)
            windows-agent.ps1 (Windows agent enrollment)
triggers/   failed-ssh.sh, fim-etc.sh, vuln-downgrade.sh, windows-failed-logon.ps1, windows-fim.ps1
docs/       network-diagram.md
screenshots/
secrets/    gitignored: install tar and passwords
```
