# Theory of operations

How the Wazuh lab works, with the values observed on 2026-09-30. For the build steps see
PLAN.md; the diagram is in [docs/network-diagram.md](docs/network-diagram.md).

## 1. Components

All components run on **ubuntu-lab** (Ubuntu 24.04.5 ARM64, 4 vCPU, 5.9 GB usable RAM).
They were installed with `wazuh-install.sh -a -i` (Wazuh **4.14.8**) in about 2 minutes.

| Component | Role here | Notes |
|-----------|-----------|-------|
| **agent 000** | The manager watching itself: `wazuh-syscheckd` (FIM), `wazuh-logcollector` (logs), `syscollector` (inventory), rootcheck, SCA | `agent_control -l` shows `ID: 000, ubuntu-lab (server), 127.0.0.1, Active/Local` |
| **wazuh-manager** | `remoted` (1514), `authd` (1515), `analysisd` (decoders and rules), `wazuh-db`, `modulesd` (vulnerability scanner, content manager, inventory harvester), `apid` (55000) | Peaked at 1.5 GB RSS during install |
| **filebeat** | Ships `alerts.json` to the indexer | `wazuh-alerts-*` had 880 documents after the triggers |
| **wazuh-indexer** | OpenSearch, holding alerts and inventory/vulnerability state | Heap capped at **2 GB** (`-Xmx2g` via `jvm.options.d`); bound to 127.0.0.1:9200 |
| **wazuh-dashboard** | Web UI on 443 | https://192.168.64.2, reachable from the Mac only |

With everything running, about **2.6 GB** of RAM stays available.

## 2. Data flow

```
log line / file change / package list
  -> agent 000 module (logcollector | syscheckd | syscollector)
  -> local queue (a remote agent would use 1514/tcp, AES-encrypted; enrolled over 1515)
  -> analysisd: pre-decoding -> decoder -> rules -> alert (if level >= 3)
  -> /var/ossec/logs/alerts/alerts.json
  -> filebeat -> wazuh-indexer (wazuh-alerts-4.x-*) -> dashboard

inventory (syscollector) -> wazuh-db -> inventory harvester / vulnerability scanner
  (matched against the CTI feed in /var/ossec/queue/vd, 9.7 GB)
  -> indexer-connector -> wazuh-states-* indices -> dashboard
```

Alerts and state travel on **separate paths**. Alerts go through filebeat; inventory and
vulnerability state go through modulesd's indexer-connector. One can work while the other
doesn't, which is what happened here (§5.3).

## 3. Ports and trust

| Port | Service | Exposure |
|------|---------|----------|
| 443 | dashboard | ufw: 192.168.64.1 only |
| 1514 / 1515 | agent events / enrollment | ufw: 192.168.64.0/24 |
| 55000 | API | listens on 0.0.0.0 but ufw blocks it; the dashboard uses localhost |
| 9200 | indexer | bound to 127.0.0.1; never exposed |

- **Certificates:** the TLS certificates between filebeat, the manager, the indexer and the
  dashboard come from `wazuh-install-files.tar`. That file now lives only in `secrets/` on
  the Mac (gitignored, mode 600) and was removed from the VM.
- **Why 9200 stays local:** anyone who reaches it with the admin credentials can read or
  delete every alert. There's no reason for it to leave the VM.

## 4. Rules and alerts

- **Decoders** turn a raw line into fields: program name, source IP, user.
- **Rules** match those fields and give the alert a **level** (0–15) and **groups**.
  Alerts at level 3 or above are written to `alerts.json`.
- **Composite rules** fire when a child rule repeats within a time window. For example,
  **5712** fires after 8 × 5710 from the same source within 120 s.
- **Local rules** go in `/var/ossec/etc/rules/local_rules.xml` with IDs 100000 and up.
  `configure.sh` tests a sample "Failed publickey" line with `wazuh-logtest` first. Stock rule
  **5716** already matched it, so local rule 100100 was **not** needed.

## 5. The three dashboards

### 5.1 Failed logins: working

- **Source:** `/var/log/auth.log`, collected as syslog, into the sshd decoder.
- **Trigger:** `triggers/failed-ssh.sh`.
  - From the Mac: one attempt as the bogus user `nosuchuser`, and one as `emre` with a
    throwaway key, 6 s apart.
  - On the VM over loopback: a burst of 10 attempts as `labbrute1-10`.
- **Why the burst runs on the VM:** from the Mac, `ufw limit` would reject the 7th
  connection within 30 s. Loopback traffic is exempt.
- **Why wrong-key attempts are visible:** hardening-lab set sshd to `LogLevel VERBOSE`. At
  INFO, a rejected key only shows up as "Connection closed".

Observed at 12:15 UTC:

| Rule | Level | Count | Meaning |
|------|------:|------:|---------|
| 5710 | 5 | 21 | attempt to log in as a non-existent user (two log lines per attempt) |
| 5716 | 5 | 2 | authentication failed, including `Failed publickey for emre` |
| 5712 | 10 | 1 | brute force: non-existent user |
| 5715 | 3 | 6 | successful login (the operator's own key logins; normal activity) |

**Dashboard:** Threat Hunting → `rule.groups:authentication_failed`.

### 5.2 File integrity: working

- **Source:** `wazuh-syscheckd` watches `/etc` with `realtime="yes" report_changes="yes"
  check_all="yes"`, using 258 inotify watches.
- **No diffs of secrets:** `/etc/shadow`, `/etc/gshadow` and the SSH host keys are set to
  `nodiff`, so alerts never contain password hashes or private keys.
- **Trigger:** `triggers/fim-etc.sh` creates, edits, `chmod`s and deletes
  `/etc/wazuh-lab-test.conf`, then appends to `/etc/hosts` and restores it.

Observed at 12:14 UTC, each event about 5 s apart:

| Rule | Level | Event | Path |
|------|------:|-------|------|
| 554 | 5 | added | /etc/wazuh-lab-test.conf |
| 550 | 7 | modified, with diff | /etc/wazuh-lab-test.conf (content) |
| 550 | 7 | modified, with diff | /etc/wazuh-lab-test.conf (chmod 600) |
| 553 | 7 | deleted | /etc/wazuh-lab-test.conf |
| 550 | 7 | modified, with diff | /etc/hosts (append) |
| 550 | 7 | modified, with diff | /etc/hosts (restore) |

**Dashboard:** File Integrity Monitoring → Events.

### 5.3 Vulnerability detection: works for agents, not for the manager itself

Status: working for windows-lab (§5.4), with 2 CVEs found. Still empty for ubuntu-lab, the
manager's own agent 000 (§7). The ubuntu-lab history:

- **Source:** syscollector's package inventory, matched against the Wazuh CTI feed. Results
  are written as **state** to `wazuh-states-vulnerabilities-ubuntu-lab`, not as ordinary
  alerts.
- **Trigger:** `triggers/vuln-downgrade.sh` downgraded rsync from `3.2.7-1ubuntu1.5` to the
  release build `3.2.7-1ubuntu1` (which has known CVEs), put it on `apt-mark hold`, and
  restarted the manager at 12:16.

What was observed, as of 12:23 UTC:

| Check | Result |
|-------|--------|
| CTI feed downloaded | yes: 9.7 GB in `/var/ossec/queue/vd`, "Feed update process completed" |
| Inventory collected | yes: wazuh-db holds **711** packages for agent 000 |
| Inventory in the indexer | **no**: all 14 `wazuh-states-*-ubuntu-lab` indices have 0 documents |
| indexer-connector queue | **433 MB** waiting in `/var/ossec/queue/indexer` |
| Indexer authentication errors | none; no indexer warnings since 12:10 |
| Errors logged | one `VulnerabilityScannerFacade::start: Write failed` at 11:59:04, during the install, in the same second the installer rewrote the indexer credentials in the keystore |

The first reading, that the indexer-connector couldn't deliver, turned out to be **wrong**.
The debug run showed the connector delivers fine. The scanner simply never scans the manager.
See §7.

rsync stays downgraded and held so a working scan will find it. Undo with
`triggers/vuln-downgrade.sh --revert`.

### 5.4 Windows agent (windows-lab): all three dashboards working

**Enrollment** (`setup/windows-agent.ps1`, run over SSH as an elevated admin, on 2026-10-01
around 02:25 UTC):
- Downloaded `wazuh-agent-4.14.8-1.msi` (5.7 MB, Authenticode-signed by Wazuh), matching the
  manager's version.
- Installed silently with `WAZUH_MANAGER` and `WAZUH_REGISTRATION_SERVER=192.168.64.2` and
  `WAZUH_AGENT_NAME=windows-lab`, then `NET START WazuhSvc`.
- The x86 agent runs under Windows' x86 emulation on ARM64.
- It enrolls over 1515 and sends events over 1514. hardening-lab's Windows firewall allows
  outbound connections, and ubuntu-lab's ufw allows both ports from 192.168.64.0/24.
- `agent_control -l`: **ID 001, windows-lab, Active**, reporting "Microsoft Windows 11 Pro"
  and "Wazuh v4.14.8". It went Disconnected → Pending → Active within about 40 s while it
  restarted to apply the shared config the manager pushed.

**Failed logons** (`triggers/windows-failed-logon.ps1`):
- Six `net use \\127.0.0.1\IPC$ /user:nosuchuser wrongpass` attempts. Every attempt was
  refused (system error 1326), but Windows wrote **one** event 4625 per run, because the SMB
  client fails the repeats locally.
- `nosuchuser` doesn't exist, so hardening-lab's 5-attempt lockout can't lock a real account.

| Rule | Level | Count | Meaning |
|------|------:|------:|---------|
| **60122** | 5 | 2 (one per run) | Logon failure: unknown user or bad password. Event data: `targetUserName=nosuchuser`, status `0xc000006d`, sub-status `0xc0000064` (no such user), logon type 3, from 127.0.0.1 |
| 60104 | 5 | 2 | Windows audit failure event (generic parent) |

This only works because hardening-lab turned on failure auditing for Logon and Credential
Validation. Without it, Windows writes no 4625 events.

**File integrity** (`triggers/windows-fim.ps1`, in `C:\Windows\System32\drivers\etc`):
- The default agent config scans that folder every **12 h** (`frequency 43200`), not in real
  time. So each step was followed by a forced scan from the manager:
  `agent_control -r -u 001`. No config was changed.
- Each alert arrived about 20 s after its scan:

| Step | Rule | Level | Event |
|------|-----:|------:|-------|
| create `wazuh-lab-test.txt` | **554** | 5 | added |
| modify it | **550** | 7 | modified |
| delete it (the revert) | **553** | 7 | deleted |

**Vulnerability detection:** on the first check after enrollment,
`wazuh-states-vulnerabilities-*` held **2 entries for windows-lab**, and 30 packages were
inventoried. Both CVEs are in the **QEMU guest agent 109.1.0**, which UTM's guest tools
installed:

| CVE | Severity | CVSS |
|-----|----------|------|
| CVE-2023-1386 | High | 7.8 |
| CVE-2021-20255 | Medium | 5.5 |

**Configuration check (SCA):** the agent's first SCA run evaluated the CIS Microsoft Windows
11 Enterprise Benchmark v3.0.0 (rules 19004/19007/19008/19009). That gives a second, Wazuh-side
view next to hardening-lab's HardeningKitty score.

## 6. How hardening-lab shapes this lab

| hardening-lab setting | Effect on Wazuh |
|-----------------------|-----------------|
| `ufw limit OpenSSH` | The brute-force burst has to run over loopback. `run-remote.sh` retries 10 s apart, because 5 s apart locked it out after a reboot (6 `UFW LIMIT BLOCK` entries). |
| sshd `LogLevel VERBOSE` | Wrong-key attempts are logged, so rule 5716 fires |
| auditd rules | `audit.log` is collected (a default `localfile`); these events are extra material for demos |
| unattended-upgrades | It would quietly re-patch rsync, hence the `apt-mark hold` |
| `UMASK 027` | `install.sh` and `configure.sh` set `umask 022` so Wazuh's service users can read their own files |
| `ufw limit OpenSSH`, again | During the Windows FIM test, a loop that opened two new SSH connections to the manager per step hit the limit ("Connection refused") on its third step. It recovered after waiting about 45 s; poll over one connection instead. |
| Windows: Logon/Credential Validation failure auditing | Makes event 4625, and so rule 60122, possible at all |
| Windows: outbound firewall Allow | The agent reaches 1514/1515 on the manager with no extra Windows rule |
| Mac on battery with 1-minute sleep | The first install attempt died when the Mac idle-slept for 16 minutes during the API step, and the installer rolled itself back. It succeeded on AC power, run in the foreground. |

## 7. Open issues

### Vulnerability detection doesn't scan the manager (agent 000)

**Status:** open, but **narrowed down on 2026-10-01**. The second-agent test (next step 2
below) is done: windows-lab is scanned normally and produced 2 CVEs within minutes of
enrolling (§5.4). The feed, the scanner, the indexer-connector and the indexer all work. Only
the **manager self-scan** (agent 000) is off. The dashboard shows windows-lab's
vulnerabilities and nothing for ubuntu-lab.

**Ruled out, in order:**

| Attempt | Result |
|---------|--------|
| Waited about 10 min after the rsync downgrade and manager restart | 0 vulnerabilities, 0 packages in `wazuh-states-*` |
| Re-wrote the indexer credentials into the keystore (`wazuh-keystore -f indexer`) | credentials get HTTP 200 from the indexer; counts still 0 |
| Deleted `queue/vd`, `queue/vd_updater` and `queue/indexer`, then a clean feed download with no restarts | feed completed in 304 s (9.9 GB) and triggered a re-scan; counts still 0 after 20 min |
| Checked the `<indexer>` block | host `https://127.0.0.1:9200` matches the indexer's binding; all 3 cert files exist (root:root 400); TLS verifies |
| `wazuh_modules.debug=2`, one restart, 3 min of debug logs | see below |

**What debug logging showed** (13:06–13:09 UTC):
- The indexer-connector **does** reach the indexer. Its bulk responses say `"errors":false`.
  Everything it sent was **deletes**: 32 for `inventory-processes` and 7 for
  `inventory-ports`, meaning processes and ports that ended. It sent no inserts at all.
- The key line from the vulnerability scanner:
  `vulnerabilityScanPolicyChange(): DEBUG: Vulnerability scanner in manager still disabled`,
  followed by `handlePolicyChanges(): No policy has changed or no action is needed for the manager`.
- The package inventory itself exists: wazuh-db holds 711 packages for agent 000,
  including rsync `3.2.7-1ubuntu1`.

**Diagnosis:** the scanner's policy treats scanning of the manager's own packages as
**disabled**. Agent 000 is the only agent, so nothing is ever scanned or indexed. The loss is
not on the network or indexer side. The syscollector wodle on the manager *is* enabled
(`<disabled>no</disabled>`, `<packages>yes</packages>`), so it's still unexplained why the
scanner considers the manager disabled. The cause is inside Wazuh 4.14.8's scan-policy logic,
not in this lab's `ossec.conf` edits (the flow was the same before `configure.sh`, as §5.3
shows).

**Next steps, not yet done:**
1. Check the Wazuh 4.14 documentation and issue tracker for how manager scanning is enabled.
   There may be a separate setting, or a known issue on single-node or arm64 installs.
2. ~~Get a second agent.~~ **Done 2026-10-01:** windows-lab shows 2 CVEs, which confirms the
   agent path works.
3. For Linux coverage, enroll ubuntu-lab-hardened (or another VM) as a regular **agent**. It
   would be scanned on the agent path, and the rsync downgrade would show up there.

**Leftovers:** `wazuh_modules.debug=2` was reverted in `local_internal_options.conf` but stays
active until the next manager restart. At idle it adds almost nothing to `ossec.log` (it
measured 0 KB/min); the 62,908 debug lines were a one-off burst at startup.
