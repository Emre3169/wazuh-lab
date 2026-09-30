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

### 5.3 Vulnerability detection: not producing results yet

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

## 6. How hardening-lab shapes this lab

| hardening-lab setting | Effect on Wazuh |
|-----------------------|-----------------|
| `ufw limit OpenSSH` | The brute-force burst has to run over loopback. `run-remote.sh` retries 10 s apart, because 5 s apart locked it out after a reboot (6 `UFW LIMIT BLOCK` entries). |
| sshd `LogLevel VERBOSE` | Wrong-key attempts are logged, so rule 5716 fires |
| auditd rules | `audit.log` is collected (a default `localfile`); these events are extra material for demos |
| unattended-upgrades | It would quietly re-patch rsync, hence the `apt-mark hold` |
| `UMASK 027` | `install.sh` and `configure.sh` set `umask 022` so Wazuh's service users can read their own files |
| Mac on battery with 1-minute sleep | The first install attempt died when the Mac idle-slept for 16 minutes during the API step, and the installer rolled itself back. It succeeded on AC power, run in the foreground. |

## 7. Open issues

### Vulnerability detection doesn't scan the manager (agent 000)

**Status:** open as of 2026-09-30 13:10 UTC. The Vulnerability Detection dashboard is empty.

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
2. Get a **second agent**. The Windows VM agent (PLAN.md §5) is scanned by the agent path,
   not the manager path, so if the problem is only the manager policy, windows-lab should
   show vulnerabilities.
3. Or enroll a lightweight Linux agent on another VM as a control.

**Leftovers:** `wazuh_modules.debug=2` was reverted in `local_internal_options.conf` but stays
active until the next manager restart. At idle it adds almost nothing to `ossec.log` (it
measured 0 KB/min); the 62,908 debug lines were a one-off burst at startup.
