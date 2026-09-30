# Network diagram

The real values from the installed lab (2026-09-30): Wazuh 4.14.8 all-in-one on ubuntu-lab,
behind UTM's Shared (NAT) network.

```mermaid
flowchart LR
  subgraph mac["MacBook Air (host)"]
    browser["Browser<br/>https://192.168.64.2"]
    term["Terminal<br/>ssh -F hardening-lab/.ssh/config"]
  end

  subgraph utm["UTM Shared network 192.168.64.0/24 (NAT, gateway 192.168.64.1)"]
    subgraph vm["ubuntu-lab 192.168.64.2 (Ubuntu 24.04.5 ARM64, 4 vCPU, 6 GB)"]
      ufw{{"ufw (default deny)<br/>22 limit: any<br/>443: 192.168.64.1<br/>1514/1515: 192.168.64.0/24"}}
      dash["wazuh-dashboard<br/>0.0.0.0:443"]
      api["wazuh-apid<br/>0.0.0.0:55000<br/>(blocked by ufw)"]
      mgr["wazuh-manager<br/>remoted 1514 · authd 1515<br/>analysisd · modulesd"]
      agent0["agent 000<br/>(the manager itself)<br/>syscheck · logcollector · syscollector"]
      fb["filebeat"]
      idx[("wazuh-indexer<br/>127.0.0.1:9200<br/>heap 2 GB")]
    end
    win["windows-lab (planned)<br/>Wazuh agent"]
  end

  internet(("packages.wazuh.com<br/>cti.wazuh.com"))

  browser -- "443/tcp" --> ufw --> dash
  term -- "22/tcp" --> ufw
  dash -- "55000 (localhost)" --> api --> mgr
  dash -- "9200 (localhost)" --> idx
  agent0 -- "local queue" --> mgr
  mgr -- "alerts.json" --> fb -- "9200 (localhost)" --> idx
  mgr -- "states (indexer-connector)" --> idx
  win -. "1515 enroll · 1514 events" .-> ufw -.-> mgr
  mgr -- "vulnerability feed (outbound 443)" --> internet
```

## Ports

| Port | Listener | Bound to | Reachable from | Why |
|------|----------|----------|----------------|-----|
| 22/tcp | sshd | 0.0.0.0 | anywhere, rate-limited (`ufw limit`) | admin access; hardening-lab |
| 443/tcp | wazuh-dashboard | 0.0.0.0 | 192.168.64.1 (the Mac) only | web UI |
| 1514/tcp | wazuh-remoted | 0.0.0.0 | 192.168.64.0/24 | agent events (AES-encrypted) |
| 1515/tcp | wazuh-authd | 0.0.0.0 | 192.168.64.0/24 | agent enrollment |
| 55000/tcp | wazuh-apid | 0.0.0.0 | **VM only** (ufw blocks it) | the dashboard uses it over localhost |
| 9200/tcp | wazuh-indexer | 127.0.0.1 | **VM only** (not bound externally) | OpenSearch; filebeat, dashboard, indexer-connector |
| 1516/tcp | cluster | not listening | nobody | single node; no cluster |

From the Mac, 443 returns the login page. 9200 and 55000 both refuse connections (checked with
`nc -z` on 2026-09-30).
