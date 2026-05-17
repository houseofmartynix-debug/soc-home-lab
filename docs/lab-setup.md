# Lab Setup Guide

End-to-end instructions to reproduce this lab on any virtualization platform (VirtualBox, VMware Workstation, Proxmox, Hyper-V).

## Prerequisites

- Host machine with **16 GB RAM** and at least **100 GB free disk**
- Hypervisor of your choice
- ISOs:
  - Ubuntu Server 22.04 LTS (Wazuh)
  - Ubuntu Server 22.04 LTS (target server)
  - Windows 10 / 11 evaluation
  - pfSense CE
  - Kali Linux

## Network Plan

A single internal network `10.0.0.0/24` with pfSense as the gateway:

| Host | IP | Role |
|---|---|---|
| pfSense | 10.0.0.1 | Gateway / firewall |
| Wazuh manager | 10.0.0.10 | SIEM |
| Windows 10 | 10.0.0.20 | Endpoint (agent) |
| Ubuntu Server | 10.0.0.30 | Endpoint (agent) |
| Kali | 10.0.0.50 | Attack host |

## Step 1 — Wazuh All-in-One

Detailed in [wazuh-installation.md](wazuh-installation.md).

## Step 2 — Onboard Windows Endpoint

1. On the Wazuh dashboard, go to **Agents → Deploy new agent → Windows**.
2. Copy the generated PowerShell installer command and run it as **Administrator** on the Windows host.
3. Install **Sysmon** with the SwiftOnSecurity config for rich telemetry:

```powershell
Invoke-WebRequest -Uri https://live.sysinternals.com/Sysmon64.exe -OutFile C:\Tools\Sysmon64.exe
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Tools\sysmonconfig.xml
C:\Tools\Sysmon64.exe -accepteula -i C:\Tools\sysmonconfig.xml
```

4. Tell the Wazuh agent to read the Sysmon channel. Edit `C:\Program Files (x86)\ossec-agent\ossec.conf` and add:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

5. Restart the agent service: `Restart-Service WazuhSvc`.

## Step 3 — Onboard Linux Endpoint

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-agent_4.7.0-1_amd64.deb
sudo WAZUH_MANAGER='10.0.0.10' WAZUH_AGENT_GROUP='linux-servers' \
  dpkg -i ./wazuh-agent_4.7.0-1_amd64.deb
sudo systemctl enable --now wazuh-agent
```

## Step 4 — pfSense Syslog Forwarding

1. **Status → System Logs → Settings**.
2. Enable **Send log messages to remote syslog server**.
3. Remote server: `10.0.0.10:514`, protocol UDP.
4. Tick **Firewall events** and **Everything**.

On the Wazuh manager, ensure `/var/ossec/etc/ossec.conf` listens for syslog from pfSense:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>10.0.0.1</allowed-ips>
</remote>
```

Restart: `sudo systemctl restart wazuh-manager`.

## Step 5 — Verify Telemetry

In the Wazuh dashboard:
- **Agents** → confirm all three agents show **Active**.
- **Discover** → confirm events arriving from `agent.name = windows-01`, `ubuntu-01`, and `pfsense`.

If anything is missing, the [troubleshooting checklist](#troubleshooting) below covers the usual suspects.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Agent stuck on **Never connected** | Firewall blocking 1514/tcp | Allow on pfSense + host firewall |
| No Sysmon events on Windows | `localfile` block missing | Verify edit + restart WazuhSvc |
| pfSense syslog empty in Wazuh | UDP/514 blocked or wrong allowed-ips | tcpdump on manager: `sudo tcpdump -i any port 514` |
| Dashboard 502 after install | Indexer not ready yet | `sudo systemctl status wazuh-indexer` and wait |
