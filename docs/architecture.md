# Lab Architecture

## Overview

This SOC home lab simulates a small enterprise environment with monitored endpoints, a perimeter firewall, and a centralized SIEM. The goal is to replicate the data flow a Tier 1 SOC analyst sees every day.

## Components

| Component | Role | Specs |
|---|---|---|
| **Wazuh Manager** | Rule engine, decoders, alerting | Ubuntu 22.04, 4 vCPU, 8 GB RAM |
| **Wazuh Indexer** | OpenSearch-based log storage | Same host (all-in-one) |
| **Wazuh Dashboard** | OpenSearch Dashboards UI | Same host (all-in-one) |
| **Windows 10 Endpoint** | Simulated user workstation | 2 vCPU, 4 GB RAM, Sysmon installed |
| **Ubuntu Server** | Simulated web server / SSH target | 2 vCPU, 2 GB RAM |
| **pfSense Firewall** | Perimeter, sends syslog to Wazuh | 1 vCPU, 1 GB RAM |
| **Kali Linux** | Attack simulation host | 2 vCPU, 4 GB RAM |

## Data Flow

1. **Endpoints (Windows/Linux)** run the Wazuh agent. It tails logs, monitors files, and ships events over TLS to the Wazuh manager.
2. **pfSense** forwards firewall logs via syslog (UDP/514) to the manager.
3. **Wazuh Manager** runs the event through its **decoders** (parse) and **rules** (match). Matched events generate alerts.
4. **Alerts** are written to `/var/ossec/logs/alerts/alerts.json` and indexed by the Wazuh indexer.
5. **Analyst** views, filters, and pivots on alerts in the Wazuh dashboard.

## Network Layout

```
        Internet
            |
        [pfSense]  <-- syslog --> Wazuh
         /       \
   [LAN 10.0.0.0/24]
   |       |        |
[Win10] [Ubuntu] [Kali]
   |       |
   +---agents---> [Wazuh Manager 10.0.0.10]
```

## Why This Layout

- **All-in-one Wazuh**: keeps lab requirements low; in production these would be separate clustered nodes.
- **Sysmon on Windows**: gives much richer telemetry than the default Security log (process creation w/ command line, network connections, file hashes).
- **pfSense**: realistic perimeter device whose logs surface scanning and outbound anomalies.
- **Kali**: dedicated red-team host so attacks come from a known, isolatable source — easy to clean up after tests.

## Adversary Simulation

Attacks are launched from Kali using:
- **Hydra / nmap** for brute force and recon
- **Atomic Red Team** for ATT&CK technique tests
- **Manual PowerShell** payloads for endpoint detection tuning

Every simulation is a controlled, lab-only exercise. See [../attack-simulations/](../attack-simulations/) for the specific tests run.
