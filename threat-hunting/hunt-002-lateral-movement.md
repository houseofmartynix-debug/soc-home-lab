# HUNT-002 — Lateral Movement via SMB / WMI

| Field | Value |
|---|---|
| Hunter | (you) |
| Date | 2026-05-16 |
| MITRE | T1021.002 (SMB/Admin Shares), T1047 (WMI), T1021.001 (RDP) |
| Status | Complete — coverage gap documented |

## 1. Hypothesis

If an attacker compromised a workstation, they would attempt to spread to other endpoints using built-in admin protocols, since they leave less artifact than dropping a new tool. Specifically:

- Mounting `\\target\C$` or `\\target\ADMIN$` from a user workstation (T1021.002)
- Running `wmic /node:target process call create ...` (T1047)
- Outbound RDP (3389) from a non-IT user host (T1021.001)

## 2. Data

| Source | Event | Signal |
|---|---|---|
| Windows Security | 5140 | A network share object was accessed |
| Sysmon | 3 (NetworkConnect) | Outbound 445, 5985, 3389 from user workstations |
| Sysmon | 1 (ProcessCreate) | `wmic.exe`, `psexec`, `winrs`, `net use \\...` |

## 3. Queries

### 3.1 — Unusual SMB peers

```kql
data.win.system.eventID:"3"
  AND data.win.eventdata.destinationPort:"445"
  AND NOT data.win.eventdata.destinationIp:(10.0.0.10 OR 10.0.0.30)   // file server, wazuh
  AND agent.name:win10-*
| stats count by agent.name, data.win.eventdata.destinationIp
```

### 3.2 — WMI remote process invocation

```kql
data.win.eventdata.image:*\\wmic.exe
  AND data.win.eventdata.commandLine:(*"/node:"* AND *"process call create"*)
```

### 3.3 — RDP from non-IT user

```kql
data.win.system.eventID:"3"
  AND data.win.eventdata.destinationPort:"3389"
  AND NOT data.win.eventdata.user:(it_* OR admin_*)
```

## 4. Findings

- **0 hits** on all three queries across 7 days. As expected in a quiet lab.
- However, this hunt exposed a **coverage gap**: I have no native detection rule for any of these three TTPs. The hunt queries above are the only thing that would surface them today.

## 5. Output

Three detection-engineering tickets opened (in this repo as future rules):
1. `rule 100220` — outbound 445 from a workstation to a non-server peer.
2. `rule 100221` — `wmic.exe` with `/node:` + `process call create`.
3. `rule 100222` — outbound 3389 from a non-IT user account.

**Hunt verdict:** Quiet environment (good) + visible gap (also good, now we know).
