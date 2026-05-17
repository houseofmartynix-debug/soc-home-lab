# HUNT-001 — Persistence via Run Keys & Scheduled Tasks

| Field | Value |
|---|---|
| Hunter | (you) |
| Date | 2026-05-15 |
| MITRE | T1547.001 (Run Keys), T1053.005 (Scheduled Tasks) |
| Status | Complete — new detection drafted |

## 1. Hypothesis

If an attacker established a foothold on any lab endpoint in the last 7 days, they likely created persistence via:
- A new HKCU/HKLM `\Software\Microsoft\Windows\CurrentVersion\Run` value, OR
- A new Scheduled Task pointing to a non-standard binary path

A junior SOC analyst should be able to baseline what "normal" looks like in the lab and spot the outliers.

## 2. Data

- Sysmon Event ID 13 (RegistryValueSet) → captures Run-key writes
- Sysmon Event ID 1 (ProcessCreate) → captures `schtasks.exe` invocations
- Windows Security 4698 (Scheduled Task Created)

## 3. Queries

### 3.1 — Run key writes in the last 7 days

```kql
data.win.system.channel:"Microsoft-Windows-Sysmon/Operational"
  AND data.win.system.eventID:"13"
  AND data.win.eventdata.targetObject:*\\CurrentVersion\\Run*
  AND @timestamp:[now-7d TO now]
| stats values(data.win.eventdata.image) by agent.name, data.win.eventdata.targetObject
```

### 3.2 — Scheduled task creations

```kql
(data.win.system.eventID:"4698"
 OR (data.win.system.eventID:"1" AND data.win.eventdata.image:*\\schtasks.exe))
  AND @timestamp:[now-7d TO now]
| sort by @timestamp desc
```

## 4. Findings

Lab dataset (5 endpoints, 7 days):

| Run-key writes | Scheduled tasks |
|---|---|
| 12 | 18 |

After baselining (Microsoft Edge updater, OneDrive, vendor auto-start) the residue was:

- **win10-01**: `HKCU\...\Run\UpdaterSvc → C:\Users\Public\u.exe` — **suspicious**. Not signed, not in baseline.
- **win10-01**: scheduled task `\GoogleUpdateTaskCore` pointing to `%TEMP%\g.exe` — **suspicious**.

Both traced back to my own **Atomic Red Team T1547.001 test** earlier in the week — known/expected. Cleaned up.

No unexpected findings on other hosts.

## 5. Output

- Drafted **rule 100210** (planned) — alert on Run-key write where the target binary is in `C:\Users\Public`, `%TEMP%`, or `%APPDATA%` (rare for legit software).
- Drafted **rule 100211** (planned) — alert on scheduled task creation whose action path is outside `Program Files`, `Windows`, `ProgramData`.
- Documented the lab's baseline of expected Run keys / tasks so future hunts are faster.

**Hunt verdict:** No live intrusion. Detection ideas captured. Will repeat monthly.
