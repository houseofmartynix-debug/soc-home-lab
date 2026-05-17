# MITRE ATT&CK Coverage Matrix

Mapping of every detection rule and playbook in this lab to the [MITRE ATT&CK for Enterprise](https://attack.mitre.org/) framework.

## Why Map to ATT&CK

ATT&CK is the lingua franca of modern SOCs. When an analyst says "we have a gap in **TA0008 — Lateral Movement**", everyone understands what coverage is missing. Mapping every detection to a technique:

- Surfaces blind spots
- Communicates coverage to leadership in a standard vocabulary
- Aligns detection engineering with red team / purple team exercises

## Coverage Matrix

| Tactic | Technique ID | Technique Name | Detection | Playbook |
|---|---|---|---|---|
| Initial Access | T1078 | Valid Accounts | [suspicious-login-time.yml](../detection-rules/sigma-rules/suspicious-login-time.yml) | — |
| Initial Access | T1110.001 | Password Guessing | [0100-bruteforce-ssh.xml](../detection-rules/wazuh-custom-rules/0100-bruteforce-ssh.xml) | [IR-002](../playbooks/IR-002-bruteforce-attack.md) |
| Initial Access | T1566.001 | Phishing — Attachment | — (manual triage) | [IR-003](../playbooks/IR-003-phishing-email.md) |
| Execution | T1059.001 | PowerShell | [0101-suspicious-powershell.xml](../detection-rules/wazuh-custom-rules/0101-suspicious-powershell.xml) | [IR-001](../playbooks/IR-001-malware-infection.md) |
| Defense Evasion | T1562.001 | Disable or Modify Tools | [windows-defender-disabled.yml](../detection-rules/sigma-rules/windows-defender-disabled.yml) | [IR-001](../playbooks/IR-001-malware-infection.md) |
| Credential Access | T1003 | OS Credential Dumping | [0102-mimikatz-detection.xml](../detection-rules/wazuh-custom-rules/0102-mimikatz-detection.xml) | [IR-001](../playbooks/IR-001-malware-infection.md) |
| Exfiltration | T1048 | Exfil Over Alt Protocol | [0103-data-exfiltration.xml](../detection-rules/wazuh-custom-rules/0103-data-exfiltration.xml) | [IR-004](../playbooks/IR-004-data-exfiltration.md) |
| Impact | T1486 | Data Encrypted for Impact | — (file-integrity monitoring) | [IR-005](../playbooks/IR-005-ransomware.md) |

## Visualizing Coverage

Export the matrix above to the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) by importing `coverage-layer.json` (planned, see roadmap).

## Known Gaps (Honest Assessment)

| Tactic | Status | Note |
|---|---|---|
| Reconnaissance (TA0043) | No coverage | External recon hard to see without NDR |
| Resource Development (TA0042) | No coverage | Attacker infra, not on our wire |
| Persistence (TA0003) | Partial | Need Run-key + scheduled-task detections |
| Lateral Movement (TA0008) | Partial | Need PsExec / WMI / RDP detections |
| Command and Control (TA0011) | No coverage | Need DNS + JA3 telemetry |

These gaps drive the [roadmap](../README.md#roadmap).
