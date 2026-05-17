# IR-005 — Ransomware Outbreak

| Attribute | Value |
|---|---|
| Severity | Critical |
| MITRE Tactic | Impact (T1486 — Data Encrypted for Impact) |
| Trigger | FIM mass-change alert, ransom note detected, user reports |
| Estimated Time | War-room until contained |

> **First rule of ransomware response: contain before you investigate.** Every minute of delay = more encrypted files.

## 1. Detection — Indicators

- Mass file-rename events in Wazuh File Integrity Monitoring
- New file extensions appearing org-wide (e.g., `.locked`, `.encrypted`, `.<random>`)
- Shadow copy deletion: `vssadmin delete shadows /all /quiet`
- Ransom note files (`README*.txt`, `HOW_TO_DECRYPT*`) created across many directories
- Sudden spike in CPU + disk write on file servers

## 2. Containment — DO THIS FIRST

- [ ] **Disconnect** affected hosts from the network (pull cable / disable virtual NIC / EDR isolation).
- [ ] **Disable** the originating user account.
- [ ] **Block** SMB (445/tcp) and admin shares between segments at the firewall to slow lateral spread.
- [ ] **Notify** the incident commander (Tier 2 lead / CISO on-call). Open a war-room channel.
- [ ] Do **not** power off — RAM may contain decryption keys or active attacker session.

## 3. Investigation (in parallel with containment)

- [ ] Identify patient zero: earliest encryption timestamp + initial access vector.
- [ ] Capture ransom note + sample encrypted file → submit to ID Ransomware / NoMoreRansom.
- [ ] Enumerate all hosts with the new extension across the org (Wazuh FIM, EDR).
- [ ] Check backups — are they reachable / intact / also encrypted?
- [ ] Look for data **exfiltration** before encryption (double-extortion is the norm) — pivot to IR-004.

## 4. Eradication & Recovery

- [ ] Reimage all affected hosts from clean baselines.
- [ ] Restore data from offline backups verified clean.
- [ ] Rotate **all** privileged credentials (domain admin, service accounts, vault secrets).
- [ ] Patch the entry-point vulnerability before reconnecting hosts.

## 5. Post-Incident

- [ ] Engage law enforcement (in IDN: BSSN / Cyber Crime Polri; report via ID-SIRTII channels). In the US: FBI IC3.
- [ ] Engage cyber insurance carrier (if applicable) — they often mandate specific IR vendors.
- [ ] Public/customer comms drafted by legal + comms, not IT.
- [ ] **Never** pay the ransom on your own authority — that is a board-level decision with legal and regulatory implications (OFAC sanctions).
- [ ] Full root-cause analysis + remediation roadmap within 30 days.

## Decision Matrix — Pay or Not?

Pay/no-pay is **never** a SOC decision. Escalate to executive + legal. Provide them with:
- Technical viability of decryption (do free decryptors exist on NoMoreRansom?)
- Backup recovery viability + estimated time
- Sanctions check on the threat actor
- Data exfiltration confirmation (does paying actually solve the leak?)
