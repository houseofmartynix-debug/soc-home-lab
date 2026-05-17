# Incident Response Playbooks

Playbooks turn ad-hoc analyst skill into **repeatable**, **auditable** response. Every playbook here follows the NIST SP 800-61r2 lifecycle:

1. **Preparation**
2. **Detection & Analysis**
3. **Containment, Eradication, Recovery**
4. **Post-Incident Activity**

## Playbook Index

| ID | Scenario | Severity |
|---|---|---|
| [IR-001](IR-001-malware-infection.md) | Endpoint Malware Infection | High |
| [IR-002](IR-002-bruteforce-attack.md) | Brute Force on Public Service | Medium |
| [IR-003](IR-003-phishing-email.md) | Phishing Email Reported by User | Medium |
| [IR-004](IR-004-data-exfiltration.md) | Suspected Data Exfiltration | Critical |
| [IR-005](IR-005-ransomware.md) | Ransomware Outbreak | Critical |

## How to Use

For every alert that matches a playbook:

1. Open a case in the SOC ticketing system (TheHive in the planned roadmap).
2. Paste the playbook checklist into the case.
3. Tick boxes as you execute each step. **Never** skip a step silently — annotate "N/A — reason" if it doesn't apply.
4. Attach evidence (screenshots, raw logs, hashes) to the case.
5. Close the case with a one-paragraph executive summary.

## Authoring Conventions

- One markdown file per playbook
- Checklist-driven so a junior analyst can execute under pressure
- Each playbook states explicit **escalation criteria** — when to wake the Tier 2 / IR lead
