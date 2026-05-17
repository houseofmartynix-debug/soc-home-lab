# Screenshots

Visual evidence of the lab in action. Add screenshots here as the lab is built out — visuals are far more convincing to recruiters than text alone.

## What to Capture

| Screenshot | Filename suggestion | What it proves |
|---|---|---|
| Wazuh dashboard home with active agents | `01-wazuh-dashboard.png` | The lab is real and running |
| Security events view with a custom rule firing | `02-custom-rule-fired.png` | Detection engineering works end-to-end |
| MITRE ATT&CK module showing technique coverage | `03-mitre-coverage.png` | Coverage thinking, not just rule-writing |
| Discover view with a pivot KQL query | `04-investigation-pivot.png` | Analyst-style investigation skill |
| Sysmon process tree from a triggered alert | `05-sysmon-tree.png` | Comfort reading Windows telemetry |
| Active Response in action (host isolated) | `06-active-response.png` | Containment workflow understood |
| pfSense block rule added after IR-002 | `07-pfsense-block.png` | Cross-tool response capability |

## Conventions

- **PNG**, max 1920px wide (keeps repo size sane)
- **Redact** any real IPs, usernames, hostnames that aren't lab-only placeholders
- Name files with a leading sequence number so they sort the way you'd present them
- Reference screenshots inline from case studies / playbooks where relevant, e.g.:
  ```markdown
  ![Wazuh alert for CASE-002](../screenshots/02-custom-rule-fired.png)
  ```

## Privacy Reminder

Wazuh dashboards leak a lot — hostnames, user accounts, internal IPs. Before pushing any screenshot, double-check:
- No real production hostnames or IPs (use placeholders like `WIN10-01`, `10.0.0.20`)
- No real usernames (use fake ones like `budi.santoso`)
- No license keys, tokens, or session cookies visible in browser UI
