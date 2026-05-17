# Detection Rules

This folder holds two flavors of detection logic:

| Folder | Format | Purpose |
|---|---|---|
| [wazuh-custom-rules/](wazuh-custom-rules/) | Wazuh XML | Ready to load into a Wazuh manager |
| [sigma-rules/](sigma-rules/) | Sigma YAML | Vendor-neutral; convert with `sigmac` to any SIEM |

## Rule Naming Convention

`<rule-id>-<short-name>.<ext>`

- Wazuh rule IDs **100000–120000** are reserved for user rules (Wazuh docs recommendation). I use **0100+** as the local sequence number embedded in filenames for sorting.
- Sigma files use lowercase kebab-case names.

## Authoring Workflow

1. Identify the technique (use MITRE ATT&CK).
2. Find or generate a representative log event.
3. Write the rule.
4. Test it with `wazuh-logtest` (Wazuh) or `sigma-cli` (Sigma).
5. Document the rule's intent, false-positive profile, and remediation in the file header.
6. Map it in [../docs/mitre-attack-mapping.md](../docs/mitre-attack-mapping.md).

## False-Positive Discipline

Every rule in this folder has a **`<!-- FP -->`** comment describing realistic false-positive scenarios and tuning notes. A detection without a known FP profile is a detection that will be muted by a tired analyst at 2am.
