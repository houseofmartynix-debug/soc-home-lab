# Threat Hunting

Hunting is **proactive search for the things detections miss.** Every hunt here follows a hypothesis-driven format inspired by Sqrrl's PEAK framework:

1. **Hypothesis** — what attacker behavior do we expect?
2. **Data** — what telemetry will reveal it?
3. **Query** — the actual KQL / Wazuh search
4. **Findings** — what was found / not found
5. **Output** — new detection, new playbook, or "nothing today, repeat next sprint"

## Hunts in This Repo

| Hunt | Hypothesis | Output |
|---|---|---|
| [HUNT-001](hunt-001-persistence-mechanisms.md) | An attacker established persistence via Run keys or scheduled tasks | New detection ideas |
| [HUNT-002](hunt-002-lateral-movement.md) | An attacker is moving laterally via SMB / WMI | Coverage gap documented |

## Why a Junior Analyst Should Hunt

It is tempting to think hunting is a "senior only" activity. It is not. Hunting:
- Forces you to learn how the data is shaped
- Surfaces what your detections **don't** see
- Builds the muscle of asking "what would I look like if I were the attacker"

Even a poorly-executed hunt that finds nothing teaches you the dataset.
