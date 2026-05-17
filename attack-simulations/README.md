# Attack Simulations (Purple Team)

Detection rules are only as good as the attacks they catch. This folder documents the **controlled, lab-only** attack simulations I ran from the Kali host to validate each detection.

> **Scope notice:** every command here is executed against my own lab VMs on an isolated network. Do **not** run these against systems you do not own or have explicit written authorization to test.

## Approach

I use **[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)** for most tests because each "atomic" is a single-technique unit aligned to a MITRE ATT&CK ID. This makes it trivial to answer: *"Does my rule fire for technique X?"*

## Test Matrix

| Technique | Atomic Test | Expected Rule | Result |
|---|---|---|---|
| T1110.001 (SSH BF) | Hydra from Kali | 100100 / 100101 | ✅ Fires within 2 min |
| T1059.001 (PS encoded) | Atomic T1059.001 #1 | 100200 | ✅ Fires immediately |
| T1059.001 + T1566.001 (Office macro) | Custom `.docm` | 100201 | ✅ Fires immediately |
| T1003.001 (Mimikatz) | Atomic T1003.001 #1 | 100300 / 100301 | ✅ Fires on cmdline match |
| T1562.001 (Disable Defender) | Atomic T1562.001 #1 | Sigma `windows-defender-disabled` | ✅ Fires |
| T1547.001 (Run key) | Atomic T1547.001 #1 | (no rule yet — gap) | ⚠️ Gap, ticket open |

## Running a Test

### Example — Atomic T1059.001 #1 (encoded PowerShell)

On the Windows endpoint with Atomic Red Team's `Invoke-AtomicTest` PowerShell module installed:

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1
```

Then verify in Wazuh dashboard within 1 minute that rule **100200** fired with the expected `agent.name`.

### Example — Hydra SSH brute force from Kali

```bash
# Lab-only target
hydra -L users.txt -P passwords.txt ssh://10.0.0.30 -t 4 -f
```

Expected: rule 100100 fires at 8 failed attempts in 120s; rule 100101 escalates at 15 in 300s.

## Cleanup

Every Atomic test has a `-Cleanup` flag. **Always run it.** Lingering artifacts will pollute later hunts and turn this lab into a haunted house.

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
```

## Why Purple Team

Writing a rule and assuming it works is wishful thinking. Running the attack and watching the alert fire (or fail) is the only way to know your detection works under the conditions that matter.
