# CASE-001 — SSH Brute Force from External IP

| Field | Value |
|---|---|
| Case ID | SOC-2026-0001 |
| Analyst | (you) |
| Opened | 2026-05-10 14:22 UTC |
| Closed | 2026-05-10 15:05 UTC |
| Severity | Medium |
| Disposition | True Positive — Contained |
| MITRE | T1110.001 |
| Playbook | [IR-002](../playbooks/IR-002-bruteforce-attack.md) |

## 1. Alert

```
Rule:       100101 (level 12) — SSH brute force, sustained attack
Agent:      ubuntu-30 (10.0.0.30)
Source IP:  203.0.113.42 (placeholder external IP)
Window:     14:18 – 14:21 UTC, 47 failed auths
Usernames:  root, admin, ubuntu, oracle, postgres, git, test
```

## 2. Triage (first 5 minutes)

- Opened Wazuh dashboard → Security events → filtered `rule.id:(5712 OR 100100 OR 100101)`.
- Confirmed alert is **not duplicate** — no prior SOC ticket on this IP.
- GeoIP on `203.0.113.42` → routed via cloud-hosting ASN, no business relationship.
- Quick pivot: `data.srcip:"203.0.113.42" AND rule.groups:"authentication_success"` → **0 hits.** No successful login.

Classification at triage: **likely true positive, no compromise**. Proceed with IR-002.

## 3. Investigation

### 3.1 — Scope check

```kql
agent.name:"ubuntu-30" AND data.srcip:"203.0.113.42"
```

47 failed attempts, all to SSH, all denied. Username list looks like a stock dictionary — opportunistic, not targeted.

### 3.2 — Has this IP touched other assets?

```kql
data.srcip:"203.0.113.42"
```

→ Only `ubuntu-30`. Single target. Confirms opportunistic scan.

### 3.3 — Reputation

- AbuseIPDB: **97% confidence — abusive**, 200+ reports in last 30 days for SSH brute force.
- Shodan: cloud VPS with port 22 exposed, no other context.

### 3.4 — Could the SSH service be hardened more?

Checked `/etc/ssh/sshd_config` on `ubuntu-30`:
- `PermitRootLogin no` ✓
- `PasswordAuthentication yes` ✗ — this is why brute force is even possible
- No fail2ban installed

## 4. Response

| Step | Action | Result |
|---|---|---|
| 1 | pfSense → block 203.0.113.42 in `bruteforce_blocklist` alias | Block live at 14:38 UTC |
| 2 | Verified attempts stopped in Wazuh | 0 events after 14:38 ✓ |
| 3 | Opened hardening ticket: switch ubuntu-30 to key-only auth + install fail2ban | Ticket OPS-1184 |
| 4 | No password reset needed (no compromise) | — |

## 5. Closure & Lessons

**Disposition:** True positive — opportunistic brute force, contained at perimeter, no compromise.

**Lessons learned for the lab:**
1. Any internet-facing SSH should be key-only by default — this is a baseline I should harden across all lab hosts.
2. Wazuh's stock 5712 rule + my 100100/100101 chain works as designed — the level-12 escalation is the right signal to act on.
3. Detection time was 3 minutes from first failed attempt to alert — good.
4. Time to containment was 16 minutes — acceptable, but installing fail2ban would auto-contain in seconds for routine scans, freeing the analyst for higher-value work.

**IoCs added to watchlist:**
- `203.0.113.42` → bruteforce_blocklist (30d)
- ASN AS00000 → review for repeat offenders
