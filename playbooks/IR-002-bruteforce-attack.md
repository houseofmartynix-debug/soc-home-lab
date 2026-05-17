# IR-002 — Brute Force on Public Service

| Attribute | Value |
|---|---|
| Severity | Medium (High if successful login) |
| MITRE Tactic | Credential Access (T1110) |
| Trigger Detections | Rule 100100, 100101 |
| Estimated Time | 20–45 min (Tier 1) |

## 1. Detection & Analysis

- [ ] Open the alert and capture:
  - Source IP, source country (via GeoIP), source ASN
  - Target hostname, target service (SSH, RDP, VPN, etc.)
  - Number of failed attempts and time window
  - Usernames tried (sprayed vs. focused)
- [ ] **Check for successful login** from the same source IP in the alert window. Pivot:
  - `data.srcip:"X.X.X.X" AND rule.groups:"authentication_success"`
- [ ] **Classify**:
  - **Failed only** → Containment (block) then close as contained
  - **Successful login present** → escalate to IR-001 path (treat as compromise)

## 2. Containment

- [ ] Block the source IP at the perimeter (pfSense → Firewall → Aliases → add to `bruteforce_blocklist`).
- [ ] If the targeted account is real, **force a password reset** and **enable MFA** if not already.
- [ ] If the service should not be internet-facing (e.g., SSH on 22 from any), open a hardening ticket.

## 3. Eradication

- [ ] If the IP is part of a known botnet (check AbuseIPDB / Spamhaus), keep the block indefinite.
- [ ] If unknown / one-off scanner, time-bound the block (30 days) and review.

## 4. Recovery

- [ ] Confirm legitimate users can still authenticate.
- [ ] Verify Wazuh alert volume from this source has dropped to zero.

## 5. Post-Incident

- [ ] Update the bruteforce blocklist export shared with peer teams.
- [ ] If this is the **Nth** brute force from the same ASN this month, propose ASN-level block to network team.

## Escalation Criteria

- A **successful** login from the brute-forcing IP → escalate to Tier 2 and pivot into IR-001.
- Brute force targets a privileged account (admin, root, domain admin) → escalate even if unsuccessful.
