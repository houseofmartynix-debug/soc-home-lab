# IR-004 — Suspected Data Exfiltration

| Attribute | Value |
|---|---|
| Severity | Critical |
| MITRE Tactic | Exfiltration (T1048, T1041) |
| Trigger Detections | Rule 100400, 100401, anomalous bandwidth in pfSense |
| Estimated Time | 90–180 min (Tier 1 + 2 + legal) |

## 1. Detection & Analysis

- [ ] Capture from the alert:
  - Source host + user
  - Destination IP, port, ASN, GeoIP
  - Process name + command line that initiated the transfer
  - Approximate bytes transferred (NetFlow / firewall logs)
- [ ] Determine the **data type** at risk:
  - File-server / database hostname → potential PII / IP
  - Endpoint only → user-level documents
- [ ] Pivot in Wazuh for **archive creation** on the source host in the 24h before:
  - `process.executable: (*7z.exe OR *rar.exe OR *zip.exe)`
- [ ] Check pfSense for **DNS exfil** indicators (long subdomains, high query volume to one TLD).

## 2. Containment — fast, in parallel

- [ ] **Block destination IP** at the perimeter immediately.
- [ ] **Isolate source host** (Wazuh Active Response or EDR network containment).
- [ ] **Disable the user account** at the directory service (do not delete — preserve evidence).
- [ ] Notify **legal & privacy** within 1 hour if PII may have left the network — they own breach-notification clocks.

## 3. Eradication

- [ ] Identify and remove the exfil tooling on the source host (preserve a copy for forensics).
- [ ] If the user account was compromised: rotate credentials + sessions for that user.
- [ ] If a service account was used: rotate the service credential and review all systems it touches.

## 4. Recovery

- [ ] Reimage source host (assume full compromise once exfil is confirmed).
- [ ] Restore from a clean backup if data on the host was also encrypted / corrupted.

## 5. Post-Incident

- [ ] Quantify **what** was exfiltrated (file lists, database query logs if possible).
- [ ] Coordinate with legal/comms on disclosure.
- [ ] Add destination IP, hashes, and TTPs to long-term watchlist.

## Escalation Criteria — escalate immediately if:

- Destination IP belongs to a known APT or commercial spy ASN
- Data classified **Confidential** or higher may have left
- Volume exceeds **500 MB** in a single session
- Exfil method is novel (e.g., DoH-tunneled, steganography)
