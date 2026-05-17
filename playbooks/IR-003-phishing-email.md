# IR-003 — Phishing Email Reported by User

| Attribute | Value |
|---|---|
| Severity | Medium (Critical if credentials/payload delivered) |
| MITRE Tactic | Initial Access (T1566) |
| Trigger | User report or mail-gateway alert |
| Estimated Time | 30–90 min (Tier 1) |

## 1. Detection & Analysis

- [ ] Obtain the **original email with full headers** (`.eml` or `.msg`). Never act on a forwarded copy alone.
- [ ] Extract IoCs:
  - Sender address, sender IP (from `Received:` chain)
  - SPF / DKIM / DMARC results
  - All URLs (defang before storing: `hxxps://bad[.]example[.]com`)
  - Attachment hashes (SHA-256)
- [ ] Detonate suspicious URLs / attachments in a sandbox (any.run, Joe Sandbox, or local Cuckoo).
- [ ] Check VirusTotal, URLhaus, PhishTank for each IoC.

## 2. Determine Scope

- [ ] Search the mail server / Wazuh logs for **other recipients** of the same campaign:
  - Same sender, same subject, same URL/attachment hash
- [ ] For every recipient: check if they **clicked** (proxy logs) or **opened the attachment** (Sysmon process tree from Outlook).
- [ ] If any user interacted: pivot into IR-001 (treat as endpoint compromise).

## 3. Containment

- [ ] Purge the email from all recipient mailboxes (Microsoft 365: `Search-Mailbox -DeleteContent`; Google: bulk delete in admin console).
- [ ] Block sender domain / IP at the mail gateway.
- [ ] Block malicious URLs at the web proxy / DNS sinkhole.
- [ ] If credentials were entered into a phishing page: **force password reset + invalidate active sessions** for affected user.

## 4. Eradication & Recovery

- [ ] Confirm purge succeeded across all mailboxes.
- [ ] If credentials harvested: enable MFA, review last 30 days of sign-ins for the user.
- [ ] Notify affected users with a short, non-blaming explanation and what to do next time.

## 5. Post-Incident

- [ ] Submit the sample to your mail-gateway vendor for signature update.
- [ ] If this campaign was novel, consider awareness comms to the whole org.
- [ ] Update phishing simulation training topics if user awareness was a factor.

## Escalation Criteria

- Any user **clicked** + **submitted credentials** → escalate to Tier 2.
- Attachment executed and Sysmon shows child process activity → escalate (IR-001).
- Spear-phish targeting an executive → escalate immediately regardless of outcome.
