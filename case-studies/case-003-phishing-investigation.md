# CASE-003 — User-Reported Phishing Email

| Field | Value |
|---|---|
| Case ID | SOC-2026-0023 |
| Analyst | (you) |
| Opened | 2026-05-14 08:12 UTC |
| Closed | 2026-05-14 10:55 UTC |
| Severity | Medium |
| Disposition | True Positive — Campaign Purged |
| MITRE | T1566.002 (Phishing — Spearphishing Link) |
| Playbook | [IR-003](../playbooks/IR-003-phishing-email.md) |

## 1. Alert

Not a SIEM alert — user-submitted report via the "Report Phishing" button. A finance user (`dewi.lestari@example.lab`) flagged an email titled **"Pemberitahuan Tagihan Tertunda — Konfirmasi Segera"** ("Notice of Overdue Invoice — Confirm Immediately") at 08:09 UTC. The user did **not** click.

## 2. Triage

Pulled the original `.eml` from the report. Headers showed:

| Field | Value | Notes |
|---|---|---|
| From | `billing@example-secure-pay[.]com` | Lookalike domain, registered 2026-05-08 (6 days old) |
| Reply-To | `billing-team@protonmail[.]com` | Free webmail mismatch with sender |
| SPF | softfail | |
| DKIM | none | |
| DMARC | fail | |
| Body link | `hxxps://example-secure-pay[.]com/invoice/view?id=4523` | Defanged |

All three auth checks failing + 6-day-old lookalike domain = textbook phish. Classification at triage: **likely true positive**.

## 3. Investigation

### 3.1 — Detonate the link

Submitted the URL to any.run. Result:
- Redirects through 2 hops to `hxxps://example-secure-pay[.]com/login`
- Renders a near-pixel-perfect clone of an Indonesian banking portal
- Credentials are POSTed to `/api/submit` and exfil to a Telegram bot webhook

Confirmed: **credential-harvesting phishing**, not malware-delivery.

### 3.2 — Scope: who else got it?

Searched the mail-gateway logs for the sender domain and subject across the 48h prior:

```
sender_domain:"example-secure-pay.com" OR subject:"Pemberitahuan Tagihan Tertunda"
```

**11 recipients** in the org. Of those:
- 9 emails still in inbox, **unopened**.
- 1 user moved it to trash on their own.
- 1 user (`andi.pratama@example.lab`) **clicked the link** at 07:47 UTC, but proxy logs show the request returned a 200 — page rendered. **No POST to /api/submit was logged** for this user.

Spoke with Andi via Teams: he clicked but did **not** enter credentials, "looked suspicious so I closed the tab." Good catch.

### 3.3 — IoCs

- Sender domain: `example-secure-pay[.]com`
- Sender IP: 198.51.100.77 (placeholder)
- Phishing URL: `hxxps://example-secure-pay[.]com/invoice/view`
- Telegram bot ID: `bot7894561230:AAH...` (exfil destination)

## 4. Response

| Step | Time | Action |
|---|---|---|
| Purge | 08:35 | M365 content search + bulk delete → all 11 copies removed |
| Block sender | 08:40 | Mail gateway: domain `example-secure-pay.com` to deny list |
| Block URL | 08:42 | Web proxy + DNS sinkhole: `example-secure-pay.com` |
| User confirmation | 09:00 | Andi confirmed no credentials submitted; conservative MFA-reset issued anyway |
| Comms | 09:30 | Sent awareness email to all 11 recipients thanking the reporter, explaining what to look for |
| Vendor submit | 10:00 | Sample submitted to mail-gateway vendor for global signature update |

## 5. Closure & Lessons

**Disposition:** True positive. Campaign of 11 emails fully purged. One click, no credentials harvested. No follow-on activity detected.

**What worked:**
- The "Report Phishing" button workflow: user-to-SOC ticket in <2 minutes.
- Proxy logs let me confirm with high confidence that Andi did not POST credentials — without proxy visibility I would have had to assume the worst and rotate his creds at minimum.
- Sandbox detonation took ~3 minutes to confirm intent.

**What I'd improve:**
- Add a SIEM correlation rule: when a user clicks a URL whose domain was registered <30 days ago, alert. Plan to wire this with a passive-DNS feed.
- Awareness training should specifically cover bank-portal lookalike domains — these are the dominant phishing pretext in the local market.
- The mail gateway should have caught this on DMARC fail alone. Investigated → policy was set to `quarantine` for fail, but the gateway's allow-list bypass for "external partners" inadvertently included anything in the `*-pay.com` pattern. Tightened.

**IoCs added to watchlist:**
- Lookalike domain pattern: `example-secure-pay*.com`, monitor passive DNS for new variants
- Telegram bot identifier as a high-confidence exfil sink across the org
