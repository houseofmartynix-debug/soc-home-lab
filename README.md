# SOC Home Lab — Wazuh-Based Security Operations Center

> A practical, end-to-end Security Operations Center home lab built around **Wazuh XDR/SIEM**, documenting how a Tier 1 SOC analyst monitors, detects, investigates, and responds to real-world threats — mapped to the **MITRE ATT&CK** framework.

![SOC](https://img.shields.io/badge/SOC-Home%20Lab-blue)
![SIEM](https://img.shields.io/badge/SIEM-Wazuh%204.7-orange)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Status](https://img.shields.io/badge/Status-Active-success)

---

## Table of Contents

1. [Purpose](#purpose)
2. [Lab Architecture](#lab-architecture)
3. [Skills Demonstrated](#skills-demonstrated)
4. [Repository Structure](#repository-structure)
5. [Detection Coverage](#detection-coverage)
6. [Case Studies](#case-studies)
7. [Getting Started](#getting-started)
8. [Roadmap](#roadmap)
9. [References](#references)

---

## Purpose

This repository documents my hands-on learning as an aspiring **Tier 1 SOC Analyst**. It is built to demonstrate that I understand:

- How a **SIEM** ingests, parses, and correlates security telemetry
- How **detection rules** are written, tuned, and mapped to attacker behavior
- How **alerts** are triaged, investigated, and escalated
- How **incident response playbooks** drive consistent analyst workflow
- How **threat hunting** proactively finds what detections miss
- How modern attacks map to the **MITRE ATT&CK** framework

Every artifact here — rules, playbooks, case studies — is something I would write or use on the job.

---

## Lab Architecture

```
                    +-------------------------------+
                    |     ATTACK SIMULATION         |
                    |   (Kali Linux + Atomic Red)   |
                    +---------------+---------------+
                                    |
                                    v
   +-------------------+    +-------------------+    +-------------------+
   |  Windows 10/11    |    |   Ubuntu Server   |    |   pfSense FW      |
   |  Wazuh Agent      |    |   Wazuh Agent     |    |   Syslog -> Wazuh |
   +--------+----------+    +---------+---------+    +---------+---------+
            |                         |                        |
            +-------------------------+------------------------+
                                      |
                                      v
                       +--------------+--------------+
                       |       WAZUH MANAGER         |
                       |  (rules + decoders + API)   |
                       +--------------+--------------+
                                      |
                                      v
                       +--------------+--------------+
                       |     WAZUH INDEXER (OS)      |
                       |   + WAZUH DASHBOARD (UI)    |
                       +-----------------------------+
                                      |
                                      v
                       +-----------------------------+
                       |  ANALYST WORKSTATION        |
                       |  - Triage alerts            |
                       |  - Run playbooks            |
                       |  - Document investigations  |
                       +-----------------------------+
```

> Full diagram and component breakdown: see [docs/architecture.md](docs/architecture.md)

---

## Skills Demonstrated

| Skill Area | Where in This Repo |
|---|---|
| SIEM deployment & configuration | [docs/wazuh-installation.md](docs/wazuh-installation.md) |
| Log source onboarding (Windows, Linux, Firewall) | [docs/lab-setup.md](docs/lab-setup.md) |
| Detection rule writing (Wazuh XML + Sigma) | [detection-rules/](detection-rules/) |
| MITRE ATT&CK mapping | [docs/mitre-attack-mapping.md](docs/mitre-attack-mapping.md) |
| Alert triage & investigation | [case-studies/](case-studies/) |
| Incident response playbooks | [playbooks/](playbooks/) |
| Threat hunting hypotheses | [threat-hunting/](threat-hunting/) |
| Attack simulation & purple teaming | [attack-simulations/](attack-simulations/) |
| Automation scripting (Python) | [scripts/](scripts/) |

---

## Repository Structure

```
soc-home-lab/
├── README.md                       <- you are here
├── docs/                           <- architecture, install, MITRE mapping
├── detection-rules/
│   ├── wazuh-custom-rules/         <- custom Wazuh XML rules
│   └── sigma-rules/                <- vendor-neutral Sigma rules
├── playbooks/                      <- IR playbooks (markdown)
├── case-studies/                   <- simulated investigations w/ evidence
├── threat-hunting/                 <- hunt hypotheses + queries
├── attack-simulations/             <- Atomic Red Team test mappings
├── scripts/                        <- helper tooling
└── diagrams/                       <- network + workflow diagrams
```

---

## Detection Coverage

Rules in this lab currently cover the following MITRE ATT&CK techniques:

| Tactic | Technique | Rule |
|---|---|---|
| Initial Access | T1110 — Brute Force | [SSH brute force](detection-rules/wazuh-custom-rules/0100-bruteforce-ssh.xml) |
| Execution | T1059.001 — PowerShell | [Suspicious PowerShell](detection-rules/wazuh-custom-rules/0101-suspicious-powershell.xml) |
| Credential Access | T1003 — OS Credential Dumping | [Mimikatz indicators](detection-rules/wazuh-custom-rules/0102-mimikatz-detection.xml) |
| Exfiltration | T1048 — Exfil over Alt Protocol | [Large outbound transfer](detection-rules/wazuh-custom-rules/0103-data-exfiltration.xml) |
| Defense Evasion | T1562.001 — Disable Defender | [sigma-rules/windows-defender-disabled.yml](detection-rules/sigma-rules/windows-defender-disabled.yml) |
| Initial Access | T1078 — Valid Accounts | [sigma-rules/suspicious-login-time.yml](detection-rules/sigma-rules/suspicious-login-time.yml) |

Full mapping: [docs/mitre-attack-mapping.md](docs/mitre-attack-mapping.md)

---

## Case Studies

Each case study walks through a simulated incident — from initial alert to closure — exactly as I would document it in a SOC ticketing system.

- [CASE-001 — SSH Brute Force from External IP](case-studies/case-001-ssh-bruteforce.md)
- [CASE-002 — Suspicious PowerShell Execution on Endpoint](case-studies/case-002-suspicious-powershell.md)
- [CASE-003 — Phishing Email Investigation](case-studies/case-003-phishing-investigation.md)

---

## Getting Started

Build the lab yourself in under an hour:

```bash
# 1. Spin up Wazuh all-in-one (Ubuntu 22.04 VM, 4 vCPU / 8 GB RAM)
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a

# 2. Onboard a Windows endpoint
#    See docs/lab-setup.md

# 3. Import custom detection rules
sudo cp detection-rules/wazuh-custom-rules/*.xml \
    /var/ossec/etc/rules/
sudo systemctl restart wazuh-manager
```

Full step-by-step: [docs/wazuh-installation.md](docs/wazuh-installation.md)

---

## Roadmap

- [x] Wazuh manager + indexer + dashboard deployment
- [x] Windows + Linux agent onboarding
- [x] 6 custom detection rules mapped to MITRE
- [x] 5 incident response playbooks
- [x] 3 end-to-end case studies
- [ ] Integrate **TheHive** for case management
- [ ] Integrate **MISP** for threat intel enrichment
- [ ] Add **Shuffle** SOAR for auto-containment
- [ ] Expand to 20+ detection rules across all 14 ATT&CK tactics

---

## References

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Sigma HQ](https://github.com/SigmaHQ/sigma)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [NIST SP 800-61r2 — Computer Security Incident Handling Guide](https://csrc.nist.gov/pubs/sp/800/61/r2/final)

---

## Author

Built as part of my journey toward a career as a **SOC Analyst**. Feedback, questions, and collaboration always welcome via GitHub Issues.

> *"You can't defend what you don't understand. This lab is how I learned to understand it."*
