
Threat hunting # 🛡️ Threat Hunt: Devices Accidentally Exposed to the Internet

> **Platform:** Microsoft Defender for Endpoint (MDE) + Azure CyberRange  
> **Analyst:** Saran  
> **Hunt Date:** March 27, 2026  
> **Severity:** Medium  
> **Status:** ✅ Resolved — No Breach Confirmed

---

## 📋 Table of Contents

- [Overview](#overview)
- [Scenario Background](#scenario-background)
- [Hunt Methodology](#hunt-methodology)
- [Key Findings](#key-findings)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Response Actions Taken](#response-actions-taken)
- [Lessons Learned](#lessons-learned)
- [KQL Query Reference](#kql-query-reference)
- [Project Structure](#project-structure)
- [Tools & Technologies](#tools--technologies)

---

## Overview

This repository documents a **hands-on threat hunting exercise** conducted in a live cyberrange environment using **Microsoft Defender for Endpoint (MDE)** and **Kusto Query Language (KQL)**. The hunt was triggered after it was discovered that several virtual machines in a shared services cluster were accidentally exposed to the public internet.

The goal was to determine whether any of these exposed machines had been compromised through brute-force login attacks by external threat actors.

**Bottom Line Up Front (BLUF):** The target device (`saranpc2`) was internet-facing for several days and received brute-force login attempts from **7 unique external IP addresses**. However, **no brute-force attempts were successful**, and all successful remote logons were attributed to the legitimate `labuser` account from known IPs.

---

## Scenario Background

During routine maintenance, the security team identified that VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) had been **mistakenly exposed to the public internet**. This created a window where:

- Devices were publicly reachable without intended exposure.
- Older devices lacked **account lockout policies**, making them vulnerable to brute-force attacks.
- External threat actors and automated bots could attempt credential stuffing or brute-force attacks.

**Hypothesis:**  
> *"One or more exposed VMs may have been successfully compromised via brute-force login from an external source, given the absence of account lockout controls on legacy devices."*

---

## Hunt Methodology

This investigation follows a structured **Threat Hunting Lifecycle**:

```
1. Preparation  →  2. Data Collection  →  3. Data Analysis
       ↑                                         ↓
7. Improvement  ←  6. Documentation  ←  4. Investigation
                                         ↓
                                    5. Response
```

For the full step-by-step walkthrough, see [`reports/hunt-report.md`](reports/hunt-report.md).

---

## Key Findings

| Finding | Detail |
|---|---|
| **Internet Exposure Duration** | Several days (last confirmed: `2026-03-27T06:59:56Z`) |
| **Unique Attacker IPs** | 7 external IPs identified |
| **Top Attacker** | `185.156.73.74` — highest number of failed attempts |
| **Brute Force Success?** | ❌ No |
| **Legitimate Remote Logons** | 5 successful `Network` logons by `labuser` from known IPs |
| **Compromise Confirmed?** | ❌ No evidence of compromise |

---

## MITRE ATT&CK Mapping

| TTP ID | Technique | Tactic | Observed |
|---|---|---|---|
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Initial Access | Device was internet-exposed |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion / Persistence | Investigated legitimate logons |
| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | Credential Access | Multiple failed logons from external IPs |
| [T1587](https://attack.mitre.org/techniques/T1587/) | Develop Capabilities | Resource Development | Potential attacker tooling/infrastructure |

See [`mitre/ttp-mapping.md`](mitre/ttp-mapping.md) for detailed analysis.

---

## Response Actions Taken

1. **Network Security Group (NSG) Hardened** — Restricted RDP access on `saranpc2` to specific approved endpoints only. Public internet RDP access removed.
2. **Account Lockout Policy** — Recommended implementation to block brute-force attempts automatically.
3. **MFA Enforcement** — Recommended enabling Multi-Factor Authentication on all remote access accounts.

---

## Lessons Learned

- 🔴 **Public internet exposure of internal VMs** is a critical misconfiguration risk — even short exposure windows attract automated attacks.
- 🟡 **Absence of account lockout** on legacy devices significantly increases brute-force risk.
- 🟢 **Proactive threat hunting** caught this issue before a breach occurred.
- 🟢 **MDE telemetry** (DeviceInfo + DeviceLogonEvents) provided sufficient visibility to confirm or deny compromise.

---

## KQL Query Reference

All KQL queries used in this hunt are documented in [`queries/kql-queries.md`](queries/kql-queries.md), including:

- Internet-facing device identification
- Failed logon enumeration by source IP
- Brute-force success verification
- Legitimate logon baseline analysis

---

## Project Structure

```
📁 soc-exposed-devices/
├── 📄 README.md                    ← You are here
├── 📁 reports/
│   └── 📄 hunt-report.md           ← Full investigation report
├── 📁 queries/
│   └── 📄 kql-queries.md           ← All KQL queries with explanations
├── 📁 mitre/
│   └── 📄 ttp-mapping.md           ← MITRE ATT&CK framework mapping
├── 📁 playbooks/
│   └── 📄 exposed-device-response.md ← IR playbook for this scenario
└── 📁 assets/
    └── 📄 timeline.md              ← Attack timeline reconstruction
```

---

## Tools & Technologies

| Tool | Purpose |
|---|---|
| **Microsoft Defender for Endpoint (MDE)** | Endpoint telemetry and alert source |
| **Kusto Query Language (KQL)** | Log analysis and threat hunting queries |
| **Microsoft Sentinel / MDE Portal** | SIEM/XDR query interface |
| **MITRE ATT&CK Navigator** | TTP mapping and adversary behavior analysis |
| **Azure CyberRange** | Lab environment for hands-on practice |

---

## About This Project

This project was completed as part of a **CyberRange threat hunting exercise** designed to simulate real-world SOC analyst workflows. It demonstrates:

- Structured threat hunting methodology
- KQL proficiency for log analysis
- MITRE ATT&CK framework application
- Incident documentation and reporting skills

> 💡 *If you're a recruiter or fellow analyst reviewing this — all queries are tested against live MDE telemetry in a sandboxed environment. Findings are real.*

---

*Last updated: March 27, 2026 | Author: Saran*
