# 🗺️ MITRE ATT&CK Framework Mapping

> **Hunt:** Devices Accidentally Exposed to the Internet  
> **Date:** March 27, 2026  
> **Reference:** [MITRE ATT&CK v14](https://attack.mitre.org/)

---

## Overview

This document maps the observed adversary behaviors from this threat hunt to the [MITRE ATT&CK Enterprise Framework](https://attack.mitre.org/). Understanding *where* an attack falls in the ATT&CK matrix helps analysts anticipate next steps, identify detection gaps, and build better defenses.

---

## ATT&CK Navigator Summary

```
INITIAL ACCESS          CREDENTIAL ACCESS       DEFENSE EVASION
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│  T1190           │    │  T1110           │    │  T1078           │
│  Exploit Public- │    │  Brute Force     │    │  Valid Accounts  │
│  Facing          │    │  (Observed)      │    │  (Investigated)  │
│  Application     │    │                  │    │                  │
│  (Observed)      │    │  T1110.001       │    │                  │
└──────────────────┘    │  Password        │    └──────────────────┘
                        │  Guessing        │
RESOURCE DEVELOPMENT    └──────────────────┘
┌──────────────────┐
│  T1587           │
│  Develop         │
│  Capabilities    │
│  (Inferred)      │
└──────────────────┘
```

---

## Detailed TTP Analysis

### T1190 — Exploit Public-Facing Application

| Field | Detail |
|---|---|
| **Tactic** | Initial Access |
| **ID** | [T1190](https://attack.mitre.org/techniques/T1190/) |
| **Status in Hunt** | ✅ Observed |
| **Confidence** | High |

**Description:**  
Adversaries may attempt to exploit weaknesses in internet-facing services to gain initial access to a target network. In this scenario, `saranpc2` was unintentionally exposed to the public internet with its RDP port accessible, making it a viable target for exploitation.

**Evidence:**
- `DeviceInfo` confirmed `IsInternetFacing == true` for several days
- The device was discoverable via internet-wide scanners (Shodan, Censys, Masscan)
- External IPs began attempting logons shortly after exposure

**Detection:**
```kql
DeviceInfo
| where IsInternetFacing == true
| where Timestamp > ago(24h)
```

**Mitigation:**
- Remove public internet exposure from internal VMs (NSG hardening)
- Enable Just-in-Time (JIT) VM access
- Deploy Azure Bastion for RDP access instead of exposing port 3389

---

### T1110 — Brute Force

| Field | Detail |
|---|---|
| **Tactic** | Credential Access |
| **ID** | [T1110](https://attack.mitre.org/techniques/T1110/) |
| **Sub-Technique** | T1110.001 (Password Guessing) |
| **Status in Hunt** | ✅ Observed |
| **Confidence** | High |

**Description:**  
Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. In this hunt, 7 external IP addresses were observed making large numbers of failed logon attempts against `saranpc2` — consistent with automated password guessing tools.

**Evidence:**
- 7 unique external IPs with high failed logon attempt counts
- `DeviceLogonEvents` where `ActionType == "LogonFailed"` and `RemoteIP` is populated
- Top attacker IP (`185.156.73.74`) had the highest volume of attempts
- No account lockout policy configured — attackers could attempt unlimited passwords

**Why It Didn't Succeed:**
- Despite the high attempt volume, the account passwords were sufficiently complex
- The `labuser` account had zero failed logons — it was not targeted specifically
- Brute-force success query returned no results for any attacker IP

**Sub-technique Analysis:**

| Sub-technique | ID | Description | Observed? |
|---|---|---|---|
| Password Guessing | T1110.001 | Trying common passwords against accounts | ✅ Likely |
| Password Cracking | T1110.002 | Cracking captured hashes | ❌ Not observed |
| Password Spraying | T1110.003 | Few passwords against many accounts | ⚠️ Possible |
| Credential Stuffing | T1110.004 | Using leaked credential pairs | ⚠️ Possible |

**Detection:**
```kql
DeviceLogonEvents
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize FailedAttempts = count() by RemoteIP, DeviceName, bin(Timestamp, 5m)
| where FailedAttempts > 50
```

**Mitigation:**
- Implement account lockout policy (GPO)
- Enable MFA for all remote access
- Block known malicious IPs at NSG/firewall level
- Rate-limit RDP connections

---

### T1078 — Valid Accounts

| Field | Detail |
|---|---|
| **Tactic** | Defense Evasion / Persistence / Initial Access |
| **ID** | [T1078](https://attack.mitre.org/techniques/T1078/) |
| **Status in Hunt** | ⚠️ Investigated (to rule out misuse) |
| **Confidence** | High — No misuse confirmed |

**Description:**  
Adversaries may obtain and abuse credentials of existing accounts to bypass security controls. This TTP was investigated to rule out the possibility that the `labuser` account (which had successful network logons) was compromised or being abused.

**Evidence:**
- 5 successful `Network` logons for `labuser` in the last 30 days
- Zero failed logon attempts against `labuser` — no brute-force targeting of this account
- Source IPs for `labuser` logons appeared consistent and legitimate

**Conclusion:** No misuse of valid accounts detected. The `labuser` logons are assessed as **legitimate**.

**What to Check When This Is Suspected:**
```kql
// Check if a legitimate account suddenly logs in from a new IP
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where AccountName == "target_account"
| summarize LoginCount = count() by RemoteIP, AccountName, DeviceName
// Compare IPs to known-good baseline
```

**Mitigation:**
- Enforce MFA to prevent credential-only authentication
- Implement Conditional Access based on device compliance and location
- Monitor for logons from new/unknown IPs

---

### T1587 — Develop Capabilities

| Field | Detail |
|---|---|
| **Tactic** | Resource Development |
| **ID** | [T1587](https://attack.mitre.org/techniques/T1587/) |
| **Status in Hunt** | ⚠️ Inferred |
| **Confidence** | Medium |

**Description:**  
Adversaries may build capabilities that can be used during targeting, such as developing malware or attack tools. The IP addresses observed in this hunt (particularly `185.156.73.74`) are likely part of dedicated attacker infrastructure — VPS hosts, botnets, or scanning services used to automate credential attacks.

**Evidence:**
- Consistent attack volume suggests tooling, not manual attempts
- Multiple distinct IPs suggests coordinated infrastructure or botnet activity
- IPs were likely pre-scanned for open RDP ports before attacks began

**Recommended Threat Intel Actions:**
1. Submit the 7 IPs to threat intelligence platforms:
   - [VirusTotal](https://www.virustotal.com)
   - [AbuseIPDB](https://www.abuseipdb.com)
   - [Shodan](https://www.shodan.io)
2. Check if IPs are associated with known threat actor groups
3. Add confirmed malicious IPs to NSG deny lists or SIEM watchlists

---

## Kill Chain Mapping

Using the **Unified Cyber Kill Chain**, here's where the attacker activity falls:

```
PREPARATION         INITIAL FOOTHOLD      POST-COMPROMISE
┌─────────────────┐ ┌─────────────────┐  ┌─────────────────┐
│ • Scan internet │ │ • RDP Brute     │  │  (Never reached) │
│   for open 3389 │ │   Force via     │  │                 │
│ • Identify      │ │   T1110         │  │  Attack was      │
│   targets via   │ │                 │  │  stopped at the  │
│   Shodan/Censys │ │ • FAILED —      │  │  Initial         │
│ • T1590, T1587  │ │   No success    │  │  Foothold phase  │
└─────────────────┘ └─────────────────┘  └─────────────────┘
```

**Key Insight:** By detecting and remediating during the **Initial Foothold** phase, we prevented any post-compromise activity (persistence, lateral movement, data exfiltration, etc.).

---

## Detection Coverage Assessment

| TTP | Detection Method | Coverage |
|---|---|---|
| T1190 | `DeviceInfo | where IsInternetFacing == true` | ✅ Good |
| T1110 | Failed logon aggregation by source IP | ✅ Good |
| T1078 | Successful logon baseline analysis | ✅ Good |
| T1587 | Threat intel correlation (manual) | ⚠️ Partial |

**Gap Identified:** No automated alert existed for internet-facing devices or high-volume failed logons. Both should be implemented as detection rules.

---

## References

- [MITRE ATT&CK T1190](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK T1587](https://attack.mitre.org/techniques/T1587/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

---

*Mapping authored by: Saran | CyberRange Lab | March 27, 2026*
