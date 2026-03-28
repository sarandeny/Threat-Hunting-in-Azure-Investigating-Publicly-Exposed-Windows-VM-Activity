
# 📋 Incident Response Playbook
## Scenario: Devices Accidentally Exposed to the Internet

**Playbook ID:** IR-PB-001  
**Version:** 1.0  
**Last Updated:** March 27, 2026  
**Classification:** TLP:WHITE  

---

## Purpose

This playbook provides a structured, repeatable process for investigating and responding to virtual machines that have been unintentionally exposed to the public internet. It is designed for **Tier 1 and Tier 2 SOC analysts** working in environments with Microsoft Defender for Endpoint (MDE) telemetry.

---

## Trigger Conditions

Initiate this playbook when **any of the following** are true:

- [ ] An alert fires for a device with `IsInternetFacing == true` that should not be public-facing
- [ ] A network or infrastructure team reports an NSG misconfiguration
- [ ] Threat intelligence identifies a known internal IP in external scan data
- [ ] High-volume failed logon events are detected from external IPs on a device
- [ ] Routine security review discovers unexpected internet exposure

---

## Severity Classification

| Severity | Criteria |
|---|---|
| 🔴 **Critical** | Brute-force attempt **succeeded** — unauthorized logon confirmed |
| 🟠 **High** | Device exposed + active brute-force with no current success |
| 🟡 **Medium** | Device was exposed (historic), no active attacks detected |
| 🟢 **Low** | Device briefly exposed, no attack attempts logged |

**This hunt:** 🟠 High → downgraded to 🟡 Medium after confirming no successful logons.

---

## Phase 1: Detection & Initial Triage

**Estimated time: 15–30 minutes**

### Step 1.1 — Confirm Internet Exposure

```kql
DeviceInfo
| where DeviceName == "<DEVICE_NAME>"
| where IsInternetFacing == true
| order by Timestamp desc
| take 10
```

- [ ] Note the **earliest** and **latest** internet-facing timestamps
- [ ] Calculate the **total exposure window** (duration)
- [ ] Record the device's **public IP** if shown

### Step 1.2 — Check for Failed Logon Activity

```kql
DeviceLogonEvents
| where DeviceName == "<DEVICE_NAME>"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by RemoteIP, ActionType
| order by Attempts desc
```

- [ ] Are there **external IPs** with high failed logon counts?
- [ ] Record all attacker IPs and their attempt counts
- [ ] Note the **time range** of the attacks

### Step 1.3 — Assign Initial Severity

Based on findings from Steps 1.1 and 1.2, assign the initial severity level using the table above.

**Escalate to Tier 2 if:** Severity is 🔴 Critical or 🟠 High with more than 1,000 failed attempts.

---

## Phase 2: Scope & Impact Assessment

**Estimated time: 20–45 minutes**

### Step 2.1 — Check for Brute Force Success

```kql
let AttackerIPs = dynamic(["IP1", "IP2", "IP3"]); // Replace with actual IPs

DeviceLogonEvents
| where DeviceName == "<DEVICE_NAME>"
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(AttackerIPs)
```

- [ ] **If results exist:** Escalate to 🔴 Critical — proceed to Phase 3 (Compromise Response)
- [ ] **If no results:** Continue to Step 2.2

### Step 2.2 — Baseline Legitimate Logons

```kql
DeviceLogonEvents
| where DeviceName == "<DEVICE_NAME>"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| summarize LoginCount = count() by AccountName, RemoteIP
```

- [ ] Are all `AccountName` values expected/authorized?
- [ ] Do all `RemoteIP` values match known admin workstations or VPN ranges?
- [ ] Are there any logons outside business hours?

### Step 2.3 — Check Exposure Scope (Other Devices)

```kql
DeviceInfo
| where IsInternetFacing == true
| where Timestamp > ago(7d)
| summarize LastSeen = max(Timestamp) by DeviceName, PublicIP
| order by LastSeen desc
```

- [ ] Is this an isolated misconfiguration or part of a broader issue?
- [ ] Are other devices in the shared services cluster also exposed?

---

## Phase 3A: If No Compromise Detected

**Estimated time: 30–60 minutes**

### Step 3A.1 — Immediate Containment

| Action | Priority | Owner |
|---|---|---|
| Remove internet exposure (update NSG rules) | 🔴 Immediate | Network/Cloud Team |
| Block attacker IPs at NSG/firewall | 🟠 High | Network Team |
| Document all findings | 🟡 Medium | SOC Analyst |

### Step 3A.2 — Hardening Actions

| Action | Priority | Details |
|---|---|---|
| Enable account lockout policy | 🟠 High | Via GPO — lockout after 10 failed attempts |
| Enforce MFA on RDP accounts | 🟠 High | Conditional Access policy |
| Enable JIT VM access | 🟡 Medium | Microsoft Defender for Cloud |
| Review all NSG rules in cluster | 🟡 Medium | Quarterly review cadence |

### Step 3A.3 — Threat Intelligence Enrichment

For each attacker IP identified:
1. Submit to [AbuseIPDB](https://www.abuseipdb.com) — check reputation score
2. Submit to [VirusTotal](https://www.virustotal.com) — check detection count
3. Search [Shodan](https://www.shodan.io) — identify open ports/services on attacker IP
4. Add confirmed malicious IPs to SIEM watchlist for ongoing monitoring

---

## Phase 3B: If Compromise IS Detected (Critical Escalation)

> ⚠️ **Stop.** If attacker IPs achieved successful logons — this is a **Security Incident**, not just a threat hunt finding. Escalate immediately.

### Step 3B.1 — Isolate the Device

- In MDE Portal: Select device → **Isolate device**
- This cuts all network connections while preserving forensic data

### Step 3B.2 — Preserve Evidence

```kql
// Capture timeline of all events on device after suspected compromise
DeviceProcessEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp > <COMPROMISE_TIMESTAMP>
| order by Timestamp asc

DeviceNetworkEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp > <COMPROMISE_TIMESTAMP>
| order by Timestamp asc

DeviceFileEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp > <COMPROMISE_TIMESTAMP>
| order by Timestamp asc
```

### Step 3B.3 — Escalation Path

```
Tier 1 Analyst
    ↓
Tier 2 SOC Analyst (Immediate escalation)
    ↓
SOC Manager / Incident Commander
    ↓
CISO (if data breach suspected)
    ↓
Legal / Compliance (if regulatory notification required)
```

### Step 3B.4 — Additional Investigation Queries

```kql
// What processes ran after the attacker logged in?
DeviceProcessEvents
| where DeviceName == "<DEVICE_NAME>"
| where InitiatingProcessAccountName == "<ATTACKER_ACCOUNT>"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

```kql
// Were any new user accounts created?
DeviceEvents
| where DeviceName == "<DEVICE_NAME>"
| where ActionType == "UserAccountCreated"
| project Timestamp, AccountName, InitiatingProcessFileName
```

```kql
// Were any files created or modified?
DeviceFileEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp > <COMPROMISE_TIMESTAMP>
| where ActionType in ("FileCreated", "FileModified")
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName
```

---

## Phase 4: Documentation & Reporting

### Step 4.1 — Incident Record (Fill Out)

```
Incident ID: _______________
Date Opened: _______________
Analyst: _______________

DEVICE INFORMATION
------------------
Device Name: _______________
Exposure Start: _______________
Exposure End: _______________
Total Exposure Duration: _______________

ATTACK SUMMARY
--------------
Number of Attacker IPs: _______________
Total Failed Logon Attempts: _______________
Brute Force Success: [ ] Yes  [ ] No
Unauthorized Accounts Used: [ ] Yes  [ ] No

VERDICT
-------
[ ] No Compromise
[ ] Compromise Confirmed
[ ] Inconclusive — further investigation required

ACTIONS TAKEN
-------------
[ ] NSG hardened
[ ] Attacker IPs blocked
[ ] Account lockout configured
[ ] MFA enabled
[ ] Device isolated (if compromised)

RECOMMENDATIONS
---------------
1. _______________
2. _______________
3. _______________
```

### Step 4.2 — Lessons Learned (Post-Hunt)

Answer the following:
- What **detection gap** allowed this exposure to go unnoticed?
- What **new detection rule** could catch this earlier next time?
- What **process or configuration** change would prevent recurrence?
- How was the **hunt methodology** — what worked, what didn't?

---

## Phase 5: Post-Incident Hardening

### Recommended Detection Rules to Create

| Rule | Trigger | Priority |
|---|---|---|
| Internet-Exposed Device Alert | Any device `IsInternetFacing == true` that's not whitelisted | 🔴 High |
| Brute Force Volume Alert | >50 failed logons from one IP in 5 min | 🔴 High |
| Brute Force Success Alert | Attacker IP achieves `LogonSuccess` after failed attempts | 🔴 Critical |
| After-Hours Logon Alert | Successful logons outside business hours | 🟡 Medium |

---

## Appendix: Common Commands

### Check NSG Rules (Azure CLI)
```bash
az network nsg rule list \
  --nsg-name <NSG_NAME> \
  --resource-group <RG_NAME> \
  --output table
```

### Restrict RDP to Specific IP (Azure CLI)
```bash
az network nsg rule update \
  --name AllowRDP \
  --nsg-name <NSG_NAME> \
  --resource-group <RG_NAME> \
  --source-address-prefixes <TRUSTED_IP>/32 \
  --priority 300
```

### Account Lockout Policy (GPO Path)
```
Computer Configuration →
  Windows Settings →
    Security Settings →
      Account Policies →
        Account Lockout Policy
          - Account lockout threshold: 10
          - Account lockout duration: 30
          - Reset account lockout counter: 30
```

---

*Playbook authored by: Saran | CyberRange Lab | March 27, 2026*  
*Review cycle: Quarterly or after each major incident*
