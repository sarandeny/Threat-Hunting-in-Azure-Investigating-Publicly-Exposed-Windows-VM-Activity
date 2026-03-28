
# 🔍 Threat Hunt Report: Devices Accidentally Exposed to the Internet

**Hunt ID:** TH-2026-001  
**Analyst:** Saran  
**Date:** March 27, 2026  
**Platform:** Microsoft Defender for Endpoint (MDE)  
**Target Device:** `saranpc2` (referred to as `windows-target-1` in environment)  
**Classification:** TLP:WHITE — Suitable for public sharing

---

## 1. Executive Summary

A threat hunt was initiated following the discovery that virtual machines (VMs) in the shared services cluster were inadvertently exposed to the public internet. The primary target of this investigation was `saranpc2`, which was confirmed to be internet-facing for several days.

The investigation revealed that **7 distinct external IP addresses** attempted brute-force logins against the device during its exposure window. Despite the volume of attempts, **no successful unauthorized logins were recorded**. The only successful remote network logons were attributed to the legitimate `labuser` account from recognized IP addresses.

**Verdict: No Compromise Detected.** However, the exposure itself represents a significant security gap that has since been remediated.

---

## 2. Preparation

### 2.1 Hunt Objective

Identify any VMs in the shared services cluster (DNS, Domain Services, DHCP) that were mistakenly exposed to the public internet, and assess whether any unauthorized access occurred during the exposure window.

### 2.2 Threat Hypothesis

> *"One or more exposed VMs may have been successfully brute-forced by an external threat actor, given the lack of account lockout policies on older legacy devices."*

**Rationale:**  
Devices exposed to the public internet without adequate hardening are frequently targeted by automated scanning and credential-stuffing tools within minutes of exposure. The combination of:

- Public internet reachability (no NSG restriction)
- No account lockout policy on legacy devices
- Open RDP port (Remote Desktop Protocol)

...creates a high-risk environment for successful brute-force attacks.

### 2.3 Key Data Sources Identified

| Table | Purpose |
|---|---|
| `DeviceInfo` | Identify which devices are internet-facing |
| `DeviceLogonEvents` | Analyze logon attempts (failed + successful) |

### 2.4 Scope

- **Primary target:** `saranpc2`
- **Secondary scope:** Any VM in the environment with similar exposure indicators

---

## 3. Data Collection

### 3.1 Confirming Internet Exposure

The first step was confirming that the target device was actually internet-facing and for how long.

**Query Used:**
```kql
DeviceInfo
| where DeviceName startswith "saran"
| where IsInternetFacing == true
| order by Timestamp desc
```

**Result:**  
- `saranpc2` was confirmed internet-facing.
- Last recorded internet-facing timestamp: **`2026-03-27T06:59:56.5662935Z`**
- The device had been in this state for **several days** prior to detection.

### 3.2 Log Availability Verification

Before proceeding with analysis, the following tables were confirmed to contain recent, relevant logs:

- ✅ `DeviceInfo` — Active and populated
- ✅ `DeviceLogonEvents` — Active with logon data for the target device

---

## 4. Data Analysis

### 4.1 Failed Logon Enumeration

To identify external brute-force attempts, all failed logons from remote IPs were aggregated by source.

**Query Used:**
```kql
DeviceLogonEvents
| where DeviceName startswith "saran"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```

**Key Findings:**

| Remote IP | Failed Attempts | Notes |
|---|---|---|
| `185.156.73.74` | Highest | Top attacker — likely automated tool |
| `99.209.201.66` | High | 2nd highest volume |
| `74.39.190.50` | Moderate | — |
| `121.30.214.172` | Moderate | — |
| `83.222.191.62` | Moderate | — |
| `45.41.204.12` | Moderate | — |
| `192.109.240.116` | Moderate | — |

> **Observation:** The volume and pattern of failed attempts from these IPs is consistent with **automated credential stuffing or brute-force tooling**, not manual login attempts.

### 4.2 Brute-Force Success Check

To determine if any of the attacking IPs had successfully logged in, the top suspect IPs were cross-referenced against successful logon events.

**Query Used:**
```kql
let RemoteIPsInQuestion = dynamic(["185.156.73.74","99.209.201.66",
    "74.39.190.50", "121.30.214.172", "83.222.191.62",
    "45.41.204.12", "192.109.240.116"]);

DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

**Result:** `<No Results>`

✅ **None of the identified attacker IPs achieved a successful logon.**

### 4.3 Baseline of Legitimate Remote Logons

To rule out any other unauthorized access, all successful remote network logons to the device in the last 30 days were reviewed.

**Query Used:**
```kql
DeviceLogonEvents
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where DeviceName startswith "saran"
```

**Result:**  
- **5 total successful network logons** — all attributed to the `labuser` account.

**Query Used (with IP breakdown):**
```kql
DeviceLogonEvents
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where DeviceName startswith "saran"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```

**Result:**  
All source IPs for the `labuser` account appeared **consistent and legitimate** — no unusual geographic locations or unknown IP ranges were identified.

**Additionally:** Zero failed logons were observed for the `labuser` account, ruling out any targeted brute-force attempt against that specific credential.

---

## 5. Investigation

### 5.1 Threat Actor Profiling

The attacking IPs (`185.156.73.74`, `99.209.201.66`, etc.) exhibited behavior consistent with:

- **Automated scanning bots** — rapid, high-volume login attempts
- **Credential stuffing campaigns** — testing commonly leaked username/password combos
- **Opportunistic attackers** — targeting exposed RDP ports identified via tools like Shodan or Censys

### 5.2 MITRE ATT&CK Correlation

| TTP | Technique | Evidence |
|---|---|---|
| **T1190** | Exploit Public-Facing Application | Device internet-exposed without authorization |
| **T1110** | Brute Force | Mass failed logons from 7 external IPs |
| **T1078** | Valid Accounts | Legitimate `labuser` logons investigated to rule out misuse |
| **T1587** | Develop Capabilities | Attacker infrastructure used (dedicated IPs for scanning) |

See [`mitre/ttp-mapping.md`](../mitre/ttp-mapping.md) for detailed analysis.

### 5.3 Timeline Reconstruction

```
[T-several days]  saranpc2 becomes internet-facing (NSG misconfiguration)
[T-several days]  Automated bots discover open RDP port
[T-ongoing]       Brute-force attempts begin from 7 external IPs
[T-ongoing]       No lockout triggered (no lockout policy configured)
[2026-03-27]      Security team initiates threat hunt
[2026-03-27]      Internet exposure confirmed via DeviceInfo query
[2026-03-27]      7 attacking IPs identified via DeviceLogonEvents
[2026-03-27]      Brute-force success check: NO results for any attacker IP
[2026-03-27]      Legitimate logon baseline established (labuser, 5 logons)
[2026-03-27]      Hunt conclusion: No compromise — Remediation initiated
[2026-03-27]      NSG hardened, RDP restricted to approved endpoints only
```

---

## 6. Response

### 6.1 Immediate Actions

| Action | Status | Detail |
|---|---|---|
| **NSG Hardening** | ✅ Complete | RDP access restricted to approved internal endpoints on `saranpc2`. Public internet access removed. |
| **Account Lockout Policy** | 🔲 Recommended | Configure lockout after N failed attempts on all devices, especially legacy ones. |
| **MFA Enforcement** | 🔲 Recommended | Enable Multi-Factor Authentication for all remote access accounts. |

### 6.2 Recommended Remediation Steps

1. **Audit all NSG rules** in the shared services cluster to identify other potentially misconfigured VMs.
2. **Enable Just-in-Time (JIT) VM Access** in Microsoft Defender for Cloud to eliminate persistent RDP exposure.
3. **Configure account lockout policy** via Group Policy (GPO):
   - Lockout threshold: 5–10 failed attempts
   - Lockout duration: 30 minutes (or administrator reset required)
4. **Deploy Conditional Access policies** to enforce MFA for all RDP and VPN access.
5. **Monitor with an alert rule** in MDE/Sentinel to trigger on `>X failed logons from a single external IP within Y minutes`.

---

## 7. Documentation

### 7.1 Evidence Summary

| Evidence Type | Detail |
|---|---|
| Internet Exposure Confirmed | `DeviceInfo` — `IsInternetFacing == true` |
| Brute-Force IPs | 7 external IPs with high failed logon counts |
| No Attacker Success | Zero results for attacker IPs in `LogonSuccess` events |
| Legitimate Logons | 5 `labuser` network logons from known IPs |
| Remediation | NSG hardened post-hunt |

### 7.2 Artifacts

- All KQL queries: [`queries/kql-queries.md`](../queries/kql-queries.md)
- MITRE mapping: [`mitre/ttp-mapping.md`](../mitre/ttp-mapping.md)
- IR Playbook: [`playbooks/exposed-device-response.md`](../playbooks/exposed-device-response.md)

---

## 8. Improvement

### 8.1 What Worked Well

- MDE telemetry provided **complete visibility** into logon events — both failed and successful.
- The `DeviceInfo` table's `IsInternetFacing` field was a **fast and reliable** starting point for identifying exposed assets.
- Using `let` to define the suspect IP list as a **dynamic variable** made the brute-force success query clean and easy to modify.

### 8.2 What Could Be Improved

| Gap | Recommendation |
|---|---|
| No automated alert existed for internet-facing devices | Create a Sentinel/MDE alert rule: `DeviceInfo | where IsInternetFacing == true` on new devices |
| No alert for high-volume failed logons | Alert when `>50 failed logons from a single external IP in 5 minutes` |
| Legacy devices lacked lockout policy | Enforce account lockout via GPO across all VMs |
| Hunt was reactive | Implement **continuous monitoring** of internet-facing devices using scheduled KQL queries |

### 8.3 Detection Engineering Opportunity

This hunt identified a gap that can be converted into a **detection rule**. Suggested Sentinel alert:

```kql
// Alert: High-Volume Failed Logons from External IP
DeviceLogonEvents
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| where LogonType has_any("Network", "RemoteInteractive")
| summarize FailedAttempts = count() by RemoteIP, DeviceName, bin(Timestamp, 5m)
| where FailedAttempts > 50
| project Timestamp, DeviceName, RemoteIP, FailedAttempts
```

> *Converting threat hunt findings into detection rules is a core SOC analyst skill — this is how a reactive hunt becomes a proactive defense.*

---

*Report authored by: Saran | CyberRange Lab | March 27, 2026*
