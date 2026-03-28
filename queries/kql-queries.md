# 📊 KQL Query Reference — Exposed Device Threat Hunt

> All queries were executed in **Microsoft Defender for Endpoint (MDE)**  
> Platform: MDE Advanced Hunting / Microsoft Sentinel  
> Hunt Date: March 27, 2026

---

## Table of Contents

1. [Identify Internet-Facing Devices](#1-identify-internet-facing-devices)
2. [Failed Logon Enumeration by Source IP](#2-failed-logon-enumeration-by-source-ip)
3. [Brute Force Success Verification](#3-brute-force-success-verification)
4. [Legitimate Logon Baseline](#4-legitimate-logon-baseline)
5. [Logon Summary with IP Breakdown](#5-logon-summary-with-ip-breakdown)
6. [Bonus: Detection Engineering Queries](#6-bonus-detection-engineering-queries)

---

## 1. Identify Internet-Facing Devices

**Purpose:** Identify which devices in the environment are currently or were recently exposed to the public internet.

```kql
DeviceInfo
| where DeviceName startswith "saran"
| where IsInternetFacing == true
| order by Timestamp desc
```

**What to look for:**
- `IsInternetFacing == true` — direct confirmation of public exposure
- `Timestamp` — how long has the device been exposed?
- Multiple entries = device has been repeatedly internet-facing

**Result (this hunt):**  
`saranpc2` confirmed internet-facing. Last timestamp: `2026-03-27T06:59:56.5662935Z`

---

**Broader version (all devices in environment):**

```kql
DeviceInfo
| where IsInternetFacing == true
| summarize LastSeen = max(Timestamp) by DeviceName, PublicIP
| order by LastSeen desc
```

> 💡 **SOC Tip:** Run this query as a **scheduled hunt** to detect newly exposed devices automatically. Any device appearing here that shouldn't be internet-facing is an immediate priority.

---

## 2. Failed Logon Enumeration by Source IP

**Purpose:** Identify external IPs attempting to brute-force the exposed device.

```kql
DeviceLogonEvents
| where DeviceName startswith "saran"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```

**Field Reference:**

| Field | Description |
|---|---|
| `LogonType` | Type of logon (`Network` = RDP/SMB, `Interactive` = local login) |
| `ActionType` | `LogonFailed` or `LogonSuccess` |
| `RemoteIP` | Source IP of the logon attempt |
| `Attempts` | Aggregated count of failed attempts per IP |

**What to look for:**
- IPs with unusually high attempt counts (hundreds or thousands) → brute-force bot
- IPs from unexpected geographies → check with threat intel
- Attempts in short time windows → automated tooling

**Result (this hunt):**  
7 distinct external IPs identified. Top attacker: `185.156.73.74`

---

**Extended version — add time range and geolocation context:**

```kql
DeviceLogonEvents
| where Timestamp > ago(7d)
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize 
    Attempts = count(), 
    FirstSeen = min(Timestamp), 
    LastSeen = max(Timestamp) 
    by RemoteIP, DeviceName
| extend AttackDuration = LastSeen - FirstSeen
| order by Attempts desc
```

---

## 3. Brute Force Success Verification

**Purpose:** Determine whether any of the identified attacker IPs successfully authenticated.

```kql
let RemoteIPsInQuestion = dynamic(["185.156.73.74","99.209.201.66",
    "74.39.190.50", "121.30.214.172", "83.222.191.62",
    "45.41.204.12", "192.109.240.116"]);

DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

**Key concepts:**

- `let` — defines a variable (the suspect IP list) for reuse in the query
- `dynamic([...])` — creates a list/array type in KQL
- `has_any()` — checks if a field matches any value in the provided list

**What to look for:**
- Any result here = **potential compromise** → escalate immediately
- Check `AccountName` — which account did they log in as?
- Check `Timestamp` — when did the breach occur?

**Result (this hunt):**  
`<No Results>` — ✅ **No attacker IP achieved a successful logon.**

---

**Template version — update with your own IP list:**

```kql
// Replace IP addresses with your suspects
let SuspectIPs = dynamic([
    "ATTACKER_IP_1",
    "ATTACKER_IP_2",
    "ATTACKER_IP_3"
]);

DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(SuspectIPs)
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType
| order by Timestamp desc
```

---

## 4. Legitimate Logon Baseline

**Purpose:** Review all successful remote logons on the device to understand normal activity and rule out unauthorized access.

```kql
DeviceLogonEvents
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where DeviceName startswith "saran"
```

**What to look for:**
- Unexpected `AccountName` values (accounts that shouldn't have remote access)
- Logons outside business hours
- `RemoteIP` values that don't match known admin workstations or VPN ranges

**Result (this hunt):**  
5 total successful network logons, all from `labuser` account. No anomalies detected.

---

## 5. Logon Summary with IP Breakdown

**Purpose:** Get an aggregated view of all successful remote logons to identify patterns and spot anomalies.

```kql
DeviceLogonEvents
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where DeviceName startswith "saran"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```

**What to look for:**
- High `LoginCount` from a single `RemoteIP` may indicate scripted access
- Unknown `AccountName` = unauthorized account usage
- `RemoteIP` values outside trusted ranges

**Result (this hunt):**  
All IPs and accounts appeared consistent and legitimate.

---

## 6. Bonus: Detection Engineering Queries

These queries can be converted into **scheduled detection rules** in Microsoft Sentinel or MDE Custom Detections.

### 6.1 — Alert on High-Volume Failed Logons (Brute Force Detector)

```kql
DeviceLogonEvents
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| where LogonType has_any("Network", "RemoteInteractive")
| summarize FailedAttempts = count() by RemoteIP, DeviceName, bin(Timestamp, 5m)
| where FailedAttempts > 50
| project Timestamp, DeviceName, RemoteIP, FailedAttempts
```

> **Alert threshold:** >50 failed attempts per IP per 5-minute window  
> **Severity:** High  
> **Recommended action:** Block IP at NSG/firewall, investigate logon context

---

### 6.2 — Alert on Brute Force Followed by Success (Spray & Pray)

```kql
// Identify IPs that failed many times AND then succeeded
let FailedIPs = 
    DeviceLogonEvents
    | where ActionType == "LogonFailed"
    | where isnotempty(RemoteIP)
    | summarize FailCount = count() by RemoteIP, DeviceName
    | where FailCount > 10;

DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| join kind=inner FailedIPs on RemoteIP, DeviceName
| project Timestamp, DeviceName, AccountName, RemoteIP, FailCount
| order by Timestamp desc
```

> **Severity:** Critical  
> **Recommended action:** Immediately isolate device, reset credentials, initiate IR process

---

### 6.3 — Newly Internet-Exposed Devices (Continuous Monitoring)

```kql
// Find devices that became internet-facing in the last 24 hours
DeviceInfo
| where IsInternetFacing == true
| where Timestamp > ago(24h)
| summarize FirstSeen = min(Timestamp) by DeviceName, PublicIP
| order by FirstSeen desc
```

> **Run frequency:** Every 1 hour  
> **Severity:** Medium  
> **Recommended action:** Validate if intentional — if not, remove internet exposure immediately

---

### 6.4 — After-Hours Remote Logon Detection

```kql
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where LogonType has_any("Network", "RemoteInteractive")
| where isnotempty(RemoteIP)
| extend HourOfDay = datetime_part("hour", Timestamp)
| where HourOfDay < 7 or HourOfDay > 19  // Adjust for your timezone/work hours
| project Timestamp, DeviceName, AccountName, RemoteIP, HourOfDay
| order by Timestamp desc
```

> **Severity:** Medium  
> **Recommended action:** Validate with account owner — may be legitimate after-hours work or unauthorized access

---

## Quick Reference: Key KQL Operators Used

| Operator | Usage |
|---|---|
| `where` | Filter rows based on condition |
| `summarize` | Aggregate data (count, min, max, etc.) |
| `order by` | Sort results |
| `project` | Select specific columns to display |
| `extend` | Add a new calculated column |
| `let` | Define a variable or sub-query |
| `has_any()` | Match field against a list of values |
| `isnotempty()` | Filter out null/empty values |
| `startswith` | String prefix matching |
| `bin()` | Round timestamps to a time bucket |
| `join` | Combine two tables on a key |
| `ago()` | Time relative to now (e.g., `ago(7d)`) |
| `datetime_part()` | Extract part of a datetime (hour, day, etc.) |

---

*Queries authored by: Saran | CyberRange Lab | March 27, 2026*
