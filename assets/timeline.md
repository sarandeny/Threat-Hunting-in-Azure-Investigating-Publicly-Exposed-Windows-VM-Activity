
# ⏱️ Attack Timeline Reconstruction

**Device:** `saranpc2`  
**Hunt Date:** March 27, 2026  
**Analyst:** Saran

---

## Timeline of Events

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[T-SEVERAL DAYS]
    📌 EVENT: NSG Misconfiguration
    ─────────────────────────────────────────────────────────────────
    saranpc2 is accidentally exposed to the public internet.
    RDP port (3389) becomes reachable from any source IP.
    The security team is not yet aware.
    
    Source: DeviceInfo (IsInternetFacing == true, early timestamps)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[T-SEVERAL DAYS to T-HUNT]
    📌 EVENT: Internet Discovery by Threat Actors
    ─────────────────────────────────────────────────────────────────
    Automated scanners (Shodan, Censys, Masscan, botnets) detect
    an open RDP port on saranpc2's public IP. The device is added
    to attacker target lists.
    
    Status: Inferred (consistent with typical attacker behavior)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[T-ONGOING]
    📌 EVENT: Brute Force Campaign Begins
    ─────────────────────────────────────────────────────────────────
    7 external IP addresses begin automated credential attacks.
    High-volume password guessing is performed against RDP.
    No account lockout policy is in place — attacks continue
    unimpeded by lockout mechanisms.
    
    Attacker IPs:
    ┌────────────────────┬─────────────────────────────────────────┐
    │ 185.156.73.74      │ Highest attempt volume — Top attacker   │
    │ 99.209.201.66      │ Second highest volume                   │
    │ 74.39.190.50       │ Moderate activity                       │
    │ 121.30.214.172     │ Moderate activity                       │
    │ 83.222.191.62      │ Moderate activity                       │
    │ 45.41.204.12       │ Moderate activity                       │
    │ 192.109.240.116    │ Moderate activity                       │
    └────────────────────┴─────────────────────────────────────────┘
    
    Source: DeviceLogonEvents (ActionType == "LogonFailed")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[T-ONGOING (SAME PERIOD)]
    📌 EVENT: Legitimate Access (labuser)
    ─────────────────────────────────────────────────────────────────
    The labuser account successfully logs in 5 times via RDP
    over the exposure period. All source IPs are consistent
    and recognized. No failed attempts precede these logons —
    ruling out credential compromise.
    
    Source: DeviceLogonEvents (ActionType == "LogonSuccess",
            AccountName == "labuser")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27T06:59:56.566Z]
    📌 EVENT: Last Confirmed Internet-Facing Timestamp
    ─────────────────────────────────────────────────────────────────
    MDE records the final internet-facing event for saranpc2.
    
    Source: DeviceInfo (IsInternetFacing == true)
    Data: 2026-03-27T06:59:56.5662935Z

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27 — HUNT INITIATED]
    📌 EVENT: Security Team Begins Threat Hunt
    ─────────────────────────────────────────────────────────────────
    Routine maintenance review triggers investigation into
    potentially misconfigured VMs. Hypothesis formed:
    "Could brute-force attacks have succeeded?"
    
    Hunt begins using MDE Advanced Hunting (KQL).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27 — DATA COLLECTION]
    📌 QUERY 1: Confirm internet exposure
    ─────────────────────────────────────────────────────────────────
    DeviceInfo | where DeviceName startswith "saran"
               | where IsInternetFacing == true
    
    ✅ Result: saranpc2 confirmed exposed. Last seen: 06:59:56Z

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27 — DATA ANALYSIS]
    📌 QUERY 2: Enumerate failed logons by source IP
    ─────────────────────────────────────────────────────────────────
    DeviceLogonEvents | where ActionType == "LogonFailed"
                      | where isnotempty(RemoteIP)
    
    ✅ Result: 7 external IPs with brute-force activity identified
    
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27 — INVESTIGATION]
    📌 QUERY 3: Check if any attacker IPs succeeded
    ─────────────────────────────────────────────────────────────────
    DeviceLogonEvents | where ActionType == "LogonSuccess"
                      | where RemoteIP has_any(AttackerIPs)
    
    ✅ Result: <NO RESULTS> — No attacker IP achieved access

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27 — VERIFICATION]
    📌 QUERY 4: Baseline legitimate logons
    ─────────────────────────────────────────────────────────────────
    DeviceLogonEvents | where ActionType == "LogonSuccess"
                      | where LogonType == "Network"
    
    ✅ Result: 5 logons — all labuser, all from known IPs
    ✅ Zero failed logons for labuser (not targeted by brute-force)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27 — VERDICT]
    📌 CONCLUSION: No Compromise Detected
    ─────────────────────────────────────────────────────────────────
    ✅ Device was internet-facing for several days
    ✅ 7 external IPs launched brute-force attacks
    ✅ NO attacker achieved a successful logon
    ✅ All legitimate logons are accounted for and verified
    
    VERDICT: No breach. Exposure closed. Remediation in progress.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27 — RESPONSE]
    📌 REMEDIATION: NSG Hardened
    ─────────────────────────────────────────────────────────────────
    NSG attached to saranpc2 updated:
    - RDP access restricted to specific approved endpoints ONLY
    - Public internet RDP access removed
    
    Additionally recommended:
    - Account lockout policy (GPO)
    - MFA enforcement for remote access

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## What Could Have Happened (Threat Modeling)

If the brute-force had **succeeded**, the likely adversary kill chain would have been:

```
RDP Brute Force Success (T1110)
         ↓
Attacker gains interactive access to saranpc2
         ↓
Discovery: whoami, ipconfig, net user, net localgroup (T1082, T1087)
         ↓
Persistence: Create new admin account, registry run key (T1136, T1547)
         ↓
Lateral Movement: RDP to other hosts in shared services cluster (T1021)
         ↓
Impact: Ransomware, data exfiltration, or DNS/DHCP manipulation (T1486, T1565)
```

The exposure of a **shared services cluster VM** is particularly dangerous — successful compromise could have cascaded to DNS, DHCP, and Domain Services, affecting the entire environment.

---

## Key Timestamps Reference

| Timestamp | Event |
|---|---|
| `[T-several days]` | saranpc2 becomes internet-facing (NSG misconfiguration) |
| `[T-several days]` | Brute-force attempts begin from external IPs |
| `2026-03-27T06:59:56Z` | Last confirmed internet-facing event |
| `2026-03-27` | Threat hunt initiated — exposure discovered |
| `2026-03-27` | 7 attacker IPs identified — no success confirmed |
| `2026-03-27` | Legitimate logon baseline established |
| `2026-03-27` | NSG hardened — exposure closed |

---

*Timeline reconstructed by: Saran | CyberRange Lab | March 27, 2026*
