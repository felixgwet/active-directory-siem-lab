# Detection Rules

## Overview

This directory contains Splunk SPL detection rules developed during the Active Directory Security Monitoring Lab. Each rule maps to a MITRE ATT&CK technique and targets specific Windows Event IDs.

---

## Rule 1: Privileged Group Modification

**File:** `privileged_group_modification.spl`
**EventCode:** 4728
**Severity:** HIGH
**MITRE ATT&CK:** T1098 — Account Manipulation

### Description
Detects when a user account is added to a security-enabled global group (e.g., Domain Admins, IT_Admins, Enterprise Admins). This is a common privilege escalation technique used by attackers to maintain persistence.

### Splunk SPL
```spl
index=* source="WinEventLog:Security" EventCode=4728
| table _time, Account_Name, MemberName, ComputerName, Security_ID
| eval Risk="HIGH"
| eval Description="User added to privileged group"
| sort - _time
```

### Expected Output
| _time | Account_Name | MemberName | ComputerName | Risk |
|-------|-------------|------------|--------------|------|
| 2026-09-15 10:33:41 | Administrator | testuser | LAB-SERVER | HIGH |

### False Positive Considerations
- Legitimate IT staff adding users to groups during onboarding
- Service account provisioning

### Recommended Action
- Verify with the account owner or IT manager
- Check for concurrent EventCode 4732 (member added to local group)
- Review authentication logs for the added account

---

## Rule 2: Multiple Failed Logons (Brute Force)

**File:** `brute_force_detection.spl`
**EventCode:** 4625
**Severity:** MEDIUM
**MITRE ATT&CK:** T1110 — Brute Force

### Description
Identifies accounts with more than 5 failed logon attempts within the search timeframe. May indicate password guessing, brute force, or credential stuffing attacks.

### Splunk SPL
```spl
index=* source="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, ComputerName, Source_Network_Address
| where count > 5
| eval Alert="Potential Brute Force"
| sort - count
```

### Expected Output
| Account_Name | ComputerName | count | Alert |
|-------------|--------------|-------|-------|
| testuser | LAB-CLIENT | 10 | Potential Brute Force |

### False Positive Considerations
- Users forgetting passwords after holiday
- Service accounts with expired credentials
- Shared accounts (bad practice but common)

### Recommended Action
- Check if the account is legitimate
- Verify source IP (internal vs external)
- If external, check firewall logs for port scanning
- Force password reset if suspicious

---

## Rule 3: Event Volume Monitoring

**File:** `event_volume_baseline.spl`
**EventCode:** N/A (volume-based)
**Severity:** LOW
**MITRE ATT&CK:** N/A

### Description
Establishes a baseline of security event volume per endpoint. Sudden spikes or drops may indicate log tampering, disabled auditing, or mass exploitation.

### Splunk SPL
```spl
index=* host=LAB-CLIENT
| timechart span=1h count by source
| eval baseline=round(avg(count), 0)
| eval deviation=abs(count - baseline)
| where deviation > (baseline * 0.5)
```

---

## Rule 4: Successful Logon After Multiple Failures

**File:** `suspicious_successful_logon.spl`
**EventCodes:** 4625 + 4624
**Severity:** HIGH
**MITRE ATT&CK:** T1110.001 — Password Guessing

### Description
Detects a successful authentication (EventCode 4624) immediately following multiple failed attempts (EventCode 4625) for the same account. Strong indicator of a successful brute force.

### Splunk SPL
```spl
index=* source="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| transaction Account_Name maxspan=5m
| where eventcount >= 5 AND mvcount(EventCode) > 1
| search EventCode=4624
| table _time, Account_Name, ComputerName, eventcount
| eval Alert="Successful brute force suspected"
```

---

## How to Use These Rules

1. Open Splunk Search & Reporting
2. Copy the SPL query into the search bar
3. Adjust the time range (Last 15 minutes, Last 4 hours, etc.)
4. Click Save As > Report or Save As > Dashboard Panel
5. Set up alerting (if using Splunk Enterprise Security or scheduled searches)

---

## References

- [Microsoft Security Event IDs](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Splunk SPL Documentation](https://docs.splunk.com/Splexicon:SPL)
