# Project Walkthrough — Active Directory Security Monitoring Lab

> This document explains the design decisions, challenges, and lessons from building this lab. It mirrors how I would present this project in a technical interview.

---

## The 60-Second Pitch

"I built a self-contained SOC lab to develop my security operations skills. I deployed a Windows Server 2025 domain controller with Active Directory and DNS, joined a Windows 11 Pro client to the domain, and installed Splunk Enterprise as a SIEM. I configured the Splunk Universal Forwarder to ship Windows Security, System, and Application logs to the SIEM, then simulated real attack scenarios — privilege escalation via group membership changes and brute-force authentication attempts. I wrote Splunk detection rules for EventCode 4728 and 4625, mapped them to MITRE ATT&CK, and built a monitoring dashboard. I'm now pursuing Security+ and BTL1 to formalise these skills."

---

## Design Decisions

### Why Windows Server 2025?
I chose the latest evaluation release to work with current Microsoft security features and ensure the skills transfer directly to modern enterprise environments.

### Why Splunk?
Splunk is the most commonly requested SIEM in UK job postings. Learning it gives me the broadest employability. The free 500MB/day licence is sufficient for a two-VM lab.

### Why VirtualBox?
Free, lightweight, and widely documented. The Host-Only adapter pattern for VM-to-VM communication is a standard isolation technique I can explain in interviews.

### Why a Domain-Joined Client?
A standalone VM would be easier, but useless for learning AD-centric detection. The domain join forced me to understand DNS, Kerberos, Group Policy, and how authentication events flow differently between local and domain contexts.

---

## Challenges & How I Solved Them

| Challenge | Solution |
|-----------|----------|
| Windows 11 refused to install in VirtualBox (TPM 2.0 error) | Used the documented registry bypass during OOBE: created `LabConfig` key with `BypassTPMCheck` and `BypassSecureBootCheck` DWORDs |
| VMs could not communicate after domain join | Added second Host-Only network adapters; configured client DNS to point to server's Host-Only IP |
| Splunk forwarder stopped sending data | Discovered `outputs.conf` was using hostname instead of IP; switched to static IP `10.0.2.15:9997` |
| Failed logon events (4625) not appearing | Learned that domain authentication logs on the DC, not the client; pivoted to detecting EventCode 4728 (privilege escalation) which logs on the DC |
| VM time drift broke domain trust | Manually synced time on both VMs using `Set-Date` PowerShell cmdlet |

---

## Detection Engineering Logic

### Privileged Group Modification (EventCode 4728)

**Why this matters:** Attackers who compromise an account often add it to Domain Admins or similar groups to maintain persistence. This is quieter than creating a new account.

**What the rule does:** Surfaces every instance of a user being added to a security-enabled global group, with the actor, target, and timestamp.

**How I'd improve it in production:**
- Filter out known service accounts and approved change windows
- Correlate with EventCode 4732 (local group changes)
- Add risk scoring based on the privilege level of the target group

### Brute Force Detection (EventCode 4625)

**Why this matters:** Password guessing is still one of the most common initial access vectors. Early detection prevents lateral movement.

**What the rule does:** Aggregates failed logons per account and flags anything above 5 attempts.

**How I'd improve it in production:**
- Add `bucket span=5m` to detect bursts
- Include `Source_Network_Address` to spot distributed attacks
- Correlate with EventCode 4624 to catch successful brute forces immediately

---

## What I Would Add Next

- **Sysmon** for process creation, DNS, and network connection telemetry
- **A Linux endpoint** (Ubuntu or CentOS) to practice cross-platform log ingestion
- **pfSense firewall VM** to analyse network-layer traffic and detect port scans
- **Splunk Enterprise Security** for risk-based alerting and correlation searches
- **Sigma rules** to make detection logic portable across Splunk, Sentinel, and Elastic

---

## Key Takeaways

1. **Theory is not enough.** I knew what a SIEM was from my BCTec role, but configuring inputs, outputs, and parsing rules myself revealed gaps I would never have spotted in a course.
2. **Logs lie by omission.** When 4625 events did not appear, I had to understand *why* — domain auth vs local auth, audit policy settings, forwarder connectivity — not just blame the tool.
3. **Documentation matters.** I wrote this README and the detection rule explanations as I built, not after. It forced me to clarify my own thinking and created interview material simultaneously.
