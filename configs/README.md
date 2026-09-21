# Configuration Files

## Splunk Universal Forwarder — inputs.conf

**Location:** `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

```ini
[WinEventLog://Security]
disabled = 0

[WinEventLog://System]
disabled = 0

[WinEventLog://Application]
disabled = 0
```

### What This Does
Tells the Universal Forwarder which Windows Event Log channels to monitor and forward to the Splunk indexer. All three channels are enabled by default.

### Additional Channels (Optional)
```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0

[WinEventLog://Setup]
disabled = 0

[WinEventLog://ForwardedEvents]
disabled = 0
```

---

## Splunk Universal Forwarder — outputs.conf

**Location:** `C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf`

```ini
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = 10.0.2.15:9997

[tcpout-server://10.0.2.15:9997]
```

### What This Does
Directs the Universal Forwarder to send all collected data to the Splunk indexer at `10.0.2.15` on port `9997`.

### Note
Using the IP address instead of hostname (`LAB-SERVER`) ensures connectivity even if DNS resolution fails within the virtual network.

---

## Splunk Enterprise — inputs.conf (Server Local)

**Location:** `C:\Program Files\Splunk\etc\system\local\inputs.conf`

```ini
[WinEventLog://Security]
disabled = 0

[WinEventLog://System]
disabled = 0

[WinEventLog://Application]
disabled = 0
```

### What This Does
Configures the Splunk Enterprise instance on LAB-SERVER to ingest its own local Windows Event Logs, in addition to receiving data from the Universal Forwarder.

---

## Splunk Enterprise — Receiving Port

**Configured via:** Splunk Web > Settings > Forwarding and Receiving > Configure Receiving

| Setting | Value |
|---------|-------|
| Port | 9997 |
| Protocol | TCP |
| Purpose | Ingest data from Universal Forwarders |

---

## Windows Firewall (Lab Only)

**Command used to disable firewall for lab testing:**
```cmd
netsh advfirewall set allprofiles state off
```

> **Warning:** This is only appropriate for an isolated lab environment. In production, open specific ports (8000, 8089, 9997) instead.

---

## Active Directory Structure

```
gwetlab.local
├── IT
│   ├── testuser (User)
│   └── IT_Admins (Security Group)
├── Teachers
└── Students
```

---

## VirtualBox Network Configuration

### LAB-SERVER
| Adapter | Type | Purpose |
|---------|------|---------|
| Adapter 1 | NAT | Internet access |
| Adapter 2 | Host-Only Adapter | VM-to-VM communication (192.168.56.x) |

### LAB-CLIENT
| Adapter | Type | Purpose |
|---------|------|---------|
| Adapter 1 | NAT | Internet access |
| Adapter 2 | Host-Only Adapter | VM-to-VM communication (192.168.56.x) |

### IP Addresses
| VM | Host-Only IP | Role |
|----|-------------|------|
| LAB-SERVER | 10.0.2.15 (NAT) / 192.168.56.x (Host-Only) | Domain Controller + Splunk |
| LAB-CLIENT | 10.0.2.15 (NAT) / 192.168.56.x (Host-Only) | Domain Member |

> Note: Both VMs share the same NAT IP (10.0.2.15) via VirtualBox NAT, but communicate via the Host-Only adapter (192.168.56.x) for domain and Splunk traffic.
