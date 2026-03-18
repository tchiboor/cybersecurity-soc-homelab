# Detection Pipeline

## Overview

The lab forwards IDS and firewall logs from OPNsense to Wazuh for centralized monitoring.

## Pipeline

```text
Kali
  ↓
OPNsense
  ↓
Suricata
  ↓
Remote syslog
  ↓
Wazuh manager
  ↓
Wazuh dashboard
```

## Components
### Suricata
Detects:
- Nmap scanning
- suspicious traffic patterns
- exploit-related signatures

### OPNsense Syslog
Forwards:
- firewall logs
- intrusion detection logs
- system logs

### Wazuh
Receives and centralizes logs for SOC analysis.

## Validation
Traffic forwarding was confirmed using tcpdump on the SOC node:
```bash
sudo tcpdump -i any port 514
```
This showed OPNsense sending traffic to Wazuh server

