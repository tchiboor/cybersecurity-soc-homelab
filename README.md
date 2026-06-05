# Cybersecurity SOC Homelab

A Proxmox-based cybersecurity homelab designed for attack simulation, intrusion detection, SIEM monitoring, and blue-team / red-team practice.

## Overview

This project documents the design and implementation of a segmented virtual security lab using:

- Proxmox VE
- OPNsense firewall
- Suricata IDS/IPS
- Wazuh SIEM
- Kali Linux
- Ubuntu Server
- Ubuntu Desktop

The lab simulates a small enterprise network with separate zones for management, servers, attackers, and SOC monitoring.

## Lab Goals

- Practice network segmentation
- Simulate attacker behavior
- Detect attacks with Suricata
- Centralize alerts in Wazuh
- Build a reusable security research platform

## Architecture

```text
                 Internet
                     │
                 Home Router
                     │
                  OPNsense
      ┌──────────────┼───────────────┬───────────────┐
      │              │               │               │
 MGMT (vmbr1)    SERVERS (vmbr2)  ATTACK (vmbr3)  SOC (vmbr4)
10.10.0.0/24     10.10.10.0/24    10.10.30.0/24   10.10.40.0/24
Ubuntu Desktop   Ubuntu Server    Kali Linux      Wazuh SOC
VM 101           VM 200           VM 400          VM 300
```
## Virtual Machines

| VM ID | Name               | Role                   | Network                |
| ----: | ------------------ | ---------------------- | ---------------------- |
|   100 | lab-fw-edge-01     | OPNsense firewall      | WAN + all lab networks |
|   101 | lab-mgmt-util-01   | Management workstation | 10.10.0.0/24           |
|   200 | lab-srv-web-01     | Web server target      | 10.10.10.0/24          |
|   300 | lab-soc-monitor-01 | Wazuh SIEM / SOC       | 10.10.40.0/24          |
|   400 | lab-attk-kali-01   | Attacker machine       | 10.10.30.0/24          |

## Tools Used
- Proxmox VE
- OPNsense
- Wazuh
- Suricata
- Kali Linux
- Apache 2
- Nmap

## Detection Pipeline
```text
Kali attacker
      ↓
OPNsense firewall
      ↓
Suricata IDS/IPS
      ↓
Syslog forwarding
      ↓
Wazuh SIEM
      ↓
SOC dashboard alerts
```
## Validated Detection Scenarios

| Scenario | Tool | Evidence | Result |
|---|---|---|---|
| Network reconnaissance | Nmap | Suricata and firewall visibility | Detected |
| Web-server assessment | Nikto | HTTP findings and IDS visibility | Observed |
| SSH password guessing | Hydra | PAM logs and Wazuh rule `5551` | Detected |

### SSH Password-Guessing Case Study

A controlled Hydra simulation generated repeated SSH authentication failures
against a temporary test account. The Ubuntu host recorded failed logins
followed by a successful authentication attempt.

Wazuh correlated the activity into a level-10 alert:

```text
PAM: Multiple failed logins in a small period of time.

The alert mapped to MITRE ATT&CK: T1110 — Brute Force
```

### Alert Baseline and Noise Review

After validating the Hydra SSH password-guessing alert, I generated normal SSH
and HTTP traffic to compare benign behavior against attack activity.

The baseline demonstrated the difference between:

```text
One isolated authentication failure
→ monitor as low-priority telemetry

Repeated failures in a short period
→ correlated level-10 Wazuh alert
→ investigate as potential compromise
```

### Custom Wazuh Detection Engineering

After establishing a normal-traffic baseline, I created a custom Wazuh
correlation rule for a higher-risk SSH pattern:

```text
Five failed SSH login attempts
→ successful login from the same source IP
→ custom level-12 alert
→ investigate possible account compromise
```
The rule was validated with:

- wazuh-logtest
- a live sequential Hydra simulation
- a negative-control test
- live-telemetry troubleshooting after identifying rsyslog message compression

## Repository Structure
- docs/ → design and implementation notes

- configs/ → firewall, Suricata, and Wazuh configuration references

- attacks/ → attack simulation notes

- diagrams/ → architecture images

- screenshots/ → dashboard and lab screenshots

## Future Improvements

- Zeek network telemetry

- packet capture and replay

- additional vulnerable applications

- threat intelligence integration

- automated attack simulation

## Author

Trevor Henry Chiboora
Cybersecurity Research Engineer