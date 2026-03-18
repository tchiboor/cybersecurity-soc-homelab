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