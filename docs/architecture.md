# Architecture

## Purpose

The lab is designed to simulate a segmented enterprise security environment for offensive and defensive security testing.

## High-Level Design

The environment is built on Proxmox and uses OPNsense as the central firewall and routing platform.

Security zones:

- Management
- Servers
- Attack
- SOC

## Core Components

### OPNsense
Provides:
- routing
- firewall policy
- segmentation
- Suricata IDS/IPS
- syslog forwarding

### Management VM
Used to:
- access the firewall GUI
- manage the lab
- browse dashboards

### Server VM
Hosts the target web service for attack simulation.

### Kali VM
Used to perform reconnaissance and attack simulation.

### SOC VM
Runs Wazuh SIEM and receives forwarded logs and alerts.

## Traffic Flow

1. Attack traffic originates from Kali.
2. Traffic crosses OPNsense.
3. Suricata inspects traffic.
4. Events are forwarded to Wazuh.
5. Alerts are reviewed in the SOC dashboard.