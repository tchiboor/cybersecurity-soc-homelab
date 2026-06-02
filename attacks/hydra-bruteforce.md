# Controlled SSH Password-Guessing Simulation with Hydra

## Overview

This scenario validates an end-to-end detection pipeline for SSH
password-guessing activity in an isolated cybersecurity homelab.

A controlled Hydra simulation was launched from a Kali Linux attacker endpoint
against a temporary SSH account on an Ubuntu server. The activity generated
repeated authentication failures followed by a successful login. The Ubuntu
endpoint logs were collected by the Wazuh agent and correlated into a
high-severity SIEM alert.

> **Ethical Use Notice:** This test was conducted only against an isolated,
> personally owned homelab using a temporary lab-only account. No public
> systems or third-party accounts were targeted.

## Attack Path

```text
Kali Linux Attacker
10.10.30.10
        ↓
OPNsense Firewall
        ↓
Ubuntu SSH Target
10.10.10.10
        ↓
Linux PAM Authentication Logs
        ↓
Wazuh Endpoint Agent
        ↓
Wazuh SIEM
        ↓
SOC Analyst Investigation
```

## Environment

| Component     | Role                                   | Address       |
| ------------- | -------------------------------------- | ------------- |
| Kali Linux    | Controlled attacker endpoint           | `10.10.30.10` |
| Ubuntu Server | SSH target                             | `10.10.10.10` |
| OPNsense      | Segmentation, routing, and firewalling | Lab edge      |
| Wazuh Agent   | Host-log collection                    | Ubuntu target |
| Wazuh SIEM    | Alert correlation and investigation    | SOC segment   |

The Ubuntu hostname is `lab-srv-web-01`. The endpoint is registered in the
Wazuh dashboard as `web-server-01`.

## Pre-Test Validation

Before launching the simulation:

1. The Ubuntu SSH service was confirmed to be active.
2. TCP port `22` was confirmed to be reachable from the Kali attacker segment.
3. The Wazuh endpoint agent was confirmed to be running.
4. A temporary `labuser` account was created for authorized testing.
5. A manual SSH login confirmed that the temporary credentials worked.

## Controlled Simulation

The following command was executed from Kali Linux:

```bash
hydra -l labuser -P ~/password.txt ssh://10.10.10.10 -V
```

A lab-only password list was used to generate repeated authentication failures
before a successful login.

## Host-Level Evidence

The Ubuntu authentication log recorded multiple failures:

```text
Failed password for labuser from 10.10.30.10
```

A later event confirmed successful authentication:

```text
Accepted password for labuser from 10.10.30.10
```

This created an important investigation pattern:

```text
Repeated authentication failures
        ↓
Successful authentication from the same source
        ↓
Potential account compromise requiring investigation
```

## SIEM Detection Result

Wazuh correlated the repeated authentication failures and generated a
high-severity analyst-facing alert.

| Field                  | Value                                                    |
| ---------------------- | -------------------------------------------------------- |
| Registered Wazuh agent | `web-server-01`                                          |
| Ubuntu hostname        | `lab-srv-web-01`                                         |
| Source IP              | `10.10.30.10`                                            |
| Target IP              | `10.10.10.10`                                            |
| Rule ID                | `5551`                                                   |
| Alert level            | `10`                                                     |
| Alert description      | `PAM: Multiple failed logins in a small period of time.` |
| MITRE ATT&CK technique | `T1110 — Brute Force`                                    |
| MITRE tactic           | `Credential Access`                                      |

## Evidence

| Evidence                                   | Screenshot                                                             |
| ------------------------------------------ | ---------------------------------------------------------------------- |
| Network segmentation                       | `screenshots/architecture/01-proxmox-network-bridges.png`              |
| Attacker network configuration             | `screenshots/kali/03-kali-attacker-network-config.png`                 |
| Target-server network configuration        | `screenshots/ubuntu/02-ubuntu-server-network-config.png`               |
| Active SSH service                         | `screenshots/ubuntu/04-ubuntu-ssh-service-status.png`                  |
| Active Wazuh endpoint agent                | `screenshots/ubuntu/05-ubuntu-wazuh-agent-service-active.png`          |
| SSH reachability from attacker segment     | `screenshots/hydra/06-kali-ssh-connectivity-check.png`                 |
| SSH service-version validation             | `screenshots/hydra/07-kali-nmap-ssh-service-check.png`                 |
| Temporary test account                     | `screenshots/ubuntu/09-ubuntu-labuser-created.png`                     |
| Normal SSH login test                      | `screenshots/hydra/10-manual-ssh-login-success.png`                    |
| Hydra controlled simulation                | `screenshots/hydra/11-hydra-controlled-attempts.png`                   |
| Redacted Hydra result                      | `screenshots/hydra/12-hydra-password-found-redacted.png`               |
| Ubuntu failures followed by accepted login | `screenshots/ubuntu/14-ubuntu-success-after-failures.png`              |
| Wazuh correlated alert overview            | `screenshots/wazuh/15-wazuh-bruteforce-alert-overview.png`             |
| Expanded Wazuh alert details               | `screenshots/wazuh/16-wazuh-bruteforce-alert-details.png`              |
| Authentication-success investigation       | `screenshots/wazuh/17-wazuh-authentication-success-after-failures.png` |

## Analyst Interpretation

Repeated SSH authentication failures can indicate password guessing. A later
successful login from the same source increases the priority of the alert
because the account may have been compromised.

The investigation should determine whether the source host belongs to an
authorized administrator and whether the successful session resulted in
suspicious activity.

## Recommended Mitigations

* Restrict SSH access to approved management networks.
* Disable unnecessary SSH exposure.
* Prefer SSH-key authentication over password-based authentication.
* Review successful logins following repeated failures.
* Apply rate limiting or temporary blocking for confirmed malicious sources.
* Rotate credentials after suspected compromise.
* Monitor related activity across other systems and accounts.

## Lessons Learned

* Network telemetry and host telemetry serve different purposes.
* Encrypted SSH traffic limits the visibility available to network inspection.
* Linux authentication logs provide decisive evidence for password-guessing
  investigations.
* SIEM correlation turns individual failures into an actionable alert.
* Analysts should verify whether a successful login occurred after repeated
  failures.
