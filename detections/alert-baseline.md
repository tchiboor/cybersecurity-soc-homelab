# Alert Baseline and Noise Review

## Objective

Establish a normal-traffic baseline for the SOC homelab and compare benign
administrative activity against the previously validated Hydra SSH
password-guessing simulation.

The purpose of this exercise is to distinguish routine events from activity
that requires analyst escalation.

## Environment

| Component              | Role                   | Address          |
| ---------------------- | ---------------------- | ---------------- |
| Kali Linux             | Test endpoint          | `10.10.30.10`    |
| Ubuntu Server          | Monitored target       | `10.10.10.10`    |
| Ubuntu hostname        | Target hostname        | `lab-srv-web-01` |
| Wazuh registered agent | SIEM endpoint name     | `web-server-01`  |
| Wazuh SIEM             | Centralized monitoring | SOC segment      |

## Benign Activities Tested

| Test | Activity                          | Expected Classification                              |
| ---- | --------------------------------- | ---------------------------------------------------- |
| 1    | One successful SSH login          | Routine administrative activity                      |
| 2    | One incorrect SSH password        | Possible user typing error                           |
| 3    | Normal HTTP GET and HEAD requests | Routine web traffic                                  |
| 4    | Ubuntu package update check       | Routine administrative activity; reviewed separately |

## Baseline Results

| Activity                    |   Wazuh Rule ID |    Alert Level | Result                          | Analyst Action                 |
| --------------------------- | --------------: | -------------: | ------------------------------- | ------------------------------ |
| Normal SSH login            | `[ADD RULE ID]` |  `[ADD LEVEL]` | Authentication success recorded | Retain as audit telemetry      |
| One incorrect SSH password  | `[ADD RULE ID]` |  `[ADD LEVEL]` | Individual failure recorded     | Monitor; do not escalate alone |
| Normal HTTP requests        |  `[ADD RESULT]` | `[ADD RESULT]` | Routine traffic                 | Retain as telemetry            |
| Hydra SSH password guessing |          `5551` |           `10` | Correlated brute-force alert    | Investigate and escalate       |

## Comparison

| Indicator                 | Normal Baseline          | Hydra Simulation                         |
| ------------------------- | ------------------------ | ---------------------------------------- |
| Failed SSH logins         | One isolated event       | Concentrated burst of failures           |
| Successful authentication | Routine login            | Successful login after repeated failures |
| Time pattern              | Occasional               | Rapid and concentrated                   |
| Alert severity            | Low or routine           | Level `10`                               |
| MITRE ATT&CK mapping      | Not necessarily required | `T1110 — Brute Force`                    |
| Analyst action            | Retain as telemetry      | Investigate as potential compromise      |

## Analyst Interpretation

A single failed password attempt does not automatically indicate malicious
activity. Users can make typing errors. In contrast, repeated failures within a
short period followed by a successful login represent a higher-risk pattern.

The Hydra simulation generated a concentrated burst of authentication failures.
Wazuh correlated the events and generated a level-10 alert using rule `5551`:

```text
PAM: Multiple failed logins in a small period of time.
```

The baseline demonstrates why security monitoring should preserve low-level
telemetry while escalating patterns that are more likely to represent
unauthorized activity.

## Evidence

| Evidence                              | Screenshot                                                       |
| ------------------------------------- | ---------------------------------------------------------------- |
| Baseline session start                | `screenshots/baseline/18-baseline-session-start.png`             |
| Normal SSH login                      | `screenshots/baseline/19-normal-ssh-login.png`                   |
| Single incorrect SSH password         | `screenshots/baseline/20-single-failed-ssh-login.png`            |
| Normal HTTP requests                  | `screenshots/baseline/21-normal-http-requests.png`               |
| Ubuntu baseline authentication logs   | `screenshots/baseline/22-ubuntu-baseline-auth-events.png`        |
| Wazuh authentication-success event    | `screenshots/baseline/23-wazuh-authentication-success-event.png` |
| Wazuh single-failure event            | `screenshots/baseline/24-wazuh-single-failure-event.png`         |
| Wazuh baseline-events overview        | `screenshots/baseline/25-wazuh-baseline-events-overview.png`     |
| Baseline compared with Hydra activity | `screenshots/baseline/26-baseline-vs-hydra-summary.png`          |

## Lessons Learned

* Normal activity still creates security telemetry.
* A single failed login can be benign and should not automatically trigger a
  high-priority incident.
* Concentrated failures within a short period are more suspicious than isolated
  failures.
* A successful login after repeated failures increases the need for
  investigation.
* Alert quality depends on context, correlation, and analyst judgment.
