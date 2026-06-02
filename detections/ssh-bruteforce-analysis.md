## SIEM Detection Result

The controlled Hydra simulation generated repeated SSH authentication failures
from the Kali attacker endpoint (`10.10.30.10`) against the Ubuntu target
server (`10.10.10.10`).

Wazuh correlated the repeated PAM authentication failures and generated the
following analyst-facing alert:

| Field | Value |
|---|---|
| Registered Wazuh agent | `web-server-01` |
| Ubuntu hostname | `lab-srv-web-01` |
| Rule ID | `5551` |
| Alert level | `10` |
| Description | `PAM: Multiple failed logins in a small period of time.` |
| MITRE ATT&CK technique | `T1110 — Brute Force` |
| MITRE tactic | `Credential Access` |
| Source IP | `10.10.30.10` |
| Target IP | `10.10.10.10` |

The Wazuh dashboard recorded a visible spike in security events during the
Hydra test window. The dashboard also reported authentication-success events,
requiring an analyst to verify whether a successful login followed the failed
attempts.

## Analyst Interpretation

The alert indicates repeated password-guessing activity against an SSH account.
Because the source generated numerous failures and the host logs recorded a
later accepted password, the event should be treated as a potential account
compromise until validated.

## Analyst Next Steps

1. Confirm the source IP and targeted account.
2. Review authentication-success events following the failures.
3. Determine whether the source belongs to an authorized administrator.
4. Review commands executed after any successful login.
5. Lock or reset the affected account if the activity is unauthorized.
6. Restrict SSH access to approved management networks.
7. Prefer key-based SSH authentication over password-based access.