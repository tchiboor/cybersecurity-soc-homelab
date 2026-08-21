# Incident Summary

A new account `tempuser99` was created on `web-server-01` and added to privileged groups; source IP `unknown`.

## Severity

**High**

## Evidence

- Wazuh rule: `100203`
- Alert level: `12`
- Alert description: `auditd: new user account created on the system.`
- Source IP: `unknown`
- Target endpoint: `web-server-01`
- Target account: `tempuser99`
- Correlation threshold: `unknown` prior matched events
- MITRE ATT&CK IDs: `T1136.001, T1098`
- MITRE ATT&CK techniques: `Local Account, Account Manipulation`
- Prompt injection marker detected: `false`

## Analyst Interpretation

Creation of a new account with privileged group membership is a common persistence and privilege-escalation technique. Verify the change against an approved change request and confirm the creating actor was authorized.

## Recommended Next Steps

1. Verify the creation context of the new user account 'tempuser99' on web-server-01
2. Check for recent authentication attempts associated with this account
3. Review system logs for any unusual activity by this account post-creation
4. Cross-reference with known privileged user groups to assess risk level

## Human Approval Required

Yes. A human analyst must verify authorization before any containment or account action.

## Limitations

- This report is based only on the supplied sanitized Wazuh alert.
- The source IP authorization status is not included in the alert.
- Additional telemetry may be required to confirm or dismiss the activity.
- The report does not perform autonomous containment.
