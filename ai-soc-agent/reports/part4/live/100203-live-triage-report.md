# Incident Summary

A new local account `tempuser99` was created on `web-server-01`; source IP `unknown`.

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

Creation of a new local account can indicate persistence when it is not tied to an approved administrative change. Verify the change against an approved request and confirm the creating actor was authorized.

## Recommended Next Steps

1. Verify the creation context of the new user account 'tempuser99' on web-server-01
2. Check for recent authentication attempts associated with this account
3. Review system logs for any unusual activity by this user account
4. Cross-reference with other Wazuh alerts for similar patterns on the same host

## Human Approval Required

Yes. A human analyst must verify authorization before any containment or account action.

## Limitations

- This report is based only on the supplied sanitized Wazuh alert.
- The source IP authorization status is not included in the alert.
- Additional telemetry may be required to confirm or dismiss the activity.
- The report does not perform autonomous containment.
