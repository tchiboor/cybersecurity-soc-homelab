# SSH Password-Guessing Response Playbook

## Trigger

Multiple failed SSH authentication attempts from the same source IP within a
short period.

## Escalation Conditions

Escalate when:

* A successful login follows repeated failures.
* The source IP is not an approved administrative endpoint.
* Multiple usernames are targeted.
* Multiple servers are targeted.
* Suspicious commands are executed after login.
* A privileged account is involved.

## Triage

1. Identify the source IP.
2. Identify the destination server.
3. Identify the targeted username.
4. Count failed login attempts.
5. Check whether authentication later succeeded.
6. Determine whether the source belongs to an authorized administrator.
7. Search for related activity across other endpoints.

## Containment

1. Block the unauthorized source IP.
2. Lock or disable the affected account when compromise is suspected.
3. Rotate affected credentials.
4. Terminate suspicious sessions.
5. Restrict SSH access to approved management networks.

## Investigation

1. Review `/var/log/auth.log`.
2. Search Wazuh events for the source IP.
3. Review successful logins following failed attempts.
4. Inspect commands executed after successful access.
5. Review file changes and persistence mechanisms.
6. Search for lateral movement.
7. Confirm whether additional accounts were targeted.

## Long-Term Improvements

1. Prefer SSH-key authentication.
2. Disable password authentication where practical.
3. Limit SSH access using firewall rules or VPN access.
4. Apply rate limiting or temporary source blocking.
5. Tune SIEM thresholds after establishing a normal-traffic baseline.
6. Monitor repeated attempts across multiple hosts and accounts.
