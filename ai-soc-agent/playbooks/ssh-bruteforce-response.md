# SSH Password-Guessing Response Playbook

## Triage

1. Identify the source IP address.
2. Identify the targeted server and account.
3. Confirm whether successful authentication followed repeated failures.
4. Determine whether the source belongs to an authorized administrator.
5. Search for related attempts against other hosts or accounts.

## Investigation

1. Review authentication logs.
2. Review the successful SSH session.
3. Inspect commands executed after login.
4. Review account privileges.
5. Search for file changes, persistence, and lateral movement.

## Containment Recommendations

Containment actions require human approval.

Possible actions:

1. Lock the affected account if access is unauthorized.
2. Rotate affected credentials.
3. Terminate suspicious sessions.
4. Restrict SSH access to approved management networks.
5. Prefer key-based authentication.
