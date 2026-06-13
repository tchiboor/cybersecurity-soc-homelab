# AI SOC Triage Validation

## Objective

The purpose of validation was to prove that:

1. the local model receives selected Wazuh alerts;
2. the model generates useful investigation recommendations;
3. Python preserves authoritative evidence fields;
4. high-priority alerts generate reports automatically;
5. routine SSH logins do not trigger unnecessary AI processing.

## Offline High-Priority Test

A sanitized rule-`100101` alert was provided to the offline triage agent.

Expected result:

```text
Event type: ssh_success_after_failures
Severity: High
```

The generated report included:

- Wazuh rule `100101`;
- alert level `12`;
- source IP `10.10.30.10`;
- endpoint `web-server-01`;
- account `labuser`;
- correlation threshold `5`;
- MITRE ATT&CK IDs `T1110.001` and `T1078`.

Screenshot:

```text
screenshots/ai-agent/40-offline-ai-high-priority-triage-report.png
```

## Offline Benign-Login Test

A sanitized rule-`5715` alert was provided to the agent.

Expected result:

```text
Event type: routine_ssh_success
Severity: Low
```

The report correctly stated that no containment action was recommended based on
the alert alone.

Screenshot:

```text
screenshots/ai-agent/41-offline-ai-benign-login-report.png
```

## Manual Wazuh-to-AI Integration Test

The Wazuh wrapper script was executed manually using a stored rule-`100101`
alert.

Expected result:

```text
SUCCESS: AI triage report generated for rule 100101
```

Screenshot:

```text
screenshots/ai-agent/45-manual-wazuh-ai-integration-test.png
```

## Automatic Live Positive Control

A controlled Hydra simulation was executed:

```text
Five failed SSH authentication attempts
→ one successful SSH login
→ Wazuh rule 100101
→ automatic AI triage report
```

Observed result:

```text
Reports before live test: 2
Reports after live test:  3
```

Screenshot:

```text
screenshots/ai-agent/48-live-automatic-ai-triage-report.png
```

## Automatic Live Negative Control

A routine SSH login was performed without prior failures.

Expected result:

```text
Routine SSH login
→ Wazuh rule 5715
→ no AI report
```

Observed result:

```text
Reports before normal login: 3
Reports after normal login:  3
```

Screenshot:

```text
screenshots/ai-agent/49-routine-login-filter-no-new-ai-report.png
```

## Validation Result

The AI-assisted workflow behaves as intended:

| Test | Expected Result | Observed Result |
|---|---|---|
| High-priority SSH pattern | AI report generated | Passed |
| Routine SSH login | No AI report generated | Passed |
| Report evidence integrity | Correct trusted fields | Passed |
| Autonomous containment | Disabled | Passed |
| Human approval requirement | Included | Passed |
