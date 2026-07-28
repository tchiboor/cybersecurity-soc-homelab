# Local AI-Assisted SOC Triage Agent

## Overview

This project extends my Proxmox-based cybersecurity SOC homelab with a local,
read-only AI-assisted triage workflow.

The goal is not to replace a SIEM or automate containment decisions. The goal
is to enrich selected Wazuh alerts with structured investigation guidance while
preserving human analyst oversight.

The initial use case detects a successful SSH login after repeated failed
authentication attempts from the same source IP.

```text
Five failed SSH login attempts
→ successful SSH login
→ custom Wazuh rule 100101
→ local AI-assisted triage report
→ human analyst review
```

## Why I Built This

My earlier SOC pipeline already demonstrated:

```text
Kali attacker
→ OPNsense firewall
→ Suricata IDS
→ Wazuh SIEM
→ analyst dashboard
```

I then added a custom Wazuh correlation rule to identify a higher-risk SSH
pattern:

```text
Password guessing
→ valid account access
→ potential account compromise
```

The AI-assisted extension adds a read-only triage layer after the SIEM alert is
generated.

## Architecture

```mermaid
flowchart TD
    A["Kali attacker VM<br/>10.10.30.10"] --> B["Ubuntu target · web-server-01<br/>10.10.10.10"]
    B --> C[Wazuh agent]
    C --> D["Wazuh manager<br/>10.10.40.10"]
    D --> E[Custom Wazuh rule 100101]
    E --> F["Wazuh Integrator<br/>custom-ai-triage"]
    F --> G[Allowlisted JSON fields only]
    G --> H["Local Ollama API · lab-ai-triage-01<br/>10.10.40.20:11434 · qwen3:4b"]
    H --> I[AI-generated investigation recommendations]
    I --> J[Python-rendered authoritative evidence]
    J --> K[Human analyst review]
```

## Supported Detection Use Case

The first supported high-priority detection is:

```text
Five failed SSH authentication attempts
→ one successful SSH login from the same source IP
→ Wazuh rule 100101
→ level-12 alert
→ AI-assisted triage report
```

The custom detection maps to:

| MITRE ATT&CK ID | Technique |
|---|---|
| `T1110.001` | Password Guessing |
| `T1078` | Valid Accounts |

## How the Agent Works

The workflow has two layers.

### 1. Deterministic Evidence

Python extracts and renders authoritative alert facts directly from the
sanitized Wazuh JSON alert.

These fields include:

- Wazuh rule ID
- alert level
- alert description
- source IP address
- target endpoint
- target account
- correlation threshold
- MITRE ATT&CK mappings

The AI model is not allowed to rewrite these facts.

### 2. AI-Assisted Investigation Recommendations

The local model generates only defensive investigation suggestions, such as:

- review authentication logs;
- inspect the successful SSH session;
- verify account privileges;
- search for file modifications;
- check for unusual post-login process activity.

The model does not block IP addresses, disable accounts, modify firewall rules,
or perform containment actions.

## Security Controls

The design intentionally limits the AI agent.

- Ollama runs locally inside the SOC network.
- Ollama cloud features are disabled.
- The Ollama API listens on `10.10.40.20:11434`.
- UFW allows API access only from the Wazuh manager at `10.10.40.10`.
- The Kali attacker VM cannot access the Ollama API.
- Only selected Wazuh alert fields are sent to the model.
- Raw authentication logs are excluded from model input.
- Credentials, tokens, and unrelated metadata are excluded.
- Python renders trusted evidence fields directly from the Wazuh alert.
- The AI model generates defensive recommendations only.
- Human approval is required before containment actions.

## Validation

### Positive Control

The positive-control test used a controlled Hydra simulation:

```text
Five failed SSH attempts
→ one successful login
→ Wazuh rule 100101 generated
→ automatic AI triage report created
```

The report count increased:

```text
Reports before live test: 2
Reports after live test:  3
```

### Negative Control

A normal SSH login was then performed without prior failures:

```text
One routine SSH login
→ Wazuh rule 5715
→ no AI report created
```

The report count remained unchanged:

```text
Reports before normal login: 3
Reports after normal login:  3
```

This confirms that the Wazuh integration forwards only rule `100101`.

## Performance

The local model runs on the AI VM using Ollama.

During iterative testing, report-generation latency improved from approximately
44 seconds to approximately 12 seconds after:

- disabling unnecessary reasoning output;
- using structured JSON outputs;
- limiting model-generated content;
- allowing Python to render authoritative evidence;
- keeping the model loaded between requests.

## Repository Structure

```text
ai-soc-agent/
├── README.md
├── agent/
│   └── live_triage.py
├── integration/
│   └── custom-ai-triage
├── playbooks/
│   └── ssh-bruteforce-response.md
├── sample-alerts/
│   ├── benign-ssh-login-redacted.json
│   └── rule-100101-alert-redacted.json
└── docs/
    ├── architecture.md
    ├── limitations.md
    ├── security-controls.md
    ├── setup.md
    └── validation.md
```

## Important Design Principle

The AI model is an analyst aid, not a source of truth.

```text
Wazuh alert
→ trusted security evidence
→ AI-assisted recommendations
→ human analyst judgment
```

## Future Improvements

Planned extensions include:

- Zeek network telemetry enrichment;
- Suricata alert enrichment;
- threat-intelligence lookups;
- additional Wazuh custom rules;
- case-management integration;
- analyst feedback tracking;
- report-quality evaluation;
- detection tuning and false-positive reduction.

Autonomous containment remains intentionally disabled.
