# AI SOC Triage Architecture

## Purpose

This document describes the architecture of the local AI-assisted SOC triage
workflow.

The AI layer enriches selected Wazuh alerts with defensive investigation
recommendations. It does not replace Wazuh detection logic or human analyst
judgment.

## Network Placement

The AI triage VM is deployed inside the SOC network.

| System | Role | IP Address |
|---|---|---|
| `lab-attk-kali-01` | Attacker simulation VM | `10.10.30.10` |
| `lab-srv-web-01` | Ubuntu target web server | `10.10.10.10` |
| `lab-soc-monitor-01` | Wazuh manager | `10.10.40.10` |
| `lab-ai-triage-01` | Local AI triage server | `10.10.40.20` |

## End-to-End Flow

```text
Hydra SSH simulation
        ↓
Ubuntu authentication logs
        ↓
Wazuh agent
        ↓
Wazuh manager
        ↓
Custom correlation rule 100101
        ↓
Wazuh Integrator
custom-ai-triage
        ↓
Allowlisted alert fields
        ↓
Local Ollama API
10.10.40.20:11434
        ↓
qwen3:4b
        ↓
Investigation recommendations
        ↓
Deterministic Markdown report
        ↓
Human analyst review
```

## Detection Logic

The custom Wazuh detection identifies:

```text
Five failed SSH login attempts
→ one successful SSH login
→ same source IP
→ 120-second correlation window
```

The alert is generated as:

| Field | Value |
|---|---|
| Rule ID | `100101` |
| Rule level | `12` |
| Detection category | SSH success after repeated failures |
| MITRE ATT&CK | `T1110.001`, `T1078` |

## Integration Filtering

The Wazuh configuration forwards only rule `100101`:

```xml
<integration>
  <name>custom-ai-triage</name>
  <rule_id>100101</rule_id>
  <alert_format>json</alert_format>
</integration>
```

This prevents normal SSH-success alerts and unrelated SIEM events from
triggering AI processing.

## AI-Agent Responsibility Boundary

Python renders authoritative evidence.

The local model generates only defensive investigation suggestions.

```text
Trusted Wazuh JSON
→ Python evidence renderer
→ local AI recommendation generator
→ Markdown report
```

The model cannot:

- change firewall rules;
- disable accounts;
- block IP addresses;
- execute shell commands;
- modify Wazuh;
- perform autonomous containment.
