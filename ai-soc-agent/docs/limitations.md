# AI SOC Triage Limitations

## Current Scope

The first version supports a focused SSH detection use case:

```text
Repeated failed SSH authentication attempts
→ successful login
→ rule 100101
→ AI-assisted triage report
```

## Known Limitations

- The AI output is an analyst aid, not a source of truth.
- The model does not have access to full endpoint telemetry.
- The model does not perform threat-intelligence lookups.
- The model does not correlate alerts across multiple endpoints.
- The model does not inspect packet captures.
- The model does not execute commands.
- The model does not perform autonomous containment.
- The initial deployment uses a small local model.
- CPU-based inference can introduce report-generation latency.
- Additional detection templates are required for new alert categories.
- Prompt-injection marker detection is keyword-based: novel or obfuscated
  phrasings will not match, and generic markers (for example,
  "system prompt") could occasionally flag benign text. The primary
  defense remains the architecture: the model has no authority over
  evidence, severity, or verdicts.

## Future Enhancements

Potential improvements include:

- Suricata alert enrichment;
- Zeek telemetry enrichment;
- threat-intelligence integration;
- case-management integration;
- multiple detection templates;
- analyst-feedback collection;
- report-quality scoring;
- false-positive tracking;
- local retrieval-augmented playbooks;
- dashboard visualization for generated reports.
