## `attacks/nmap-scan.md`

```markdown
# Nmap Scan

## Command

```bash
nmap -sS -A 10.10.10.10
```

## Purpose
- identify open ports
- detect services
- simulate reconnaissance

## Result
Observed open services:
- 22/tcp SSH
- 80/tcp HTTP

## Detection
Suricata generated scan-related alerts.