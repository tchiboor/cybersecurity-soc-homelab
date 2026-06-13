# AI SOC Triage Setup Summary

## AI VM

Create an Ubuntu Server VM inside the SOC segment:

| Setting | Value |
|---|---|
| Hostname | `lab-ai-triage-01` |
| Username | `aiadmin` |
| IP address | `10.10.40.20/24` |
| Gateway | `10.10.40.1` |
| Network bridge | `vmbr4` |

## Ollama

Install Ollama and pull the local model:

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3:4b
```

Configure the systemd override:

```ini
[Service]
Environment="OLLAMA_NO_CLOUD=1"
Environment="OLLAMA_HOST=10.10.40.20:11434"
```

Restart the service:

```bash
sudo systemctl daemon-reload
sudo systemctl restart ollama
```

## UFW Rules

Allow SSH and restrict Ollama access to the Wazuh manager:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw allow from 10.10.40.10 to any port 11434 proto tcp
sudo ufw enable
```

## Wazuh Integration

Install the wrapper script:

```text
/var/ossec/integrations/custom-ai-triage
```

Install the AI-agent script:

```text
/var/ossec/integrations/ai-agent/live_triage.py
```

Install the SSH response playbook:

```text
/var/ossec/integrations/ai-agent/playbooks/ssh-bruteforce-response.md
```

Add the Wazuh integration block:

```xml
<integration>
  <name>custom-ai-triage</name>
  <rule_id>100101</rule_id>
  <alert_format>json</alert_format>
</integration>
```

Restart Wazuh:

```bash
sudo systemctl restart wazuh-manager
```

## Report Output

Generated AI-assisted reports are stored in:

```text
/var/ossec/logs/ai-triage-reports/
```

Integration status messages are written to:

```text
/var/ossec/logs/ai-triage-integration.log
```
