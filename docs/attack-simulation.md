# Attack Simulation

## Objective

Validate that attack traffic from the attacker network can reach the server network and be detected.

## Attacker

- VM: lab-attk-kali-01
- IP: 10.10.30.10

## Target

- VM: lab-srv-web-01
- IP: 10.10.10.10

## Commands Used

### Basic connectivity

```bash
ping 10.10.10.10
```

### Port Scan
```bash
nmap 10.10.10.10
``` 

### Deeper Scan
```bash
nmap -sS -A 10.10.10.10
```

## Observed Results
- SSH detected on port 22
- HTTP detected on port 80
- Scan traffic crossed the firewall successfully
- Suricata generated alerts