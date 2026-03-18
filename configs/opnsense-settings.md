
## `configs/opnsense-settings.md`

```markdown
# OPNsense Settings Reference

## Interfaces

- WAN → DHCP
- LAN → 10.10.0.1/24
- SERVERS → 10.10.10.1/24
- ATTACK → 10.10.30.1/24
- SOC → 10.10.40.1/24

## Firewall Rules

Pass rules created for:
- SERVERS net → any
- ATTACK net → any
- SOC net → any

## Remote Logging

Remote log target:
- Host: 10.10.40.10
- Port: 514
- Transport: UDP
- Categories: firewall, intrusion detection, system