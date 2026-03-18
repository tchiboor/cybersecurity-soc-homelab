# Network Design

## Subnets

| Zone | Subnet | Gateway |
|------|--------|---------|
| Management | 10.10.0.0/24 | 10.10.0.1 |
| Servers | 10.10.10.0/24 | 10.10.10.1 |
| Attack | 10.10.30.0/24 | 10.10.30.1 |
| SOC | 10.10.40.0/24 | 10.10.40.1 |

## Proxmox Bridges

| Bridge | Purpose |
|--------|---------|
| vmbr0 | WAN / Home LAN |
| vmbr1 | Management |
| vmbr2 | Servers |
| vmbr3 | Attack |
| vmbr4 | SOC |

## IP Assignments

| Host | IP Address |
|------|------------|
| OPNsense LAN | 10.10.0.1 |
| OPNsense SERVERS | 10.10.10.1 |
| OPNsense ATTACK | 10.10.30.1 |
| OPNsense SOC | 10.10.40.1 |
| Management VM | DHCP on 10.10.0.0/24 |
| Web Server | 10.10.10.10 |
| SOC Node | 10.10.40.10 |
| Kali | 10.10.30.10 |