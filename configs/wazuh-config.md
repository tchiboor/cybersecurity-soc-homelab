# Wazuh Configuration Reference

## Platform

- Ubuntu Server 22.04
- Wazuh all-in-one deployment

## Syslog Reception

Wazuh configured to receive syslog on UDP 514.

Example config blocks:

```xml
<remote>
  <connection>secure</connection>
  <port>1514</port>
  <protocol>tcp</protocol>
  <queue_size>131072</queue_size>
</remote>

<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
</remote>

<localfile>
  <log_format>syslog</log_format>
  <location>udp://0.0.0.0:514</location>
</localfile>
```
## Validation Commands
```bash
sudo ss -lupn | grep 514
sudo tcpdump -i any port 514
sudo tail -f /var/ossec/logs/ossec.log
```