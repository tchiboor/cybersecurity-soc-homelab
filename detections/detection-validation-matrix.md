# Detection Validation Matrix

| Scenario | Tool | Target | Network Visibility | Host Visibility | SIEM Visibility | Outcome |
|---|---|---|---|---|---|---|
| TCP reconnaissance | Nmap | Ubuntu web server | Suricata and firewall logs | Limited | Forwarded events | Detected |
| Web assessment | Nikto | Apache web server | HTTP and IDS events | Apache logs | Partial visibility | Observed |
| SSH password guessing | Hydra | Ubuntu SSH service | Repeated TCP/22 connections | PAM failures and successful login | Wazuh rule `5551`, level `10`, MITRE `T1110` | Detected |