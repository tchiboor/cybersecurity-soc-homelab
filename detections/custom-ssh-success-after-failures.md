## Live-Telemetry Troubleshooting

The custom rule triggered successfully during synthetic testing with
`wazuh-logtest`, but the first live test did not generate the expected alert.

Investigation showed that repeated SSH failures were being compressed in
`/var/log/auth.log` into summary entries such as:

```text
message repeated 5 times: [Failed password for labuser ...]
```
Because the custom rule depends on counting individual authentication-failure
events, the compressed log entries prevented the live correlation threshold
from being reached consistently.

To preserve individual events, repeated-message reduction was disabled on the
Ubuntu target server:

sudo tee /etc/rsyslog.d/00-disable-repeated-message-reduction.conf >/dev/null <<'EOF'
$RepeatedMsgReduction off
EOF

sudo systemctl restart rsyslog
sudo systemctl restart wazuh-agent

After the logging change, the live validation was repeated with a clean
sequence of five failed SSH attempts followed by one successful login. Wazuh
generated custom rule 100101 at level 12.

This demonstrated that detection engineering requires validating the full live
telemetry path, not only the rule logic.