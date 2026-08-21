# Runbook — Building & Triggering the 5 Custom Alerts in Wazuh

Goal: deploy rules 100201–100205, then generate real activity so each alert
appears in the Wazuh dashboard and (optionally) auto-triages through the agent.

**Order:** easy rules first (sudo, new account), then web auth, then the two
firewall-dependent ones (port scan, outbound).

Three golden rules before you start:
1. **logtest before you trust a rule.** Base SIDs vary by version.
2. **One alert at a time.** Trigger, confirm in dashboard, then move on — so a
   screenshot maps cleanly to one action.
3. **These run against your OWN lab hosts only.**

---

## Phase 0 — Deploy the rules

On the Wazuh manager:

```bash
# Back up first
sudo cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak

# Append the Part 4 rules (paste the contents of local_rules_part4.xml,
# WITHOUT a second <group> wrapper if you merge by hand — or keep them as a
# separate <group> block, which is fine).
sudo nano /var/ossec/etc/rules/local_rules.xml

# Sanity-check the ruleset parses, then restart
sudo /var/ossec/bin/wazuh-logtest -v   # Ctrl-C after it loads with no errors
sudo systemctl restart wazuh-manager
sudo tail -f /var/ossec/logs/ossec.log   # watch for rule-load errors
```

---

## Phase 1 — Easy: sudo failure (100201)

### Confirm the base rule first
```bash
sudo /var/ossec/bin/wazuh-logtest
# paste a real sudo failure line from /var/log/auth.log, e.g.:
# sudo: pam_unix(sudo:auth): authentication failure; logname=jdoe uid=1000 ... user=jdoe
```
Read the reported **Rule id** — if it's not `5401`, update `<if_matched_sid>`
in 100201 to match, then restart the manager.

### Trigger it (on the monitored Ubuntu host)
```bash
# Fail sudo 3+ times within 60s (type a wrong password each time)
sudo -k                       # reset cached credentials
for i in 1 2 3 4; do sudo -S true <<< "definitely_wrong_password"; done
```

### Verify
- Dashboard → Security events → filter `rule.id:100201`
- CLI: `sudo tail -f /var/ossec/logs/alerts/alerts.json | grep 100201`

---

## Phase 1 — Easy: new privileged account (100203)

### Confirm the base rule
```bash
sudo /var/ossec/bin/wazuh-logtest
# paste a real useradd line, e.g.:
# useradd[12345]: new user: name=tempuser99, UID=1501, GID=1501, home=/home/tempuser99 ...
```
If the reported Rule id isn't `5902`, update `<if_sid>` in 100203.

### Trigger it (on the monitored Ubuntu host)
```bash
sudo useradd -m tempuser99
sudo usermod -aG sudo,docker tempuser99   # privileged group add = the interesting part

# ---- CLEANUP when done (do NOT leave this account) ----
# sudo deluser --remove-home tempuser99
```

### Verify
`rule.id:100203` in the dashboard. This one is single-event, so it fires
immediately — no threshold to hit.

---

## Phase 2 — Web auth failures (100205)

Prereq: your Apache/nginx auth logs must reach Wazuh (you already ingest Apache
per the validation matrix). Point this at a login endpoint that returns 401.

### Confirm the base rule
```bash
sudo /var/ossec/bin/wazuh-logtest
# paste a real 401 access-log line from your web server
```
Note the reported Rule id (commonly the 31100/31108 web family) and update
`<if_matched_sid>` in 100205 to match.

### Trigger it (from Kali, against your lab web server)
```bash
# 10+ failed logins in 5 min from one source. Adjust URL/host to your lab.
for i in $(seq 1 15); do
  curl -s -o /dev/null -u admin:wrongpass http://<LAB_WEB_HOST>/admin/login
done
# or with hydra (already in your toolkit):
# hydra -l admin -P /usr/share/wordlists/rockyou.txt <LAB_WEB_HOST> http-get /admin/login
```

### Verify
`rule.id:100205`. If it doesn't fire, check that individual 401s are being
decoded (logtest) before blaming the composite threshold.

---

## Phase 3 — Firewall-dependent: port scan (100202)

Prereq: OPNsense firewall drops (or Suricata recon alerts) must be forwarded to
Wazuh. Check first:
```bash
# On the manager — are you seeing ANY firewall events?
sudo grep -m5 -iE "opnsense|pf|firewall|suricata" /var/ossec/logs/alerts/alerts.json
```
- **If yes:** confirm the drop event's group/SID with logtest and set
  `<if_matched_group>firewall_drop</if_matched_group>` (or the Suricata scan
  SID) accordingly in 100202.
- **If no:** you need to wire up firewall/Suricata log forwarding first. Until
  then, 100202 can't fire from real traffic — validate it via fixture instead
  (see Fallback below) and be transparent about that in the article.

### Trigger it (from Kali)
```bash
# SYN scan across many ports — generates the block/recon events
sudo nmap -sS -p 1-1000 <LAB_TARGET_HOST>
```

### Verify
`rule.id:100202`. Remember: this fires on *N block events from one source*, not
literally "8 distinct ports" — Wazuh frequency counts events, not unique ports.

---

## Phase 3 — Firewall-dependent: suspicious outbound (100204)

The hardest to produce authentically. It needs egress logging that records the
destination port. If your OPNsense passes and logs outbound, generate a
connection to a high/uncommon port on a host you control:

```bash
# On the monitored host — open an outbound connection to YOUR OWN listener.
# Start a listener on a box you control (NOT a third party):
#   nc -lvnp 4444          # on your controlled destination
# Then from the monitored host:
nc <YOUR_CONTROLLED_DEST> 4444 <<< "lab egress test"
```
Match the destination port your firewall decoder logs (100204 keys on `4444`).
If egress isn't logged/forwarded, use the fixture fallback and say so.

### Verify
`rule.id:100204`.

---

## Phase 4 — Auto-triage the real alerts (optional but strong for Part 4)

Right now the agent only auto-runs on rule 100101. Extend the integration so the
new rules trigger it too. On the manager, in `ossec.conf`:

```xml
<integration>
  <name>custom-ai-triage</name>
  <rule_id>100101,100201,100202,100203,100204,100205</rule_id>
  <alert_format>json</alert_format>
</integration>
```
```bash
sudo systemctl restart wazuh-manager
# After triggering an alert, watch the agent run and write a report:
sudo tail -f /var/ossec/logs/ai-triage-integration.log
ls -lt /var/ossec/logs/ai-triage-reports/ | head
```
This closes the loop: **real dashboard alert → agent triage → report**, which is
a much stronger Part 4 story than fixtures alone.

---

## Fallback — validate a rule you can't trigger live

If a log source isn't wired up yet, you can still prove the *detection logic* by
replaying a captured log line through logtest, and prove the *triage* with your
existing fixture:

```bash
# detection logic:
echo '<paste a representative raw log line>' | sudo /var/ossec/bin/wazuh-logtest

# triage on the matching fixture:
python3 ai-soc-agent/agent/live_triage.py \
  ai-soc-agent/sample-alerts/part4/port_scan.json \
  --playbook ai-soc-agent/playbooks/general-soc-response.md \
  --output /tmp/port_scan_report.md
```
Being explicit in the article about which alerts are shown live end-to-end vs.
fixture-validated is a credibility *gain*, not a weakness.

---

## Screenshot checklist for Part 4

For each rule you get firing live, capture:
- [ ] The dashboard event with `rule.id`, level, and MITRE technique visible
- [ ] The alert detail / expanded JSON (shows the decoded fields)
- [ ] The generated triage report from `/var/ossec/logs/ai-triage-reports/`
- [ ] (nice) the `wazuh-logtest` output proving the rule matched the raw log

---

## Cleanup

```bash
# Remove the test account
sudo deluser --remove-home tempuser99 2>/dev/null

# Kill any listeners you started
# (Ctrl-C the nc listener on your controlled destination)

# Restore rules if you were only testing
# sudo cp /var/ossec/etc/rules/local_rules.xml.bak /var/ossec/etc/rules/local_rules.xml
# sudo systemctl restart wazuh-manager
```
