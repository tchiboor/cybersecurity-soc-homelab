# wazuh-logtest Cheat Sheet — Part 4 Rules

`wazuh-logtest` replays a raw log line through the decoders + ruleset so you can
see which rule matches and what fields get decoded — **before** you trigger the
real activity. Use it to confirm each parent SID and adjust the XML if needed.

```bash
sudo /var/ossec/bin/wazuh-logtest
# paste ONE raw log line, press Enter. Ctrl-C to exit.
# add -v for verbose decoder output:  sudo /var/ossec/bin/wazuh-logtest -v
```

**How to read the output** — you care about three things:
- `Phase 2: Completed decoding.` → the **decoded fields** (srcip, dstuser, etc.)
- `Phase 3: Completed filtering (rules).` → **Rule id** and **level** that fired
- If your custom rule (1002xx) shows here, it matched. If only the *base* rule
  shows, your `<if_sid>`/`<if_matched_sid>` points at the wrong parent — fix it.

> Composite/frequency rules (100201, 100202, 100205) will NOT fire from a single
> pasted line — logtest processes one event at a time. Use logtest to confirm the
> **base** rule + decoded fields match; confirm the *composite* by triggering the
> real activity and checking the dashboard.

---

## 100201 — sudo failure  (base ~5401)

Sample raw line (from `/var/log/auth.log`):
```
Aug 11 09:15:22 prod-server-01 sudo: pam_unix(sudo:auth): authentication failure; logname=jdoe uid=1000 euid=0 tty=/dev/pts/1 ruser=jdoe rhost= user=jdoe
```
Expect: a sudo auth-failure base rule (commonly **5401** / "Failed attempt to run
sudo"). Note the **Rule id** reported and set `<if_matched_sid>` in 100201 to it.
Decoded `dstuser`/`user` should be `jdoe`.

Also valid to test with the "incorrect password" summary line:
```
Aug 11 09:15:22 prod-server-01 sudo:     jdoe : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/jdoe ; USER=root ; COMMAND=/bin/bash
```

---

## 100202 — port scan  (base = your firewall drop / Suricata recon)

OPNsense/pf filterlog sample:
```
Aug 11 10:22:11 opnsense filterlog: 5,,,1000000103,igb1,match,block,in,4,0x0,,64,54321,0,DF,6,tcp,60,203.0.113.42,10.10.30.10,51514,3306,0,S,...
```
Suricata eve.json alert sample (if you route Suricata instead):
```
{"timestamp":"2026-08-11T10:22:11Z","event_type":"alert","src_ip":"203.0.113.42","dest_ip":"10.10.30.10","dest_port":3306,"proto":"TCP","alert":{"signature":"ET SCAN Potential SYN Scan","category":"Attempted Recon"}}
```
Expect: a firewall-block base rule (its **group** should include something like
`firewall_drop`) OR a Suricata scan signature rule. Set 100202's
`<if_matched_group>` (or `<if_matched_sid>`) to whichever your system reports.
Decoded `srcip` should be `203.0.113.42`.

---

## 100203 — new account  (base ~5902)  ← single-event, WILL fire in logtest

Sample raw line:
```
Aug 11 14:33:05 prod-server-01 useradd[12345]: new user: name=tempuser99, UID=1501, GID=1501, home=/home/tempuser99, shell=/bin/bash, from=/dev/pts/1
```
Expect: base **5902** ("New user added to the system"), and because 100203 is a
single-event child (`<if_sid>5902</if_sid>`), **your 100203 rule should appear in
Phase 3** with level 12. If it doesn't, 5902 is the wrong parent on your version —
correct it. The privileged-group add is a separate line worth testing too:
```
Aug 11 14:33:05 prod-server-01 usermod[12346]: add 'tempuser99' to group 'sudo'
```

---

## 100204 — suspicious outbound  (base = firewall pass w/ dstport)

OPNsense pass/allow sample showing the outbound to 4444:
```
Aug 11 02:14:56 opnsense filterlog: 10,,,1000000104,igb0,match,pass,out,4,0x0,,64,12345,0,DF,6,tcp,60,192.168.1.10,198.51.100.77,44231,4444,0,S,...
```
Expect: a firewall base rule in group `firewall`. Confirm the decoder populates a
**destination port** field and that `4444` appears — 100204 matches on it. If your
decoder names the field differently than `<match>4444</match>` catches, switch to
`<field name="dstport">4444</field>` with the exact decoded field name.

---

## 100205 — web auth failure  (base ~31108 / 31100 family)

Apache/nginx access-log 401 sample:
```
203.0.113.88 - admin [11/Aug/2026:11:05:33 +0000] "POST /admin/login HTTP/1.1" 401 512 "-" "python-requests/2.28.0"
```
Expect: a web base rule for a 401/auth failure (commonly the **31100/31108**
family). Note the reported **Rule id** and set 100205's `<if_matched_sid>` to it.
Decoded `srcip` should be `203.0.113.88`, `url` should be `/admin/login`.

---

## Fast verification loop (per rule)

```bash
# 1. paste the sample line for the rule you're working on
sudo /var/ossec/bin/wazuh-logtest

# 2. if the wrong/only-base rule fired, edit the parent SID/group:
sudo nano /var/ossec/etc/rules/local_rules.xml

# 3. reload and re-test
sudo systemctl restart wazuh-manager
sudo /var/ossec/bin/wazuh-logtest   # paste again, confirm 1002xx now appears
```

Once logtest confirms the base rule + decoded fields for a rule, go trigger the
real activity (Runbook Phases 1–3) and confirm the composite fires in the
dashboard.
