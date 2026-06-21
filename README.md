# Network Intrusion Detection System

## 1. Project Overview

This project focuses on setting up a Network Intrusion Detection System (NIDS) using Suricata.
The main goal is to monitor network traffic, detect suspicious or malicious activities, generate alerts, and apply basic response mechanisms when threats are detected.

A Network Intrusion Detection System helps security teams discover attacks such as port scanning, brute-force attempts, suspicious DNS traffic, malware communication, and unauthorized access attempts.

---

## 2. Tools Used

* Suricata
* Linux / Kali Linux / Ubuntu
* Custom IDS rules
* EVE JSON logs
* jq for reading JSON logs
* Optional: Elastic Stack / Kibana for visualization

---

## 3. System Requirements

* Linux machine
* Root or sudo privileges
* Internet connection
* Network interface such as eth0, ens33, or wlan0
* Basic knowledge of networking and security monitoring

---

## 4. Installing Suricata

```bash
sudo apt update
sudo apt install suricata jq -y
```

Check Suricata version:

```bash
suricata --build-info
```

Check available network interfaces:

```bash
ip a
```

Example interface:

```bash
eth0
```

---

## 5. Basic Suricata Configuration

Suricata main configuration file is usually located at:

```bash
/etc/suricata/suricata.yaml
```

Open the configuration file:

```bash
sudo nano /etc/suricata/suricata.yaml
```

Make sure the HOME_NET value matches your local network.

Example:

```yaml
HOME_NET: "[192.168.1.0/24]"
```

This tells Suricata that the local network is `192.168.1.0/24`.

---

## 6. Creating Custom Detection Rules

Custom rules can be stored in:

```bash
/etc/suricata/rules/local.rules
```

Open the file:

```bash
sudo nano /etc/suricata/rules/local.rules
```

### Rule 1: Detect ICMP Ping

```bash
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Detected"; sid:1000001; rev:1;)
```

This rule generates an alert when ICMP traffic is detected.

---

### Rule 2: Detect Possible SSH Brute Force Attempt

```bash
alert tcp any any -> $HOME_NET 22 (msg:"Possible SSH Connection Attempt"; flags:S; sid:1000002; rev:1;)
```

This rule detects TCP connection attempts to SSH port 22.

---

### Rule 3: Detect HTTP Access

```bash
alert http any any -> $HOME_NET any (msg:"HTTP Traffic Detected"; sid:1000003; rev:1;)
```

This rule alerts when HTTP traffic is detected.

---

### Rule 4: Detect DNS Traffic

```bash
alert dns any any -> any any (msg:"DNS Query Detected"; sid:1000004; rev:1;)
```

This rule detects DNS queries.

---

## 7. Adding Local Rules to Suricata

Make sure Suricata loads the local rules file.

Open:

```bash
sudo nano /etc/suricata/suricata.yaml
```

Search for:

```yaml
rule-files:
```

Add:

```yaml
  - local.rules
```

---

## 8. Testing Suricata Configuration

Before running Suricata, test the configuration:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

If there are no errors, Suricata is ready to run.

---

## 9. Running Suricata for Network Monitoring

Run Suricata on a network interface:

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```

Replace `eth0` with your actual network interface.

To run it as a service:

```bash
sudo systemctl enable suricata
sudo systemctl start suricata
sudo systemctl status suricata
```

---

## 10. Viewing Alerts

Suricata stores alerts in:

```bash
/var/log/suricata/
```

View fast alerts:

```bash
sudo tail -f /var/log/suricata/fast.log
```

View EVE JSON logs:

```bash
sudo tail -f /var/log/suricata/eve.json
```

Read only alerts from EVE JSON using jq:

```bash
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
```

---

## 11. Testing the Detection Rules

### Test ICMP Detection

From another machine, run:

```bash
ping TARGET_IP
```

Expected alert:

```text
ICMP Ping Detected
```

---

### Test SSH Detection

From another machine, run:

```bash
ssh user@TARGET_IP
```

Expected alert:

```text
Possible SSH Connection Attempt
```

---

### Test HTTP Detection

Open a website or access a local web server.

Expected alert:

```text
HTTP Traffic Detected
```

---

## 12. Continuous Monitoring

Suricata can monitor traffic continuously by running as a service.

Start Suricata:

```bash
sudo systemctl start suricata
```

Enable Suricata on boot:

```bash
sudo systemctl enable suricata
```

Check logs continuously:

```bash
sudo tail -f /var/log/suricata/fast.log
```

Or:

```bash
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
```

---

## 13. Response Mechanisms

When suspicious traffic is detected, the following response actions can be applied:

### 1. Block Suspicious IP Address

Example using iptables:

```bash
sudo iptables -A INPUT -s ATTACKER_IP -j DROP
```

### 2. Block Suspicious SSH Attempts

```bash
sudo iptables -A INPUT -p tcp --dport 22 -s ATTACKER_IP -j DROP
```

### 3. Save Alerts for Investigation

```bash
sudo cp /var/log/suricata/fast.log ~/suricata_alerts_backup.log
```

### 4. Restart Suricata After Rule Updates

```bash
sudo systemctl restart suricata
```

### 5. Notify Administrator

A simple alert notification script can be created to watch logs and notify the admin when an alert appears.

Example:

```bash
#!/bin/bash

tail -f /var/log/suricata/fast.log | while read line
do
    echo "Security Alert: $line"
done
```

Save it as:

```bash
alert_monitor.sh
```

Make it executable:

```bash
chmod +x alert_monitor.sh
```

Run it:

```bash
./alert_monitor.sh
```

---

## 14. Optional Visualization

For better analysis, Suricata logs can be visualized using:

* Elastic Stack
* Kibana
* Grafana
* Security Onion

Suricata EVE JSON logs can be sent to Elastic Stack, then visualized in Kibana dashboards.

Possible dashboard charts:

* Number of alerts per day
* Top attacking IP addresses
* Most targeted ports
* Alert severity levels
* Protocol distribution

---

## 15. Example Alert Output

Example alert from `fast.log`:

```text
[**] [1:1000001:1] ICMP Ping Detected [**]
[Classification: Potentially Bad Traffic] [Priority: 2]
06/21/2026-14:20:01 192.168.1.10 -> 192.168.1.5
ICMP TTL:64 TOS:0x0 ID:12345 IpLen:20 DgmLen:84
```

This alert shows that an ICMP ping was detected from `192.168.1.10` to `192.168.1.5`.

---

## 16. Findings

During testing, Suricata successfully detected suspicious network activities such as:

* ICMP ping traffic
* SSH connection attempts
* HTTP traffic
* DNS queries
* Possible scanning behavior

The alerts were stored in Suricata log files and could be reviewed using `fast.log` or `eve.json`.

---

