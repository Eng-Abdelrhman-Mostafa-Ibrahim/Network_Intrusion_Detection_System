# Network Intrusion Detection System Using Python

## Project Overview

This project is a simple **Network Intrusion Detection System (NIDS)** built using Python.

The tool monitors live network traffic and detects suspicious activities such as:

* ICMP ping requests
* DNS queries
* HTTP traffic
* Suspicious port access
* Possible SSH brute-force attempts
* Possible port scanning
* Large network packets

The main goal of this project is to understand how intrusion detection systems work and how network traffic can be analyzed to detect possible attacks or suspicious behavior.

---

## What is a Network Intrusion Detection System?

A **Network Intrusion Detection System** is a security system that monitors network traffic and looks for suspicious or malicious activity.

It does not prevent attacks by default.
Instead, it detects the activity and generates alerts so the security team or administrator can investigate.

In this project, the NIDS tool was created using Python and the `scapy` library.

---

## Tools and Technologies Used

* Python 3
* Scapy
* Linux / Kali Linux / Ubuntu
* iptables
* JSON logs
* Command-line interface

---

## Project Files

```text
Network-Intrusion-Detection-System/
│
├── nids_tool.py
├── network_intrusion_detection_system.md
├── alerts.log
└── alerts.jsonl
```

### File Description

| File                                    | Description                                                              |
| --------------------------------------- | ------------------------------------------------------------------------ |
| `nids_tool.py`                          | Main Python tool for monitoring and detecting suspicious network traffic |
| `network_intrusion_detection_system.md` | Project documentation                                                    |
| `alerts.log`                            | Text file that stores readable alerts                                    |
| `alerts.jsonl`                          | JSON Lines file that stores alerts in structured format                  |

---

## Requirements

Before running the tool, make sure Python 3 is installed.

Check Python version:

```bash
python3 --version
```

Install Scapy:

```bash
pip install scapy
```

On some Linux systems, you may need to use:

```bash
sudo apt update
sudo apt install python3-pip -y
pip3 install scapy
```

---

## How to Find Your Network Interface

Before running the tool, you need to know the name of your network interface.

Use this command:

```bash
ip a
```

Example interfaces:

```text
eth0
wlan0
ens33
enp0s3
```

If you are using Ethernet, the interface may be `eth0` or `ens33`.

If you are using Wi-Fi, the interface may be `wlan0`.

---

## How to Run the Tool

The tool needs root privileges because it captures live network packets.

Basic command:

```bash
sudo python3 nids_tool.py -i eth0
```

Replace `eth0` with your actual network interface.

Example for Wi-Fi:

```bash
sudo python3 nids_tool.py -i wlan0
```

Example for VMware or VirtualBox:

```bash
sudo python3 nids_tool.py -i ens33
```

---

## Running the Tool with Auto Block

The tool supports an optional response mechanism using `iptables`.

To enable automatic blocking of suspicious IP addresses:

```bash
sudo python3 nids_tool.py -i eth0 --auto-block
```

This option blocks IP addresses that generate high-severity alerts.

> Note: Auto-block should be used carefully because it can block legitimate devices if false alerts happen.

---

## Tool Features

### 1. ICMP Detection

The tool detects ICMP packets such as ping requests.

Example suspicious activity:

```bash
ping TARGET_IP
```

Expected alert:

```text
ICMP_DETECTED
```

This can indicate network probing or simple connectivity testing.

---

### 2. DNS Query Detection

The tool detects DNS queries made by devices on the network.

Example alert:

```text
DNS_QUERY
```

This helps identify domain requests and possible suspicious DNS activity.

---

### 3. HTTP Traffic Detection

The tool detects HTTP traffic on port 80.

Expected alert:

```text
HTTP_TRAFFIC
```

This helps monitor unencrypted web traffic.

---

### 4. Suspicious Port Detection

The tool monitors access to commonly targeted ports.

Examples:

| Port | Service |
| ---- | ------- |
| 21   | FTP     |
| 22   | SSH     |
| 23   | Telnet  |
| 445  | SMB     |
| 3389 | RDP     |
| 5900 | VNC     |

Expected alert:

```text
SUSPICIOUS_PORT_ACCESS
```

---

### 5. SSH Brute-Force Detection

The tool detects repeated SSH connection attempts.

If one IP sends many SSH SYN packets in a short time, the tool generates this alert:

```text
POSSIBLE_SSH_BRUTE_FORCE
```

This may indicate a brute-force attack attempt against SSH.

---

### 6. Port Scan Detection

The tool detects when one IP tries to connect to many different ports quickly.

Expected alert:

```text
POSSIBLE_PORT_SCAN
```

This may indicate scanning activity before an attack.

---

### 7. Large Packet Detection

The tool detects packets larger than normal size.

Expected alert:

```text
LARGE_PACKET
```

This can help identify unusual traffic patterns.

---

## Alert Output

When the tool detects suspicious activity, it prints the alert in the terminal and saves it in log files.

Example terminal output:

```text
[2026-06-21 19:10:44] [LOW] ICMP_DETECTED | SRC=192.168.1.8 -> DST=192.168.1.5 | ICMP packet detected, possible ping or network probing.
```

---

## Log Files

The tool creates two log files:

```text
alerts.log
alerts.jsonl
```

### alerts.log

This file stores alerts in a simple readable text format.

Example:

```text
[2026-06-21 19:10:44] [LOW] ICMP_DETECTED | SRC=192.168.1.8 -> DST=192.168.1.5 | ICMP packet detected, possible ping or network probing.
```

### alerts.jsonl

This file stores alerts in JSON format.

Example:

```json
{"time": "2026-06-21 19:10:44", "alert_type": "ICMP_DETECTED", "severity": "LOW", "message": "ICMP packet detected, possible ping or network probing.", "src_ip": "192.168.1.8", "dst_ip": "192.168.1.5", "src_port": null, "dst_port": null, "protocol": "ICMP"}
```

JSON logs are useful for dashboards, graphs, and future analysis.

---

## Testing the Tool

### Test 1: ICMP Ping Detection

From another device on the same network:

```bash
ping TARGET_IP
```

Expected alert:

```text
ICMP_DETECTED
```

---

### Test 2: SSH Detection

From another machine:

```bash
ssh user@TARGET_IP
```

Expected alert:

```text
SUSPICIOUS_PORT_ACCESS
```

or:

```text
POSSIBLE_SSH_BRUTE_FORCE
```

if repeated many times.

---

### Test 3: HTTP Detection

Open any website that uses HTTP or access a local HTTP server.

Expected alert:

```text
HTTP_TRAFFIC
```

---

### Test 4: Port Scan Detection

In a lab environment only, scan your own machine:

```bash
nmap TARGET_IP
```

Expected alert:

```text
POSSIBLE_PORT_SCAN
```

This test should only be done on devices you own or have permission to test.

---

## Response Mechanism

The tool includes a simple response mechanism.

When `--auto-block` is enabled, the tool can block suspicious IP addresses using `iptables`.

Example:

```bash
sudo python3 nids_tool.py -i eth0 --auto-block
```

Blocking command used by the tool:

```bash
iptables -A INPUT -s ATTACKER_IP -j DROP
```

This helps reduce the risk from repeated suspicious traffic.

---

## How the Tool Works

The tool works in the following steps:

1. Starts packet sniffing on the selected network interface.
2. Reads each packet.
3. Checks the packet against detection rules.
4. Creates alerts for suspicious behavior.
5. Saves alerts in text and JSON format.
6. Optionally blocks suspicious IP addresses.

---

## Detection Logic

| Detection Type   | Method Used                                         |
| ---------------- | --------------------------------------------------- |
| ICMP detection   | Checks for ICMP packets                             |
| DNS detection    | Checks for DNS layer                                |
| HTTP detection   | Checks TCP traffic on port 80                       |
| Suspicious ports | Checks destination ports like 22, 23, 445, 3389     |
| SSH brute force  | Counts repeated SSH SYN packets                     |
| Port scan        | Counts unique ports contacted by the same source IP |
| Large packet     | Checks packet size                                  |

---

## Example Use Case

A user starts the tool:

```bash
sudo python3 nids_tool.py -i eth0
```

Another device sends ping requests:

```bash
ping 192.168.1.5
```

The tool detects the ICMP traffic and creates an alert:

```text
ICMP_DETECTED
```

If an attacker tries to connect to many ports quickly, the tool detects it as:

```text
POSSIBLE_PORT_SCAN
```

If auto-block is enabled, the tool can block the suspicious source IP.

---

## Optional Dashboard Idea

The JSON log file `alerts.jsonl` can be used later with tools like:

* Kibana
* Grafana
* Elastic Stack
* Python charts
* Power BI

Possible dashboard graphs:

* Number of alerts per type
* Top source IP addresses
* Most targeted ports
* Alerts over time
* Severity levels

---

## Security Notes

This tool is for educational and defensive purposes only.

Do not use it to monitor networks without permission.

Only test scanning or suspicious traffic detection inside your own lab environment or on systems you are allowed to test.

---

## Problems Faced

Some common issues while running the tool:

### Permission Error

Problem:

```text
Please run this tool as root/admin.
```

Solution:

```bash
sudo python3 nids_tool.py -i eth0
```

---

### Wrong Interface

Problem:

```text
Error: Interface not found
```

Solution:

Check your interface name:

```bash
ip a
```

Then run the tool with the correct interface.

---

### Scapy Not Installed

Problem:

```text
ModuleNotFoundError: No module named 'scapy'
```

Solution:

```bash
pip install scapy
```

or:

```bash
pip3 install scapy
```

---

* How to apply basic response actions using iptables
* How logs can be used for future dashboards and analysis
