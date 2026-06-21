#!/usr/bin/env python3

import argparse
import json
import time
import os
import subprocess
from collections import defaultdict, deque
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw


# =========================
# Configuration
# =========================

ALERT_LOG_FILE = "alerts.log"
ALERT_JSON_FILE = "alerts.jsonl"

# Port scan settings
SCAN_TIME_WINDOW = 10      # seconds
SCAN_PORT_THRESHOLD = 10   # number of different ports

# SSH brute-force style detection
SSH_TIME_WINDOW = 20       # seconds
SSH_ATTEMPT_THRESHOLD = 8  # SYN attempts

# Dangerous / suspicious ports
SUSPICIOUS_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    445: "SMB",
    3389: "RDP",
    5900: "VNC"
}

# Optional blocking
ENABLE_AUTO_BLOCK = False


# =========================
# Tracking Data
# =========================

port_scan_tracker = defaultdict(lambda: deque())
ssh_tracker = defaultdict(lambda: deque())
blocked_ips = set()


# =========================
# Helper Functions
# =========================

def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def save_alert(alert):
    """
    Save alert in text and JSONL format.
    """

    alert_text = (
        f"[{alert['time']}] "
        f"[{alert['severity']}] "
        f"{alert['alert_type']} | "
        f"SRC={alert.get('src_ip', 'N/A')} -> DST={alert.get('dst_ip', 'N/A')} | "
        f"{alert['message']}"
    )

    print(alert_text)

    with open(ALERT_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(alert_text + "\n")

    with open(ALERT_JSON_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert) + "\n")


def create_alert(alert_type, severity, message, src_ip=None, dst_ip=None, src_port=None, dst_port=None, protocol=None):
    alert = {
        "time": current_time(),
        "alert_type": alert_type,
        "severity": severity,
        "message": message,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol
    }

    save_alert(alert)

    if ENABLE_AUTO_BLOCK and severity in ["HIGH", "CRITICAL"] and src_ip:
        block_ip(src_ip)


def block_ip(ip):
    """
    Block suspicious IP using iptables.
    Disabled by default.
    """

    if ip in blocked_ips:
        return

    try:
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )

        blocked_ips.add(ip)

        create_alert(
            alert_type="RESPONSE_ACTION",
            severity="HIGH",
            message=f"Blocked suspicious IP using iptables: {ip}",
            src_ip=ip
        )

    except Exception as e:
        create_alert(
            alert_type="RESPONSE_ERROR",
            severity="MEDIUM",
            message=f"Failed to block IP {ip}: {e}",
            src_ip=ip
        )


def clean_old_events(event_queue, time_window):
    """
    Remove old events from deque.
    """

    now = time.time()

    while event_queue and now - event_queue[0][0] > time_window:
        event_queue.popleft()


# =========================
# Detection Rules
# =========================

def detect_icmp(packet):
    if packet.haslayer(ICMP) and packet.haslayer(IP):
        ip = packet[IP]

        create_alert(
            alert_type="ICMP_DETECTED",
            severity="LOW",
            message="ICMP packet detected, possible ping or network probing.",
            src_ip=ip.src,
            dst_ip=ip.dst,
            protocol="ICMP"
        )


def detect_dns(packet):
    if packet.haslayer(DNS) and packet.haslayer(IP):
        ip = packet[IP]

        query_name = "Unknown"

        try:
            if packet[DNS].qd:
                query_name = packet[DNS].qd.qname.decode(errors="ignore")
        except Exception:
            pass

        create_alert(
            alert_type="DNS_QUERY",
            severity="LOW",
            message=f"DNS query detected: {query_name}",
            src_ip=ip.src,
            dst_ip=ip.dst,
            protocol="DNS"
        )


def detect_http(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        tcp = packet[TCP]
        ip = packet[IP]

        if tcp.dport == 80 or tcp.sport == 80:
            msg = "HTTP traffic detected."

            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode(errors="ignore")

                if "Host:" in payload:
                    try:
                        host_line = [line for line in payload.split("\r\n") if line.startswith("Host:")]
                        if host_line:
                            msg += f" Host: {host_line[0].replace('Host:', '').strip()}"
                    except Exception:
                        pass

            create_alert(
                alert_type="HTTP_TRAFFIC",
                severity="LOW",
                message=msg,
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=tcp.sport,
                dst_port=tcp.dport,
                protocol="HTTP"
            )


def detect_suspicious_ports(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        ip = packet[IP]
        tcp = packet[TCP]

        if tcp.dport in SUSPICIOUS_PORTS:
            service = SUSPICIOUS_PORTS[tcp.dport]

            create_alert(
                alert_type="SUSPICIOUS_PORT_ACCESS",
                severity="MEDIUM",
                message=f"Connection attempt to suspicious service: {service} on port {tcp.dport}",
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=tcp.sport,
                dst_port=tcp.dport,
                protocol="TCP"
            )


def detect_ssh_bruteforce(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        ip = packet[IP]
        tcp = packet[TCP]

        # SYN packet to SSH port
        if tcp.dport == 22 and tcp.flags == "S":
            key = ip.src
            ssh_tracker[key].append((time.time(), tcp.dport))

            clean_old_events(ssh_tracker[key], SSH_TIME_WINDOW)

            if len(ssh_tracker[key]) >= SSH_ATTEMPT_THRESHOLD:
                create_alert(
                    alert_type="POSSIBLE_SSH_BRUTE_FORCE",
                    severity="HIGH",
                    message=f"Multiple SSH connection attempts detected from {ip.src}",
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_port=tcp.sport,
                    dst_port=tcp.dport,
                    protocol="TCP"
                )

                ssh_tracker[key].clear()


def detect_port_scan(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        ip = packet[IP]
        tcp = packet[TCP]

        # Detect SYN packets
        if tcp.flags == "S":
            key = ip.src
            port_scan_tracker[key].append((time.time(), tcp.dport))

            clean_old_events(port_scan_tracker[key], SCAN_TIME_WINDOW)

            unique_ports = set(port for _, port in port_scan_tracker[key])

            if len(unique_ports) >= SCAN_PORT_THRESHOLD:
                create_alert(
                    alert_type="POSSIBLE_PORT_SCAN",
                    severity="HIGH",
                    message=f"Possible port scan detected. {ip.src} contacted {len(unique_ports)} ports quickly.",
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_port=tcp.sport,
                    dst_port=tcp.dport,
                    protocol="TCP"
                )

                port_scan_tracker[key].clear()


def detect_large_packet(packet):
    if packet.haslayer(IP):
        ip = packet[IP]
        packet_size = len(packet)

        if packet_size > 1500:
            create_alert(
                alert_type="LARGE_PACKET",
                severity="MEDIUM",
                message=f"Large packet detected. Size: {packet_size} bytes",
                src_ip=ip.src,
                dst_ip=ip.dst,
                protocol="IP"
            )


# =========================
# Packet Processor
# =========================

def process_packet(packet):
    try:
        detect_icmp(packet)
        detect_dns(packet)
        detect_http(packet)
        detect_suspicious_ports(packet)
        detect_ssh_bruteforce(packet)
        detect_port_scan(packet)
        detect_large_packet(packet)

    except KeyboardInterrupt:
        raise

    except Exception as e:
        create_alert(
            alert_type="PROCESSING_ERROR",
            severity="LOW",
            message=f"Error while processing packet: {e}"
        )


# =========================
# Main
# =========================

def banner():
    print("=" * 60)
    print("        Python Network Intrusion Detection System")
    print("=" * 60)
    print("Detects:")
    print("- ICMP Ping")
    print("- DNS Queries")
    print("- HTTP Traffic")
    print("- Suspicious Ports")
    print("- Possible SSH Brute Force")
    print("- Possible Port Scan")
    print("- Large Packets")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Simple Python Network Intrusion Detection System")

    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        help="Network interface to monitor, example: eth0, wlan0, ens33"
    )

    parser.add_argument(
        "--auto-block",
        action="store_true",
        help="Enable automatic blocking using iptables for HIGH/CRITICAL alerts"
    )

    args = parser.parse_args()

    global ENABLE_AUTO_BLOCK
    ENABLE_AUTO_BLOCK = args.auto_block

    if os.geteuid() != 0:
        print("[!] Please run this tool as root/admin.")
        print("Example:")
        print(f"sudo python3 {os.path.basename(__file__)} -i {args.interface}")
        return

    banner()

    print(f"[+] Monitoring interface: {args.interface}")
    print(f"[+] Alerts text log: {ALERT_LOG_FILE}")
    print(f"[+] Alerts JSON log: {ALERT_JSON_FILE}")

    if ENABLE_AUTO_BLOCK:
        print("[!] Auto-block is ENABLED.")
    else:
        print("[+] Auto-block is DISABLED by default.")

    print("[+] Starting packet capture...")
    print("[+] Press CTRL + C to stop.")

    try:
        sniff(
            iface=args.interface,
            prn=process_packet,
            store=False
        )

    except KeyboardInterrupt:
        print("\n[+] Stopping NIDS...")
        print("[+] Done.")

    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    main()
