#!/usr/bin/env python3
"""
nids.py — Network Intrusion Detection System
CodeAlpha Cybersecurity Internship — Task 4
Author: Adithyan V

Detects:
  - Port Scanning (SYN scan / connect scan)
  - SYN Flood (DoS)
  - ICMP Flood (Ping flood)
  - Suspicious Payloads (SQLi, XSS, shell keywords)
  - UDP Flood

Run as root: sudo python3 nids.py
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from collections import defaultdict
from datetime import datetime
import threading
import time
import sys

from alerts import AlertLogger
from response import ResponseEngine

# ─── Thresholds ────────────────────────────────────────────────────────────
PORTSCAN_THRESHOLD   = 5    # unique ports from one IP within window
SYN_FLOOD_THRESHOLD  = 20   # SYN packets from one IP within window
ICMP_FLOOD_THRESHOLD = 15   # ICMP packets from one IP within window
UDP_FLOOD_THRESHOLD  = 20   # UDP packets from one IP within window
TIME_WINDOW          = 10   # seconds for all counters

# Suspicious payload signatures
PAYLOAD_SIGNATURES = [
    b"' OR ",        # SQL Injection
    b"UNION SELECT", # SQL Injection
    b"<script>",     # XSS
    b"/bin/sh",      # Shell injection
    b"/etc/passwd",  # Path traversal
    b"cmd.exe",      # Windows shell
    b"wget http",    # Malware download attempt
    b"curl http",    # Malware download attempt
    b"base64",       # Encoded payload
    b"eval(",        # Code injection
]

# ─── State Tracking ────────────────────────────────────────────────────────
class TrafficTracker:
    def __init__(self):
        self.lock = threading.Lock()
        # {ip: {port: count}}
        self.port_scan_tracker  = defaultdict(set)
        # {ip: count}
        self.syn_flood_tracker  = defaultdict(int)
        self.icmp_flood_tracker = defaultdict(int)
        self.udp_flood_tracker  = defaultdict(int)
        # Stats
        self.total_packets = 0
        self.alerts_fired  = 0
        self.start_time    = datetime.now()

    def reset_counters(self):
        """Called every TIME_WINDOW seconds."""
        with self.lock:
            self.port_scan_tracker.clear()
            self.syn_flood_tracker.clear()
            self.icmp_flood_tracker.clear()
            self.udp_flood_tracker.clear()

tracker = TrafficTracker()
logger  = AlertLogger()
responder = ResponseEngine()

# ─── Detection Logic ───────────────────────────────────────────────────────

def detect_port_scan(src_ip, dst_port):
    with tracker.lock:
        tracker.port_scan_tracker[src_ip].add(dst_port)
        count = len(tracker.port_scan_tracker[src_ip])
    if count == PORTSCAN_THRESHOLD:
        alert = {
            "type":        "PORT SCAN",
            "severity":    "HIGH",
            "src_ip":      src_ip,
            "detail":      f"Scanned {count}+ unique ports",
            "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        logger.log(alert)
        responder.respond(alert)
        tracker.alerts_fired += 1


def detect_syn_flood(src_ip):
    with tracker.lock:
        tracker.syn_flood_tracker[src_ip] += 1
        count = tracker.syn_flood_tracker[src_ip]
    if count == SYN_FLOOD_THRESHOLD:
        alert = {
            "type":     "SYN FLOOD",
            "severity": "CRITICAL",
            "src_ip":   src_ip,
            "detail":   f"{count}+ SYN packets in {TIME_WINDOW}s",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        logger.log(alert)
        responder.respond(alert)
        tracker.alerts_fired += 1


def detect_icmp_flood(src_ip):
    with tracker.lock:
        tracker.icmp_flood_tracker[src_ip] += 1
        count = tracker.icmp_flood_tracker[src_ip]
    if count == ICMP_FLOOD_THRESHOLD:
        alert = {
            "type":     "ICMP FLOOD",
            "severity": "HIGH",
            "src_ip":   src_ip,
            "detail":   f"{count}+ ICMP packets in {TIME_WINDOW}s",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        logger.log(alert)
        responder.respond(alert)
        tracker.alerts_fired += 1


def detect_udp_flood(src_ip):
    with tracker.lock:
        tracker.udp_flood_tracker[src_ip] += 1
        count = tracker.udp_flood_tracker[src_ip]
    if count == UDP_FLOOD_THRESHOLD:
        alert = {
            "type":     "UDP FLOOD",
            "severity": "HIGH",
            "src_ip":   src_ip,
            "detail":   f"{count}+ UDP packets in {TIME_WINDOW}s",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        logger.log(alert)
        responder.respond(alert)
        tracker.alerts_fired += 1


def detect_suspicious_payload(src_ip, dst_ip, dst_port, payload: bytes):
    payload_upper = payload.upper()
    for sig in PAYLOAD_SIGNATURES:
        if sig.upper() in payload_upper:
            alert = {
                "type":     "SUSPICIOUS PAYLOAD",
                "severity": "CRITICAL",
                "src_ip":   src_ip,
                "detail":   f"Signature matched: {sig.decode(errors='replace')} → {dst_ip}:{dst_port}",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            logger.log(alert)
            responder.respond(alert)
            tracker.alerts_fired += 1
            break  # One alert per packet


# ─── Packet Processor ──────────────────────────────────────────────────────

def process_packet(packet):
    tracker.total_packets += 1

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # ── TCP Analysis ──
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
        flags    = packet[TCP].flags

        # SYN only (no ACK) = scan or flood
        if flags == 0x02:  # SYN
            detect_syn_flood(src_ip)
            detect_port_scan(src_ip, dst_port)

    # ── UDP Analysis ──
    elif packet.haslayer(UDP):
        detect_udp_flood(src_ip)

    # ── ICMP Analysis ──
    elif packet.haslayer(ICMP):
        detect_icmp_flood(src_ip)

    # ── Payload Analysis (all protocols) ──
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        dst_port = packet[TCP].dport if packet.haslayer(TCP) else (
                   packet[UDP].dport if packet.haslayer(UDP) else 0)
        detect_suspicious_payload(src_ip, dst_ip, dst_port, payload)


# ─── Counter Reset Thread ──────────────────────────────────────────────────

def reset_thread():
    while True:
        time.sleep(TIME_WINDOW)
        tracker.reset_counters()


# ─── Live Stats Display ────────────────────────────────────────────────────

def stats_thread():
    while True:
        time.sleep(5)
        elapsed = (datetime.now() - tracker.start_time).seconds
        print(f"\n  📊 [{datetime.now().strftime('%H:%M:%S')}] "
              f"Packets: {tracker.total_packets} | "
              f"Alerts: {tracker.alerts_fired} | "
              f"Uptime: {elapsed}s\n")


# ─── Main ──────────────────────────────────────────────────────────────────

def main():
    print("=" * 65)
    print("   🛡️  Python NIDS — Network Intrusion Detection System")
    print("        CodeAlpha Internship | Task 4 | Adithyan V")
    print("=" * 65)
    print(f"  ✅ Port Scan threshold  : {PORTSCAN_THRESHOLD} ports/{TIME_WINDOW}s")
    print(f"  ✅ SYN Flood threshold  : {SYN_FLOOD_THRESHOLD} SYN pkts/{TIME_WINDOW}s")
    print(f"  ✅ ICMP Flood threshold : {ICMP_FLOOD_THRESHOLD} ICMP pkts/{TIME_WINDOW}s")
    print(f"  ✅ UDP Flood threshold  : {UDP_FLOOD_THRESHOLD} UDP pkts/{TIME_WINDOW}s")
    print(f"  ✅ Payload signatures   : {len(PAYLOAD_SIGNATURES)} patterns loaded")
    print("=" * 65)
    print("  📡 Monitoring live traffic... Press Ctrl+C to stop.\n")

    # Start background threads
    threading.Thread(target=reset_thread, daemon=True).start()
    threading.Thread(target=stats_thread, daemon=True).start()

    try:
        from scapy.arch import get_if_list
        available = get_if_list()
        ifaces = [i for i in available if i == "lo" or i.startswith("wl") or i.startswith("en") or i.startswith("eth")]
        if not ifaces:
            ifaces = available
        print(f"  📡 Sniffing on interfaces: {ifaces}\n")
        sniff(prn=process_packet, store=False, iface=ifaces)
    except KeyboardInterrupt:
        print("\n\n[!] NIDS stopped.")
        print(f"[✓] Total packets captured : {tracker.total_packets}")
        print(f"[✓] Total alerts fired     : {tracker.alerts_fired}")
        print(f"[✓] Log saved to           : nids_alerts.log")
        sys.exit(0)


if __name__ == "__main__":
    main()
