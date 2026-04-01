#!/usr/bin/env python3
"""
test_attacks.py — Attack Simulator for NIDS Demo
CodeAlpha Internship — Task 4
Author: Adithyan V

Run this in a second terminal to simulate attacks while nids.py is running.
Requires root: sudo python3 test_attacks.py

WARNING: Run only in your own local lab environment.
"""

from scapy.all import IP, TCP, UDP, ICMP, Raw, send
import time

TARGET = "127.0.0.1"   # Loopback — safe for local testing
FAKE_ATTACKER = "10.0.0.99"

print("=" * 55)
print("  🧪 NIDS Attack Simulator — CodeAlpha Task 4")
print("=" * 55)
print(f"  Target   : {TARGET}")
print(f"  Attacker : {FAKE_ATTACKER} (spoofed)")
print()

# ── 1. Port Scan Simulation ──────────────────────────────────
print("[*] Simulating Port Scan (15 SYN packets to different ports)...")
for port in range(80, 95):
    pkt = IP(src=FAKE_ATTACKER, dst=TARGET) / TCP(dport=port, flags="S")
    send(pkt, verbose=0)
print("[✓] Port scan sent\n")
time.sleep(2)

# ── 2. SYN Flood Simulation ──────────────────────────────────
print("[*] Simulating SYN Flood (110 SYN packets to port 80)...")
for i in range(110):
    pkt = IP(src=FAKE_ATTACKER, dst=TARGET) / TCP(dport=80, flags="S")
    send(pkt, verbose=0)
print("[✓] SYN flood sent\n")
time.sleep(2)

# ── 3. ICMP Flood Simulation ─────────────────────────────────
print("[*] Simulating ICMP Flood (55 ping packets)...")
for i in range(55):
    pkt = IP(src=FAKE_ATTACKER, dst=TARGET) / ICMP()
    send(pkt, verbose=0)
print("[✓] ICMP flood sent\n")
time.sleep(2)

# ── 4. Suspicious Payload (SQL Injection) ────────────────────
print("[*] Simulating SQL Injection payload...")
payload = b"GET /login?user=' OR '1'='1 HTTP/1.1\r\nHost: target.com\r\n\r\n"
pkt = IP(src=FAKE_ATTACKER, dst=TARGET) / TCP(dport=80, flags="PA") / Raw(load=payload)
send(pkt, verbose=0)
print("[✓] SQLi payload sent\n")
time.sleep(1)

# ── 5. Suspicious Payload (Shell Injection) ──────────────────
print("[*] Simulating Shell Injection payload...")
payload = b"POST /ping HTTP/1.1\r\nHost: target.com\r\n\r\nhost=127.0.0.1;/bin/sh"
pkt = IP(src=FAKE_ATTACKER, dst=TARGET) / TCP(dport=80, flags="PA") / Raw(load=payload)
send(pkt, verbose=0)
print("[✓] Shell injection sent\n")
time.sleep(1)

# ── 6. UDP Flood ─────────────────────────────────────────────
print("[*] Simulating UDP Flood (105 UDP packets)...")
for i in range(105):
    pkt = IP(src=FAKE_ATTACKER, dst=TARGET) / UDP(dport=53)
    send(pkt, verbose=0)
print("[✓] UDP flood sent\n")

print("=" * 55)
print("  ✅ All attack simulations complete!")
print("  Check nids.py terminal for alerts.")
print("  Check dashboard.py terminal for visualization.")
print("=" * 55)
