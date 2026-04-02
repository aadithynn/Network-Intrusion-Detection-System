#!/usr/bin/env python3
"""
dashboard.py — Live Alert Dashboard (reads nids_alerts.json)
Personal Cybersecurity Project
Author: Adithyan V

Run this in a second terminal while nids.py is running:
    python3 dashboard.py
"""

import json
import os
import time
from datetime import datetime
from collections import defaultdict

LOG_FILE  = "nids_alerts.json"
RESP_FILE = "nids_responses.log"

# ANSI colors
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
CLEAR  = "\033[2J\033[H"

def load_alerts():
    try:
        with open(LOG_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []

def load_responses():
    try:
        with open(RESP_FILE, "r") as f:
            return f.readlines()
    except Exception:
        return []

def severity_color(sev):
    return {
        "CRITICAL": RED,
        "HIGH":     YELLOW,
        "MEDIUM":   BLUE,
        "LOW":      GREEN,
    }.get(sev, RESET)

def draw_bar(count, max_count, width=20):
    if max_count == 0:
        return "─" * width
    filled = int((count / max_count) * width)
    return "█" * filled + "░" * (width - filled)

def render(alerts, responses):
    print(CLEAR, end="")

    # Header
    print(f"{BOLD}{CYAN}{'═'*65}{RESET}")
    print(f"{BOLD}{CYAN}  🛡️  NIDS LIVE DASHBOARD — Personal Cybersecurity Project{RESET}")
    print(f"{BOLD}{CYAN}{'═'*65}{RESET}")
    print(f"  Updated: {datetime.now().strftime('%H:%M:%S')}  |  Total Alerts: {len(alerts)}")
    print()

    # Summary by severity
    by_sev = defaultdict(int)
    by_type = defaultdict(int)
    by_ip   = defaultdict(int)
    for a in alerts:
        by_sev[a.get("severity","?")] += 1
        by_type[a.get("type","?")] += 1
        by_ip[a.get("src_ip","?")] += 1

    print(f"  {BOLD}── Severity Breakdown ─────────────────────────────────{RESET}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = by_sev.get(sev, 0)
        bar = draw_bar(count, max(by_sev.values()) if by_sev else 1)
        color = severity_color(sev)
        print(f"  {color}{sev:<10}{RESET} {bar} {count}")
    print()

    # Attack types
    print(f"  {BOLD}── Attack Types ───────────────────────────────────────{RESET}")
    for atype, count in sorted(by_type.items(), key=lambda x: -x[1]):
        bar = draw_bar(count, max(by_type.values()) if by_type else 1)
        print(f"  {CYAN}{atype:<22}{RESET} {bar} {count}")
    print()

    # Top attacker IPs
    print(f"  {BOLD}── Top Source IPs ─────────────────────────────────────{RESET}")
    top_ips = sorted(by_ip.items(), key=lambda x: -x[1])[:5]
    for ip, count in top_ips:
        bar = draw_bar(count, max(by_ip.values()) if by_ip else 1)
        print(f"  {RED}{ip:<20}{RESET} {bar} {count}")
    print()

    # Recent alerts
    print(f"  {BOLD}── Recent Alerts (last 5) ─────────────────────────────{RESET}")
    recent = alerts[-5:] if len(alerts) >= 5 else alerts
    for a in reversed(recent):
        color = severity_color(a.get("severity","?"))
        ts    = a.get("timestamp","?")[-8:]  # HH:MM:SS
        atype = a.get("type","?")
        src   = a.get("src_ip","?")
        print(f"  [{ts}] {color}{a.get('severity','?'):<9}{RESET} {atype:<22} {src}")
    print()

    # Recent responses
    print(f"  {BOLD}── Response Actions ───────────────────────────────────{RESET}")
    for line in responses[-4:]:
        print(f"  {GREEN}▶{RESET} {line.strip()}")

    print(f"\n  {CYAN}{'═'*65}{RESET}")
    print(f"  Refreshing every 3s... Ctrl+C to exit")


def main():
    print(f"  {CYAN}Starting NIDS Dashboard...{RESET}")
    print(f"  Waiting for nids.py to generate alerts...\n")
    try:
        while True:
            alerts    = load_alerts()
            responses = load_responses()
            render(alerts, responses)
            time.sleep(3)
    except KeyboardInterrupt:
        print(f"\n{GREEN}[✓] Dashboard closed.{RESET}")


if __name__ == "__main__":
    main()
