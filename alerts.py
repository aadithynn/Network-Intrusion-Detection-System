#!/usr/bin/env python3
"""
alerts.py — Alert Logging Module
Personal Cybersecurity Project
Author: Adithyan V
"""

import json
import os
from datetime import datetime

# Severity color codes (ANSI)
COLORS = {
    "CRITICAL": "\033[91m",  # Bright Red
    "HIGH":     "\033[93m",  # Yellow
    "MEDIUM":   "\033[94m",  # Blue
    "LOW":      "\033[92m",  # Green
    "RESET":    "\033[0m",
}

LOG_FILE = "nids_alerts.log"
JSON_LOG = "nids_alerts.json"

class AlertLogger:
    def __init__(self):
        self.alerts = []
        # Create/clear log files
        open(LOG_FILE, "w").close()
        open(JSON_LOG, "w").close()

    def log(self, alert: dict):
        """Log alert to console, text file, and JSON file."""
        self.alerts.append(alert)

        sev   = alert.get("severity", "MEDIUM")
        atype = alert.get("type", "UNKNOWN")
        src   = alert.get("src_ip", "?")
        detail= alert.get("detail", "")
        ts    = alert.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        color = COLORS.get(sev, "")
        reset = COLORS["RESET"]

        # ── Console Output ──
        print(f"\n  {color}{'━'*55}{reset}")
        print(f"  {color}⚠  ALERT — {atype}{reset}")
        print(f"  {'━'*55}")
        print(f"  Severity  : {color}{sev}{reset}")
        print(f"  Source IP : {src}")
        print(f"  Detail    : {detail}")
        print(f"  Time      : {ts}")
        print(f"  {color}{'━'*55}{reset}\n")

        # ── Text Log ──
        with open(LOG_FILE, "a") as f:
            f.write(f"[{ts}] [{sev}] {atype} | SRC: {src} | {detail}\n")

        # ── JSON Log ──
        try:
            with open(JSON_LOG, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            data = []

        data.append(alert)
        with open(JSON_LOG, "w") as f:
            json.dump(data, f, indent=2)

    def get_alerts(self):
        return self.alerts

    def summary(self):
        total = len(self.alerts)
        by_sev = {}
        for a in self.alerts:
            s = a.get("severity", "UNKNOWN")
            by_sev[s] = by_sev.get(s, 0) + 1
        return {"total": total, "by_severity": by_sev}
