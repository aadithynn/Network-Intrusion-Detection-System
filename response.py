#!/usr/bin/env python3
"""
response.py — Automated Response Engine
CodeAlpha Internship — Task 4
Author: Adithyan V

Response actions based on alert severity:
  CRITICAL → Block IP via iptables + log
  HIGH     → Log + rate limit warning
  MEDIUM   → Log only
"""

import subprocess
import os
from datetime import datetime

BLOCKED_IPS = set()
RESPONSE_LOG = "nids_responses.log"


class ResponseEngine:
    def __init__(self):
        self.blocked = BLOCKED_IPS
        open(RESPONSE_LOG, "w").close()

    def respond(self, alert: dict):
        severity = alert.get("severity", "LOW")
        src_ip   = alert.get("src_ip", "")
        atype    = alert.get("type", "")

        if severity == "CRITICAL":
            self._block_ip(src_ip, atype)
        elif severity == "HIGH":
            self._warn(src_ip, atype)
        else:
            self._log_response(src_ip, atype, "Logged only")

    def _block_ip(self, ip: str, reason: str):
        """Block IP using iptables (requires root)."""
        if ip in self.blocked:
            return  # Already blocked

        self.blocked.add(ip)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Attempt iptables block
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True
            )
            action = f"BLOCKED via iptables"
            print(f"\n  🔴 RESPONSE: IP {ip} BLOCKED via iptables (Reason: {reason})")
        except subprocess.CalledProcessError:
            action = "BLOCK FAILED (iptables error — run as root)"
            print(f"\n  ⚠️  RESPONSE: Could not block {ip} — run as root for iptables")
        except FileNotFoundError:
            action = "BLOCK SIMULATED (iptables not found)"
            print(f"\n  ⚠️  RESPONSE: iptables not available — block simulated for {ip}")

        self._log_response(ip, reason, action, ts)

    def _warn(self, ip: str, reason: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n  🟡 RESPONSE: High severity from {ip} ({reason}) — logged & flagged")
        self._log_response(ip, reason, "FLAGGED — monitor closely", ts)

    def _log_response(self, ip: str, reason: str, action: str, ts: str = None):
        if ts is None:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(RESPONSE_LOG, "a") as f:
            f.write(f"[{ts}] IP: {ip} | Reason: {reason} | Action: {action}\n")

    def unblock_all(self):
        """Unblock all IPs (cleanup on exit)."""
        for ip in self.blocked:
            try:
                subprocess.run(
                    ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True
                )
            except Exception:
                pass
        self.blocked.clear()
        print("[✓] All blocked IPs removed from iptables.")
