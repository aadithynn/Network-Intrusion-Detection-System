# 🛡️ Python NIDS — Network Intrusion Detection System
  
**Author:** Adithyan V  
**Language:** Python 3 | **Library:** Scapy

---

## 📌 Overview

A custom-built **Network Intrusion Detection System (NIDS)** that monitors live network traffic and detects common attacks in real time. Built with Python and Scapy as part of the Personal Cybersecurity Project.

---

## 🔍 What It Detects

| Attack Type | Detection Method | Threshold |
|---|---|---|
| Port Scan | SYN packets to multiple ports | 10 unique ports / 10s |
| SYN Flood | Excessive SYN packets (DoS) | 100 SYN pkts / 10s |
| ICMP Flood | Ping flood attack | 50 ICMP pkts / 10s |
| UDP Flood | UDP-based DoS | 100 UDP pkts / 10s |
| SQL Injection | Payload signature match | `' OR`, `UNION SELECT` |
| XSS | Payload signature match | `<script>` |
| Shell Injection | Payload signature match | `/bin/sh`, `cmd.exe` |
| Path Traversal | Payload signature match | `/etc/passwd` |
| Malware Download | Payload signature match | `wget http`, `curl http` |

---

## 📁 Project Structure

```
nids/
├── nids.py          # Main NIDS engine — packet capture + detection
├── alerts.py        # Alert logger — console, .log, .json output
├── response.py      # Response engine — iptables block for CRITICAL
├── dashboard.py     # Live terminal dashboard (run in second terminal)
├── test_attacks.py  # Attack simulator for demo/testing
└── README.md
```

---

## ⚙️ Setup & Installation

### Prerequisites
```bash
# Kali Linux (recommended) or any Linux distro
sudo apt update
sudo apt install python3 python3-pip -y
pip install scapy
```

### Clone & Run
```bash
git clone https://github.com/aadithynn/aadithynn/python-nids
cd aadithynn/python-nids/nids

# Terminal 1 — Start NIDS (must be root)
sudo python3 nids.py

# Terminal 2 — Live Dashboard
python3 dashboard.py

# Terminal 3 — Run attack simulation (for demo)
sudo python3 test_attacks.py
```

---

## 🖥️ How It Works

```
Network Traffic
      │
      ▼
  Scapy Sniffer (promiscuous mode)
      │
      ▼
  Packet Parser (IP / TCP / UDP / ICMP / Raw)
      │
      ├──► Port Scan Detector    ──► Alert Logger ──► nids_alerts.log
      ├──► SYN Flood Detector    ──► Alert Logger ──► nids_alerts.json
      ├──► ICMP Flood Detector   ──► Response Engine ──► iptables BLOCK
      ├──► UDP Flood Detector    ──► Dashboard (live visualization)
      └──► Payload Signature Matcher
```

---

## 📊 Output Files

| File | Contents |
|---|---|
| `nids_alerts.log` | Human-readable alert log |
| `nids_alerts.json` | Structured JSON for analysis |
| `nids_responses.log` | Response actions taken |

---

## 🔴 Response Mechanism

| Severity | Action |
|---|---|
| CRITICAL | Auto-block source IP via `iptables -A INPUT -s <IP> -j DROP` |
| HIGH | Flag IP, log to response file |
| MEDIUM/LOW | Log only |

---

## ⚠️ Legal Disclaimer

This tool is built for **educational purposes** as a personal cybersecurity project.  
Only use on networks you own or have explicit permission to monitor.  
The attack simulator (`test_attacks.py`) should only be run in isolated lab environments.

---

## 🏷️ Tools & References

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Snort Rules Reference](https://www.snort.org/rules_explanation)
- Personal Cybersecurity Project Program
