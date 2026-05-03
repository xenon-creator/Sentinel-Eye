# 🔐 Sentinel SOC Dashboard

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux-red?style=for-the-badge" alt="Platform">
</p>

> A real-time Security Operations Center automation dashboard built in Python with a terminal-based CLI interface.

---

## ✨ Features

- **🔍 Real-time Log Monitoring** — Tails Linux system logs (`auth.log`, `syslog`) and custom log files
- **⚡ Threat Detection**
  - Brute Force Attack Detection (5+ failed SSH attempts in 60s)
  - Port Scan Detection (10+ ports probed in 30s)
  - IP Reputation Checks via VirusTotal API
- **🗄️ SQLite Database** — Persistent storage for alerts and logs
- **📊 Rich CLI Dashboard** — Live color-coded alerts and statistics
- **📁 PCAP Analysis** — Analyze packet capture files for threats
- **📄 PDF Reports** — Generate comprehensive threat reports
- **🎨 Matrix Theme** — Cyberpunk/hacking aesthetic with multi-color terminal

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/sentinel-soc-dashboard.git
cd sentinel-soc-dashboard

# Install dependencies
pip install -r requirements.txt

# Set up environment variables (optional)
cp .env.example .env
# Edit .env and add your VirusTotal API key

# Run the dashboard
python main.py
```

---

## ⚙️ Configuration

All settings are adjustable in `config.py`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `BRUTE_FORCE_THRESHOLD` | 5 | Failed logins to trigger alert |
| `BRUTE_FORCE_WINDOW` | 60 | Time window in seconds |
| `PORT_SCAN_PORT_COUNT` | 10 | Ports to trigger scan detection |
| `PORT_SCAN_WINDOW` | 30 | Time window in seconds |
| `REFRESH_INTERVAL` | 2 | Dashboard refresh rate (seconds) |

---

## 📖 Usage

```
=========================================
          SOC DASHBOARD MENU             
=========================================
  [1] Start live monitoring
  [2] View all alerts (filterable)
  [3] Analyse a .pcap file
  [4] Export PDF report
  [5] Mark alert as resolved
  [6] Exit
```

### Menu Options

| Option | Description |
|--------|-------------|
| **1** | Start real-time log monitoring and threat detection |
| **2** | Browse and filter stored alerts by severity |
| **3** | Import and analyze `.pcap` packet capture files |
| **4** | Generate a comprehensive PDF threat report |
| **5** | Mark an alert as resolved |
| **6** | Exit the application |

---

## 🖥️ Live Dashboard Preview

```
>>> SOC DASHBOARD - LIVE MONITOR | 2026-05-03 14:30:45 <<<

>>> MONITORING ACTIVE <<< | Watching: sample.log, auth.log, syslog

>>> LIVE ALERTS <<<
┌──────────────────┬───────────────┬─────────────────┬────────────┬────────────────────────────┐
│ Time             │ Type          │ IP              │ Severity   │ Details                    │
├──────────────────┼───────────────┼─────────────────┼────────────┼────────────────────────────┤
│ 2026-05-03 14:30│ Brute Force   │ 192.168.1.100   │ CRITICAL   │ VT Score: 1/91            │
└──────────────────┴───────────────┴─────────────────┴────────────┴────────────────────────────┘

>>> STATISTICS <<<
Total Alerts Today: 42
  CRITICAL: 2
  HIGH: 8
  MEDIUM: 15
  LOW: 17
Top Attacking IPs:
  192.168.1.100: 12

>>> LIVE LOG MONITOR (scanning)
2026-05-03 14:30:45 [sample.log] Failed password for root from 192.168.1.100 port 22 ssh2
```

---

## 📁 Project Structure

```
soc_dashboard/
├── main.py              # Entry point & CLI menu
├── config.py            # Configuration & settings
├── database.py          # SQLite operations
├── parser.py            # Log parsing (auth.log, syslog)
├── detector.py         # Threat detection rules
├── threat_intel.py      # VirusTotal API integration
├── dashboard.py         # Rich CLI layout & display
├── monitor.py           # Real-time log monitoring
├── network.py           # PCAP analysis & packet capture
├── report.py            # PDF report generation
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

---

## 🔒 Security Notes

- **API Keys**: Store in `.env` file, never commit to version control
- **Permissions**: Run with appropriate privileges (root for packet capture)
- **Authorization**: Ensure you have permission before monitoring network traffic

---

## 📝 License

MIT License — See [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

<p align="center">
  <sub>Built with ❤️ for Cybersecurity Automation</sub>
</p>