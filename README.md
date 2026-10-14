<div align="center">

# 🛡️ NetWatch

### Real-Time Local Network Monitoring & Threat Detection Dashboard

NetWatch captures local network traffic, analyzes packet metadata, detects suspicious activity, and presents the results through a modern web dashboard.

<br>

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.1-000000?style=for-the-badge&logo=flask&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.7-1E90FF?style=for-the-badge)
![Socket.IO](https://img.shields.io/badge/Socket.IO-Real--Time-010101?style=for-the-badge&logo=socketdotio&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
[![Tests](https://img.shields.io/github/actions/workflow/status/betulaltunyuva/Netwatch/tests.yml?branch=main&style=for-the-badge&label=Tests&logo=githubactions&logoColor=white)](https://github.com/betulaltunyuva/Netwatch/actions/workflows/tests.yml)

</div>

---

## 📖 About

NetWatch is a local network monitoring and lightweight threat detection application developed with Python, Flask, Scapy, Socket.IO, and SQLite.

The application captures IPv4, IPv6, and ARP packets visible to the computer, processes their metadata, stores historical records, and updates the dashboard in real time.

NetWatch also provides traffic history, advanced packet search, local device discovery, security alerts, data export, and automatic data retention.

If live packet capture cannot be started, the application detects the problem and switches to sample data mode so that the dashboard can still be explored.

> NetWatch is designed for educational, cybersecurity learning, and portfolio purposes. It is not intended to replace a production-grade IDS or SIEM platform.

---

## 📌 Contents

- [Screenshots](#-screenshots)
- [Key Features](#-key-features)
- [Application Pages](#-application-pages)
- [How It Works](#-how-it-works)
- [Detection Rules](#-detection-rules)
- [Data Management](#-data-management)
- [Export Options](#-export-options)
- [Technologies](#-technologies)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Running Tests](#-running-tests)
- [Security and Privacy](#-security-and-privacy)
- [Limitations](#-limitations)
- [Future Improvements](#-future-improvements)
- [Author](#-author)

---

## 📸 Screenshots

<table>
  <tr>
    <td width="50%"><img src="images/netwatch1.png" width="410" alt="Live Dashboard with total, TCP, UDP and ICMP packet counts, live data badge and alerts"></td>
    <td width="50%"><img src="images/netwatch2.png" width="410" alt="Traffic History with time range buttons, protocol totals, transferred data and traffic-over-time chart"></td>
  </tr>
  <tr>
    <td align="center"><b>📡 Live Dashboard</b> — real-time packet counts, data mode and security alerts</td>
    <td align="center"><b>🕒 Traffic History</b> — per-minute traffic chart and protocol totals</td>
  </tr>
  <tr>
    <td colspan="2" align="center"><img src="images/netwatch3.png" width="410" alt="Data Export page with packet CSV, alert CSV, PCAP download and database cleanup cards"></td>
  </tr>
  <tr>
    <td colspan="2" align="center"><b>📤 Data Export</b> — CSV and PCAP downloads and database cleanup</td>
  </tr>
</table>

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 📡 Live Packet Capture | Captures IPv4, IPv6, and ARP packets with Scapy on a selectable network interface |
| ⚡ Real-Time Dashboard | Sends live traffic information every second using Flask-SocketIO |
| 📊 Protocol Statistics | Displays TCP, UDP, ICMP / ICMPv6, and total packet counts |
| 🕒 Traffic History | Analyzes traffic from the last 15 minutes, 1 hour, 6 hours, or 24 hours |
| 🔍 Advanced Packet Search | Filters stored packets by IP address, protocol, port, and time |
| 🖥️ Device Discovery | Tracks local devices, their IP and MAC addresses, and packet counts |
| 🚨 Threat Detection | Detects port scans, SYN floods, ICMP floods, high DNS traffic, and ARP spoofing |
| 🎛️ Configurable Thresholds | Detection limits can be changed with environment variables |
| 💾 SQLite Storage | Stores packet metadata, alerts, and device information |
| 📤 CSV Export | Exports packet records and security alerts |
| 📦 PCAP Export | Exports recent raw packets for Wireshark analysis |
| 🧹 Data Retention | Deletes old records automatically every hour or manually from the Export page |
| 🩺 Capture Health Check | Detects capture failures and skips malformed packets without stopping |
| 🔐 Local Security | Host validation, CSRF protection, and Content-Security-Policy |
| 🧪 Automated Tests | 23 tests, run automatically with GitHub Actions |
| 📴 Offline Assets | Uses local Chart.js and Socket.IO files without CDN dependency |
| 🧾 Rotating Logs | Prevents unlimited log file growth |
| 🧪 Sample Mode | Provides demonstration data when live capture is unavailable |

---

## 🧭 Application Pages

| Page | Route | Purpose |
|---|---|---|
| Live Dashboard | `/` | Displays live statistics, alerts, top IPs, ports, and recent packets |
| Traffic History | `/history` | Presents historical traffic per minute (empty minutes are shown as zero) |
| Packet Search | `/search` | Searches stored packet records using advanced filters |
| Network Devices | `/devices` | Lists local devices, their status, and packet counts |
| Data Export | `/exports` | Downloads CSV and PCAP files and manages data retention |

---

## ⚙️ How It Works

1. Scapy captures packets visible to the selected network interface.
2. `NetworkMonitor` extracts packet metadata from IPv4, IPv6, and ARP packets.
3. Live TCP, UDP, ICMP, and total packet statistics are calculated.
4. `ThreatDetector` checks traffic against rule-based detection thresholds.
5. A background loop writes packets and alerts to SQLite in batches once per second, so slow disk access never blocks packet capture.
6. Flask provides web pages and JSON API endpoints.
7. Flask-SocketIO sends live updates to the dashboard.
8. Chart.js displays historical traffic information.
9. Export tools prepare packet CSV, alert CSV, and PCAP files.
10. Records older than the retention period are cleaned up automatically every hour.

---

## 🚨 Detection Rules

NetWatch uses lightweight rule-based threat detection.

| Detection | Rule | Severity |
|---|---|---|
| Port Scan | 15 different destination ports within 10 seconds | High |
| SYN Flood | 100 SYN packets within 5 seconds | Critical |
| ICMP Flood | 50 ICMP packets within 10 seconds | High |
| High DNS Traffic | 100 DNS packets within 10 seconds | Medium |
| ARP Spoofing | The same IP address is announced with a different MAC address within 5 minutes | High |
| Alert Cooldown | Prevents the same alert from repeating for 30 seconds | — |

Both IPv4 and IPv6 traffic is analyzed (ICMPv6 is counted as ICMP). Longer gaps between MAC changes are treated as normal DHCP address reassignment, not ARP spoofing.

### Custom Thresholds

Detection thresholds can be changed without editing the code by setting environment variables named `NETWATCH_<SETTING>`:

```powershell
$env:NETWATCH_PORT_SCAN_PORT_LIMIT = "25"
$env:NETWATCH_SYN_FLOOD_PACKET_LIMIT = "200"
python app.py
```

| Setting | Default | Unit |
|---|---|---|
| `PORT_SCAN_WINDOW` | 10 | seconds |
| `PORT_SCAN_PORT_LIMIT` | 15 | ports |
| `SYN_FLOOD_WINDOW` | 5 | seconds |
| `SYN_FLOOD_PACKET_LIMIT` | 100 | packets |
| `ICMP_FLOOD_WINDOW` | 10 | seconds |
| `ICMP_FLOOD_PACKET_LIMIT` | 50 | packets |
| `DNS_TRAFFIC_WINDOW` | 10 | seconds |
| `DNS_PACKET_LIMIT` | 100 | packets |
| `ALERT_COOLDOWN` | 30 | seconds |
| `ARP_SPOOF_WINDOW` | 300 | seconds |

Values must be positive integers. Invalid values are ignored and written to the log.

Per-IP detection state is cleaned up every 60 seconds, so memory usage stays stable during long monitoring sessions.

---

## 💾 Data Management

NetWatch stores the following packet metadata:

- Capture date and time
- Source and destination IP addresses (IPv4 and IPv6)
- Source and destination ports
- Network protocol
- Packet length

It also stores:

- Security alert type, severity, message, and source IP
- Detected device IP and MAC address
- First-seen and last-seen timestamps
- Packet count per device

Packet and alert records are written to SQLite in batches by a background loop. Device packet counts are updated while packets are saved, so the Devices page loads quickly even with a large database. Older databases are migrated automatically on startup.

### Data Retention

Old data is removed in two ways:

- **Automatically:** once per hour, records older than `NETWATCH_RETENTION_DAYS` (default: 30 days) are deleted. Set it to `0` to disable automatic cleanup.
- **Manually:** from the Data Export page, keeping the latest 7, 30, 90, or 365 days.

Each cleanup removes old packet and alert records, and devices that have not been seen during the retention period.

---

## 📤 Export Options

### Packet CSV

Packet CSV files contain capture time, source and destination IP addresses, source and destination ports, protocol, and packet length.

A maximum of 50,000 packet records can be exported at once.

### Security Alert CSV

Security alert CSV files contain alert time, alert type, severity, source IP address, and alert message.

A maximum of 10,000 alert records can be exported at once.

### PCAP

NetWatch can export up to 5,000 recent raw packets captured during the current application session.

PCAP files can be opened and analyzed using applications such as Wireshark.

---

## 🛠️ Technologies

| Technology | Purpose |
|---|---|
| Python | Core application language |
| Flask | Web application and API routes |
| Flask-SocketIO | Real-time dashboard updates |
| Scapy | Network packet capture and analysis |
| SQLite | Local data storage |
| HTML / CSS | Dashboard structure and responsive dark interface |
| JavaScript | Dynamic tables, filtering, and API requests |
| Chart.js | Historical traffic visualization |
| unittest | Automated application testing |
| GitHub Actions | Continuous integration (Python 3.10 and 3.12) |

---

## 📁 Project Structure

```text
Netwatch/
├── .github/
│   └── workflows/
│       └── tests.yml          # CI: runs the tests on every push
│
├── app.py                     # Flask routes, security, live update loop
├── database.py                # SQLite schema, migrations, history, cleanup
├── detector.py                # Rule-based threat detection
├── device_manager.py          # Local device tracking
├── export_manager.py          # CSV and PCAP export
├── logger.py                  # Rotating log configuration
├── packet_search.py           # Packet search filters
├── sniffer.py                 # Packet capture and live statistics
├── requirements.txt
├── README.md
│
├── images/                    # README screenshots
│
├── static/
│   ├── style.css
│   └── vendor/
│       ├── chart.umd.min.js
│       ├── socket.io.min.js
│       ├── LICENSE-chart.js.md
│       └── LICENSE-socket.io-client.txt
│
├── templates/
│   ├── _navigation.html
│   ├── index.html
│   ├── history.html
│   ├── search.html
│   ├── devices.html
│   └── exports.html
│
└── tests/
    ├── test_app.py
    ├── test_database.py
    ├── test_detector.py
    └── test_sniffer.py
```

The virtual environment, SQLite database, logs, cache files, and generated PCAP files are excluded from Git.

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/betulaltunyuva/Netwatch.git
cd Netwatch
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
```

### 3. Activate the Virtual Environment

#### Windows PowerShell

```powershell
.\venv\Scripts\Activate.ps1
```

If PowerShell blocks the script, run this first:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

#### Windows Command Prompt

```cmd
venv\Scripts\activate
```

#### Linux or macOS

```bash
source venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Start NetWatch

```bash
python app.py
```

### 6. Open the Dashboard

The terminal shows the address when the application starts:

```text
http://127.0.0.1:5000
```

Press `Ctrl + C` in the terminal to stop the application.

### 🪟 Windows Packet Capture

Live network capture may require:

- Running VS Code or the terminal as Administrator
- Installing a compatible packet capture driver such as [Npcap](https://npcap.com/)
- Allowing Python through the Windows firewall when requested

If packet capture cannot start (for example, Npcap is missing or permissions are insufficient), NetWatch detects the failure within one second and switches to sample data mode. If capture stops later while the application is running, the dashboard shows the error and the data mode changes to **Unavailable**.

---

## 🔧 Configuration

NetWatch is configured with environment variables:

| Variable | Default | Description |
|---|---|---|
| `NETWATCH_INTERFACE` | Scapy default | Network interface to capture from, e.g. `Wi-Fi`, `Ethernet`, `eth0` |
| `NETWATCH_PORT` | `5000` | Port of the local web dashboard |
| `NETWATCH_RETENTION_DAYS` | `30` | Records older than this are deleted automatically every hour (`0` disables it, max `365`) |
| `NETWATCH_DATA_DIR` | `data/` | Folder where the SQLite database is stored |
| `NETWATCH_SECRET_KEY` | Random per run | Fixed Flask secret key |
| `NETWATCH_DEBUG` | `0` | Set to `1` to enable Flask debug mode |
| `NETWATCH_<SETTING>` | See [Custom Thresholds](#custom-thresholds) | Detection thresholds |

Example for Windows PowerShell:

```powershell
$env:NETWATCH_INTERFACE = "Wi-Fi"
$env:NETWATCH_PORT = "8080"
python app.py
```

Available interface names can be listed with:

```bash
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

---

## 🧪 Running Tests

Run all automated tests with:

```bash
python -m unittest discover -s tests -v
```

Expected result:

```text
Ran 23 tests

OK
```

The tests use a temporary database and never modify `data/netwatch.db`. They also run automatically on GitHub Actions for every push and pull request.

| Area | Covered Behavior |
|---|---|
| Web application | Pages, JSON API endpoints, security headers, Host header validation, CSRF protection of the cleanup endpoint |
| Database | Packet search, CSV export, device tracking, retention cleanup, device packet counters, database migration, filling empty history minutes |
| Threat detection | Port scan, SYN / ICMP / DNS floods, ARP spoofing, thresholds from environment variables, memory cleanup |
| Packet capture | Sample mode, batch database writes, capture failure detection, malformed packets, IPv6 and ICMPv6 processing, ARP alerts |

---

## 🔐 Security and Privacy

- The application listens only on `127.0.0.1`.
- Requests are accepted only with a `127.0.0.1` or `localhost` Host header. This blocks DNS rebinding attacks that would otherwise let a malicious website read local NetWatch data.
- The data cleanup endpoint accepts only JSON requests from the local dashboard, which blocks cross-site request forgery (CSRF).
- Socket.IO connections are restricted to local application addresses.
- A Content-Security-Policy header allows pages to load only local scripts and connect only to the local server.
- Additional browser security headers (`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`) are enabled.
- A random secret key is generated on every run unless `NETWATCH_SECRET_KEY` is provided.
- Packet metadata is stored locally in SQLite and old records are deleted automatically.
- Recent raw packets are kept only in memory for session-based PCAP export.
- Log rotation prevents unlimited log file growth.
- The SQLite database and generated capture files are excluded from Git.

---

## ⚠️ Limitations

- NetWatch can only analyze traffic visible to the computer and network interface.
- Administrator or root permissions may be required for packet capture.
- Encrypted traffic payloads are not decrypted.
- Threat detection is rule-based and may produce false positives.
- Advanced attacks may not be detected.
- Device discovery currently supports IPv4 devices only.
- Raw packets used for PCAP export are cleared when the application restarts.
- The application is intended for local and educational use.

---

## 🔮 Future Improvements

- Reclaiming disk space after cleanup (`VACUUM`) and showing the database size
- More detection rules (UDP port scan, distributed SYN flood, suspicious ports)
- Editing detection thresholds from a settings page
- IPv6 device discovery
- Desktop or email notifications for critical alerts
- Docker support
- Authentication and a production server if the dashboard is exposed to a network

---

## 👩‍💻 Author

**Betül Altunyuva**

Software Engineering Student

[GitHub Profile](https://github.com/betulaltunyuva)

---

<div align="center">

Developed for learning, network analysis, and cybersecurity practice.

⭐ If you find the project useful, consider giving it a star.

</div>
