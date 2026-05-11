<div align="center">

<img src="https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D4?style=for-the-badge&logo=windows&logoColor=white"/>
<img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/PyQt6-GUI-41CD52?style=for-the-badge&logo=qt&logoColor=white"/>
<img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge"/>
<img src="https://img.shields.io/badge/Status-Active-success?style=for-the-badge"/>

<br/><br/>

```
  ██████╗ ███████╗ ██████╗██╗   ██╗██████╗ ███████╗    ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗
  ██╔════╝ ██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝    ████╗  ██║██╔═══██╗██║   ██║██╔══██╗
  ███████╗ █████╗  ██║     ██║   ██║██████╔╝█████╗      ██╔██╗ ██║██║   ██║██║   ██║███████║
  ╚════██║ ██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝      ██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
  ███████║ ███████╗╚██████╗╚██████╔╝██║  ██║███████╗    ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
  ╚══════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝
```

# 🛡️ SecureNova
### *Your Personal Windows Security Guardian*

> **A powerful, lightweight, open-source personal security suite for Windows.**
> Built with Python, powered by YARA, VirusTotal & real-time behavioral analysis.
> Detect threats before they detect you.

<br/>

[![Stars](https://img.shields.io/github/stars/Charan-8888/SecureNova?style=social)](https://github.com/Charan-8888/Secure-Nova)
[![Forks](https://img.shields.io/github/forks/Charan-8888/SecureNova?style=social)](https://github.com/Charan-8888/Secure-Nova)
[![Issues](https://img.shields.io/github/issues/Charan-8888/SecureNova?color=red)](https://github.com/Charan-8888/Secure-Nova/issues)

</div>

---

## ✨ What is SecureNova?

**SecureNova** is a free, open-source personal security application for Windows that brings **enterprise-grade threat detection** to your personal machine — without the bloat, cost, or privacy concerns of commercial antivirus software.

It runs silently in your system tray, watching for threats in real time across files, processes, network connections, USB drives, and startup entries — then instantly alerts you when something suspicious is found.

---

## 🚀 Features at a Glance

<table>
<tr>
<td width="50%">

### 🔍 Real-Time File Scanning
- **YARA signature engine** — 500+ community rules
- **Hash database** — daily sync from MalwareBazaar
- Watches Desktop, Downloads, Temp & AppData live
- Auto-quarantine on threat detection

</td>
<td width="50%">

### 🧠 Behavioral Process Monitor
- Detects **ransomware** (high file ops + CPU)
- Flags **cryptominers** (sustained >85% CPU)
- Catches **mass file deletion** attacks
- Baseline-diff alerts on new unknown processes

</td>
</tr>
<tr>
<td width="50%">

### 🌐 Network Intelligence
- Live outbound connection table
- **Domain blocker** via hosts file (URLhaus + MalwareDomains)
- Flags unknown processes phoning home
- Color-coded risk levels per connection

</td>
<td width="50%">

### 🔒 Startup & Registry Guard
- Monitors `HKLM/HKCU Run` keys in real time
- Alerts on any new startup entry
- Full startup manager (registry + folder + Task Scheduler)
- One-click disable without deleting

</td>
</tr>
<tr>
<td width="50%">

### 💾 USB Auto-Scanner
- Detects USB insertion via WMI
- Recursively scans entire drive on plug-in
- Auto-blocks `autorun.inf` execution
- Optional auto-eject on threat found

</td>
<td width="50%">

### ☁️ VirusTotal Integration
- Hash lookups with 70+ AV engine results
- Smart caching — never query the same file twice
- Rate-limited for free tier (500 lookups/day)
- File submission for unknown samples (<32 MB)

</td>
</tr>
</table>

---

## 🖥️ Dashboard Preview

```
┌──────────────────────────────────────────────────────────────────┐
│  🛡 SecureNova              ● PROTECTED          09:07:12 10 May  │
├────────────┬───────────────────────────────┬─────────────────────┤
│            │                               │                     │
│  Overview  │   🔴 Live Threat Feed         │  🦠 Threats: 0      │
│  File Scan │                               │  📂 Scanned: 142    │
│  Processes │   ✅ No threats detected      │  🔒 Blocked: 38,291 │
│  Network   │   — system is clean           │  ⚙  Procs: 87       │
│  Quarantine│                               │                     │
│  Settings  │                               │                     │
└────────────┴───────────────────────────────┴─────────────────────┘
```

**Dark-mode dashboard** with 6 panels, system tray integration, desktop notifications, and a live threat feed that loads history from the local database on startup.

---

## ⚙️ Architecture

```
┌─────────────────────────────────────────────────────┐
│              DASHBOARD  (PyQt6 Dark UI)              │
├──────────────┬──────────────────┬───────────────────┤
│ FILE MODULE  │ PROCESS MODULE   │  NETWORK MODULE   │
│  (watchdog)  │  (psutil)        │  (psutil/socket)  │
├──────────────┴──────────────────┴───────────────────┤
│        SCAN ENGINE  (YARA + MalwareBazaar Hashes)   │
├─────────────────────────────────────────────────────┤
│     RESPONSE ENGINE  (Quarantine / Kill / Alert)    │
├─────────────────────────────────────────────────────┤
│      SQLite Threat Log  (9 tables, WAL mode)        │
└─────────────────────────────────────────────────────┘
```

---

## 📦 Project Structure

```
SecureNova/
├── 📄 main.py                    # App entry point
├── 📄 setup.bat                  # One-click installer (creates .venv)
├── 📄 run.bat                    # Launch with venv auto-activation
│
├── 📁 config/
│   ├── settings.json             # Your config (gitignored)
│   └── settings.example.json     # Template — copy & rename
│
├── 📁 scanner/
│   ├── file_scanner.py           # YARA + hash scanner + quarantine
│   ├── realtime_monitor.py       # Watchdog live filesystem monitor
│   └── virustotal.py             # VirusTotal API v3 client
│
├── 📁 monitor/
│   ├── process_monitor.py        # 6-rule behavioral analyzer
│   ├── registry_watcher.py       # Startup registry baseline diff
│   ├── usb_monitor.py            # WMI USB insertion + auto-scan
│   └── startup_manager.py        # Registry + folder + schtasks
│
├── 📁 network/
│   ├── connection_monitor.py     # Live TCP/UDP connection tracker
│   └── blocklist_manager.py      # Hosts-file domain blocker
│
├── 📁 sandbox/
│   └── executor.py               # Windows Job Object soft-sandbox
│
├── 📁 gui/
│   ├── main_window.py            # Main PyQt6 window + tray icon
│   └── widgets/                  # 6 panel widgets
│       ├── overview_panel.py     # Stats + live threat feed
│       ├── filescan_panel.py     # File scan UI
│       ├── process_panel.py      # Process table
│       ├── network_panel.py      # Network connections
│       ├── quarantine_panel.py   # Quarantine vault
│       └── settings_panel.py     # Settings editor
│
└── 📁 utils/
    ├── database.py               # SQLite manager (9 tables)
    ├── logger.py                 # Rotating log handler
    └── updater.py                # Background feed updater
```

---

## 🛠️ Installation

### Prerequisites
- Windows 10 or 11
- Python 3.11 or newer → [python.org](https://www.python.org/downloads/)
- Git → [git-scm.com](https://git-scm.com/)

### Step 1 — Clone the repository
```cmd
git clone https://github.com/Charan-8888/SecureNova.git
cd SecureNova
```

### Step 2 — Run the setup script
```cmd
setup.bat
```
This will automatically:
- Create a Python virtual environment (`.venv`)
- Install all dependencies inside it
- Create required directories

### Step 3 — Configure (optional but recommended)
```cmd
copy config\settings.example.json config\settings.json
notepad config\settings.json
```
Add your free **VirusTotal API key** → [Get one here (free)](https://www.virustotal.com/gui/join-us)

### Step 4 — Launch
```cmd
run.bat
```
> 💡 **Tip:** Right-click `run.bat` → *Run as Administrator* for full features (hosts file, registry monitoring, USB eject)

---

## 🔑 Free API Keys

| Service | Purpose | Limit | Link |
|---------|---------|-------|------|
| **VirusTotal** | File hash lookup + submission | 500/day, 4 req/min | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) |
| **AbuseIPDB** | Malicious IP reputation | 1,000/day | [abuseipdb.com](https://www.abuseipdb.com/) |

Both are **completely free** for personal use. SecureNova works without them — they just add extra intelligence layers.

---

## 🛡️ Behavioral Detection Rules

| # | Pattern | Trigger Condition |
|---|---------|-------------------|
| 1 | 🔐 **Ransomware** | Process: CPU > 60% AND > 30 file writes/min |
| 2 | ⛏️ **Cryptominer** | Unknown process: CPU > 85% sustained for > 60 seconds |
| 3 | 🗑️ **Mass Deletion** | Process deletes > 10 files in < 5 seconds |
| 4 | 🔑 **Registry Hijack** | New entry added to `Run` / `RunOnce` startup keys |
| 5 | 👁️ **Unknown Process** | New process not present in trusted baseline |
| 6 | 📡 **Network Phone-Home** | Unknown process opens outbound TCP connection |

---

## 📊 Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.11+ |
| GUI | PyQt6 |
| Scan Engine | YARA + MalwareBazaar |
| Cloud Intel | VirusTotal API v3 |
| Blocklists | URLhaus, MalwareDomains |
| File Watching | watchdog |
| Process Monitor | psutil |
| USB Detection | WMI (Win32_VolumeChangeEvent) |
| Registry | winreg |
| Database | SQLite (WAL mode, thread-safe) |
| Packaging | PyInstaller |

---

## 📋 Threat Intelligence Sources

- 🔴 **[MalwareBazaar](https://bazaar.abuse.ch/)** — SHA256/MD5 hash feeds (daily)
- 🔴 **[URLhaus](https://urlhaus.abuse.ch/)** — Malicious URL & domain blocklist (6h)
- 🔴 **[MalwareDomains](https://malware-filter.pages.dev/)** — Domain blocklist (6h)
- 🔴 **[Yara-Rules/rules](https://github.com/Yara-Rules/rules)** — 500+ YARA signatures (daily)
- 🔴 **[VirusTotal](https://www.virustotal.com/)** — 70+ AV engine results (on-demand)

---

## 🏗️ Build as .exe

```cmd
.venv\Scripts\activate
pyinstaller securenova.spec
```

Output: `dist\SecureNova.exe` — a single portable executable.

---

## ⚠️ Disclaimer

SecureNova is built for **personal, educational use**. It is not a replacement for a commercial antivirus suite. While it uses real threat intelligence sources and proven detection techniques, no security tool provides 100% protection.

**Never submit personal documents** (`.docx`, `.pdf`, `.xlsx`) to VirusTotal — the file scanner will warn you before any cloud submission.

---

## 🤝 Contributing

Contributions, bug reports, and feature requests are welcome!

1. Fork the repo
2. Create your branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "Add my feature"`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

YARA rules from [Yara-Rules/rules](https://github.com/Yara-Rules/rules) are used under their respective licenses.

---

<div align="center">

Made with ❤️ for the open-source security community

**[⭐ Star this repo](https://github.com/Charan-8888/SecureNova)** if SecureNova helped you!

</div>
