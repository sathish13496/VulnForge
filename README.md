# 🛡️ LinArmor — Linux Security Misconfiguration Discovery Framework

An offensive security framework that scans remote Linux servers for misconfigurations, maps findings to known CVEs, scores them with CVSS, and generates comprehensive security assessment reports.

## Features

- **11 Scan Modules**: SSH, Services, Kernel, Credentials, Docker, NFS, Samba, Sensitive Files, SUID, Permissions, Cron
- **CVE Mapping**: Automatic matching against NVD (National Vulnerability Database)
- **CVSS Scoring**: Findings ranked by severity (Critical / High / Medium / Low)
- **Real-time Dashboard**: Web UI with live scan progress and terminal output
- **Multiple Scan Types**: Full, Quick, and Custom scans
- **Report Generation**: PDF, HTML, and JSON report formats
- **CLI & Web Interface**: Use from terminal or browser

## Quick Start

### Option 1: Install Script (Recommended)

```bash
git clone https://github.com/sathish13496/LinArmor.git
cd LinArmor
chmod +x install.sh
./install.sh

# Activate virtual environment
source venv/bin/activate

# Start web UI
linarmor --web
# Open http://localhost:5000
```

### Option 2: Docker

```bash
docker build -t linarmor .
docker run -p 5000:5000 linarmor
# Open http://localhost:5000
```

### Option 3: pip install

```bash
pip install -e .
linarmor --web
```

## Prerequisites

- **Python 3.10+**
- **Nmap** (`sudo apt install nmap`)

## Usage

### Web UI
```bash
linarmor --web                       # Start web dashboard
linarmor --web --port 8080           # Custom port
```

### CLI Scanning
```bash
linarmor scan -t 192.168.1.100                    # Full scan
linarmor scan -t 192.168.1.100 --type quick       # Quick scan
linarmor scan -t 10.0.0.5 -m ssh,kernel,services  # Custom modules
linarmor scan -t 10.0.0.5 -p 1-1000               # Custom port range
linarmor scan -t 10.0.0.5 --format html -o report.html
```

### CVE Database
```bash
linarmor --update-db                 # Download/update CVE database from NVD
```

## Scan Modules

| Module | Description | Auth Required |
|--------|-------------|:---:|
| SSH | Root login, weak ciphers, protocol issues | ❌ |
| Services | Open ports, insecure daemons, default configs | ❌ |
| Kernel | Known kernel CVEs, privilege escalation | ❌ |
| Credentials | Default/weak passwords, empty credentials | ❌ |
| Docker | API exposure, privileged containers | ❌ |
| NFS | Open exports, no_root_squash | ❌ |
| Samba | Anonymous access, null sessions, outdated SMB | ❌ |
| Sensitive Files | Exposed configs, keys, backups via HTTP | ❌ |
| SUID/SGID | Exploitable SUID binaries | ✅ |
| Permissions | World-writable files, insecure directories | ✅ |
| Cron | Writable cron scripts, PATH hijacking | ✅ |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scan/start` | POST | Start a new scan |
| `/api/scan/status` | GET | Get scan status |
| `/api/scan/pause` | POST | Pause scan |
| `/api/scan/stop` | POST | Stop scan |
| `/api/findings` | GET | Get findings |
| `/api/report/<format>` | GET | Download report |
| `/api/cve/<id>` | GET | CVE lookup |

## Project Structure

```
linarmor/
├── linarmor/
│   ├── app.py          # Flask web server
│   ├── cli.py          # CLI interface
│   ├── config.py       # Configuration
│   ├── core/           # Engine, scanner, data models
│   ├── modules/        # 11 scan modules
│   ├── cve/            # CVE database & matcher
│   └── reporting/      # Report generators
├── data/               # CVE database & rules
├── install.sh          # Install script
├── Dockerfile          # Docker deployment
└── requirements.txt    # Python dependencies
```

## License

MIT License — For educational and authorized security testing only.

> ⚠️ **Disclaimer**: This tool is for authorized security testing only. Unauthorized scanning of systems you do not own or have permission to test is illegal.
