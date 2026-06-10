"""
LinArmor Configuration Management

Handles application-wide settings, paths, and defaults.
"""

import os
from pathlib import Path


# ──────────────────────────────────────────────
# Directory Paths
# ──────────────────────────────────────────────

# Base directory of the linarmor package
BASE_DIR = Path(__file__).resolve().parent

# Project root (one level up from the package)
PROJECT_ROOT = BASE_DIR.parent

# Data directories
DATA_DIR = PROJECT_ROOT / "data"
NVD_DIR = DATA_DIR / "nvd"
RULES_DIR = DATA_DIR / "rules"
REPORTS_DIR = PROJECT_ROOT / "reports"

# Frontend paths
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# Database
CVE_DATABASE_PATH = DATA_DIR / "cve_database.sqlite"


# ──────────────────────────────────────────────
# Scan Defaults
# ──────────────────────────────────────────────

# Scan types and their module/port configurations
SCAN_TYPES = {
    "full": {
        "description": "Full comprehensive scan — all modules, all ports",
        "port_range": "1-65535",
        "modules": [
            "ssh", "services", "kernel", "credentials", "docker",
            "nfs", "samba", "sensitive_files", "suid", "permissions", "cron"
        ],
    },
    "quick": {
        "description": "Quick scan — top 5 critical modules, common ports",
        "port_range": "1-1000",
        "modules": [
            "ssh", "services", "kernel", "credentials", "suid"
        ],
    },
    "custom": {
        "description": "Custom scan — user-selected modules and port range",
        "port_range": "1-65535",
        "modules": [],  # User selects
    },
}

# Modules that require SSH/authenticated access
AUTH_REQUIRED_MODULES = ["suid", "permissions", "cron"]

# Default Nmap scan arguments
NMAP_ARGS = {
    "discovery": "-sn",                          # Ping sweep
    "syn_scan": "-sS -sV -O --version-intensity 5",  # SYN scan + version + OS
    "quick_scan": "-sS -sV --top-ports 1000",   # Top 1000 ports
    "full_scan": "-sS -sV -O -p 1-65535",       # All ports
    "banner_grab": "-sV --script=banner",        # Banner grabbing
}

# Scan timeout (seconds)
SCAN_TIMEOUT = 600  # 10 minutes per module max

# Maximum concurrent module threads
MAX_THREADS = 4


# ──────────────────────────────────────────────
# CVSS Severity Mapping
# ──────────────────────────────────────────────

SEVERITY_LEVELS = {
    "critical": {"min": 9.0, "max": 10.0, "color": "#ff2d55"},
    "high":     {"min": 7.0, "max": 8.9,  "color": "#ff6b35"},
    "medium":   {"min": 4.0, "max": 6.9,  "color": "#ffbe0b"},
    "low":      {"min": 0.1, "max": 3.9,  "color": "#06d6a0"},
    "info":     {"min": 0.0, "max": 0.0,  "color": "#00d4ff"},
}


def get_severity(cvss_score: float) -> str:
    """Map a CVSS score to a severity label."""
    if cvss_score >= 9.0:
        return "critical"
    elif cvss_score >= 7.0:
        return "high"
    elif cvss_score >= 4.0:
        return "medium"
    elif cvss_score > 0.0:
        return "low"
    return "info"


# ──────────────────────────────────────────────
# Flask / Web Server
# ──────────────────────────────────────────────

FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
FLASK_DEBUG = os.environ.get("LINARMOR_DEBUG", "false").lower() == "true"
SECRET_KEY = os.environ.get("LINARMOR_SECRET", "linarmor-dev-key-change-in-prod")


# ──────────────────────────────────────────────
# NVD / CVE Database
# ──────────────────────────────────────────────

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/1.1"

# How often to auto-update CVE database (in hours)
CVE_UPDATE_INTERVAL_HOURS = 168  # Weekly


# ──────────────────────────────────────────────
# Credential Wordlists (for brute-force module)
# ──────────────────────────────────────────────

DEFAULT_USERNAMES = [
    "root", "admin", "user", "test", "guest", "ubuntu", "pi",
    "oracle", "postgres", "mysql", "ftp", "www-data", "nobody",
]

DEFAULT_PASSWORDS = [
    "password", "123456", "admin", "root", "toor", "test",
    "guest", "changeme", "password123", "letmein", "welcome",
    "qwerty", "abc123", "monkey", "master", "dragon",
]


# ──────────────────────────────────────────────
# Ensure directories exist
# ──────────────────────────────────────────────

def ensure_directories():
    """Create necessary data directories if they don't exist."""
    for directory in [DATA_DIR, NVD_DIR, RULES_DIR, REPORTS_DIR]:
        directory.mkdir(parents=True, exist_ok=True)
