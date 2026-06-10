"""
LinArmor Target & Finding Models

Data classes representing scan targets, discovered services,
and security findings.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class ScanStatus(Enum):
    """Scan lifecycle states."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    STOPPED = "stopped"
    ERROR = "error"


class Severity(Enum):
    """Finding severity levels aligned with CVSS."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(Enum):
    """Status of a security finding."""
    OPEN = "open"
    REVIEW = "review"
    NOTED = "noted"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass
class Service:
    """A network service discovered on the target."""
    port: int
    protocol: str = "tcp"         # tcp / udp
    state: str = "open"           # open / closed / filtered
    service_name: str = ""        # e.g., "ssh", "http", "mysql"
    product: str = ""             # e.g., "OpenSSH"
    version: str = ""             # e.g., "8.2p1"
    extra_info: str = ""          # e.g., "Ubuntu 4ubuntu0.5"
    banner: str = ""              # Raw banner string
    cpe: str = ""                 # CPE string for CVE matching

    @property
    def display_name(self) -> str:
        """Human-readable service string."""
        parts = [self.product, self.version, f"({self.service_name})"]
        return " ".join(p for p in parts if p)

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service_name": self.service_name,
            "product": self.product,
            "version": self.version,
            "extra_info": self.extra_info,
            "banner": self.banner,
            "cpe": self.cpe,
        }


@dataclass
class Finding:
    """A security vulnerability or misconfiguration finding."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    cvss_score: float = 0.0
    cve_id: Optional[str] = None
    module: str = ""              # Which scan module found this
    status: FindingStatus = FindingStatus.OPEN
    evidence: str = ""            # Raw evidence/proof
    remediation: str = ""         # Fix recommendation
    references: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def status_emoji(self) -> str:
        """Status indicator for the UI."""
        return {
            FindingStatus.OPEN: "🔴",
            FindingStatus.REVIEW: "🟡",
            FindingStatus.NOTED: "🟢",
            FindingStatus.RESOLVED: "✅",
            FindingStatus.FALSE_POSITIVE: "⚪",
        }.get(self.status, "⚪")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cve_id": self.cve_id,
            "module": self.module,
            "status": self.status.value,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class Target:
    """
    Represents a scan target host with all discovered information.

    This is the central data object that accumulates information
    as the scan progresses through its phases.
    """
    ip: str
    port_range: str = "1-65535"

    # Discovery phase results
    is_alive: bool = False
    hostname: str = ""
    os_name: str = ""             # e.g., "Ubuntu 20.04 LTS"
    os_family: str = ""           # e.g., "Linux"
    kernel_version: str = ""      # e.g., "5.4.0-42-generic"
    latency: float = 0.0         # Response time in seconds

    # Enumeration phase results
    services: list[Service] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)

    # Vulnerability findings
    findings: list[Finding] = field(default_factory=list)

    # Scan metadata
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_type: str = "full"       # full / quick / custom
    scan_status: ScanStatus = field(default=ScanStatus.PENDING)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    modules_selected: list[str] = field(default_factory=list)

    @property
    def elapsed_time(self) -> str:
        """Formatted elapsed scan time."""
        if not self.start_time:
            return "00:00"
        end = self.end_time or datetime.now()
        delta = end - self.start_time
        minutes, seconds = divmod(int(delta.total_seconds()), 60)
        return f"{minutes:02d}:{seconds:02d}"

    @property
    def findings_by_severity(self) -> dict[str, list[Finding]]:
        """Group findings by severity level."""
        grouped = {s.value: [] for s in Severity}
        for f in self.findings:
            grouped[f.severity.value].append(f)
        return grouped

    @property
    def severity_counts(self) -> dict[str, int]:
        """Count findings per severity level."""
        return {k: len(v) for k, v in self.findings_by_severity.items()}

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def get_service_by_port(self, port: int) -> Optional[Service]:
        """Find a service by port number."""
        for svc in self.services:
            if svc.port == port:
                return svc
        return None

    def add_finding(self, finding: Finding) -> None:
        """Add a finding, avoiding duplicates by title."""
        if not any(f.title == finding.title for f in self.findings):
            self.findings.append(finding)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "port_range": self.port_range,
            "is_alive": self.is_alive,
            "hostname": self.hostname,
            "os_name": self.os_name,
            "os_family": self.os_family,
            "kernel_version": self.kernel_version,
            "latency": self.latency,
            "services": [s.to_dict() for s in self.services],
            "open_ports": self.open_ports,
            "findings": [f.to_dict() for f in self.findings],
            "scan_id": self.scan_id,
            "scan_type": self.scan_type,
            "scan_status": self.scan_status.value,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "modules_selected": self.modules_selected,
            "elapsed_time": self.elapsed_time,
            "severity_counts": self.severity_counts,
            "total_findings": self.total_findings,
        }
