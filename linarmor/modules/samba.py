"""
Samba Weaknesses Module

Checks for SMB/Samba security issues including anonymous access,
null sessions, outdated versions, and known vulnerabilities.
"""

from __future__ import annotations

import subprocess
import socket
import re
from typing import Optional

from linarmor.core.target import Finding, Severity, FindingStatus, Target
from linarmor.modules.base_module import BaseModule


class SambaModule(BaseModule):
    name = "Samba Weaknesses"
    description = "Anonymous access, null sessions, outdated SMB"
    module_id = "samba"
    requires_auth = False

    # Known Samba CVEs
    SAMBA_CVES = [
        {
            "cve": "CVE-2017-7494",
            "name": "SambaCry",
            "max_version": (4, 6, 3),
            "cvss": 9.8,
            "description": (
                "A remote code execution vulnerability in Samba (similar to WannaCry). "
                "Allows a malicious client to upload a shared library to a writable share "
                "and execute it on the server."
            ),
            "remediation": "Update Samba to 4.6.4+ or add 'nt pipe support = no' to smb.conf.",
        },
        {
            "cve": "CVE-2021-44142",
            "name": "Samba VFS Heap Overflow",
            "max_version": (4, 15, 4),
            "cvss": 8.8,
            "description": (
                "A heap-based buffer overflow in the Samba VFS module vfs_fruit "
                "allows remote code execution."
            ),
            "remediation": "Update Samba to 4.15.5+ or remove 'fruit' from VFS objects.",
        },
    ]

    def scan(self, target: Target) -> list[Finding]:
        findings = []

        # Check if SMB ports are open (139, 445)
        smb_ports = [p for p in [139, 445] if p in target.open_ports]
        if not smb_ports:
            self._emit("info", "SMB ports not open — skipping Samba checks")
            return findings

        self._emit("info", "Checking Samba/SMB for security weaknesses...")

        # 1. Check for anonymous/null session access
        anon_finding = self._check_anonymous_access(target.ip)
        if anon_finding:
            findings.append(anon_finding)

        # 2. Check SMB version from Nmap service data
        for service in target.services:
            if service.port in smb_ports and service.product:
                version_findings = self._check_samba_version(service)
                findings.extend(version_findings)

        # 3. Try to enumerate shares
        share_findings = self._enumerate_shares(target.ip)
        findings.extend(share_findings)

        return findings

    def _check_anonymous_access(self, ip: str) -> Optional[Finding]:
        """Check if anonymous/null SMB sessions are allowed."""
        try:
            result = subprocess.run(
                ["smbclient", "-L", ip, "-N", "-g"],
                capture_output=True,
                text=True,
                timeout=15,
            )

            if result.returncode == 0 and result.stdout:
                shares = []
                for line in result.stdout.split("\n"):
                    if line.startswith("Disk|") or line.startswith("IPC|"):
                        parts = line.split("|")
                        if len(parts) >= 2:
                            shares.append(parts[1])

                if shares:
                    return Finding(
                        title="SMB Anonymous/Null Session Access Enabled",
                        description=(
                            f"Anonymous SMB access is allowed. Found {len(shares)} shares "
                            f"accessible without authentication: {', '.join(shares[:5])}"
                        ),
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        module=self.module_id,
                        status=FindingStatus.OPEN,
                        evidence=f"smbclient -L {ip} -N returned {len(shares)} shares",
                        remediation=(
                            "Disable anonymous access in smb.conf:\n"
                            "  restrict anonymous = 2\n"
                            "  map to guest = never"
                        ),
                    )

        except FileNotFoundError:
            self._emit("warn", "smbclient not installed — skipping anonymous access check")
        except subprocess.TimeoutExpired:
            self._emit("warn", "smbclient timed out")
        except Exception as e:
            self._emit("warn", f"SMB anonymous check failed: {e}")

        return None

    def _check_samba_version(self, service) -> list[Finding]:
        """Check Samba version against known CVEs."""
        findings = []

        version_str = service.version or ""
        product = service.product or ""

        if "samba" not in product.lower():
            return findings

        # Parse version
        match = re.search(r"(\d+)\.(\d+)\.(\d+)", version_str)
        if not match:
            return findings

        version = (int(match.group(1)), int(match.group(2)), int(match.group(3)))

        for cve_info in self.SAMBA_CVES:
            if version <= cve_info["max_version"]:
                findings.append(Finding(
                    title=f"Samba {version_str} — {cve_info['name']} ({cve_info['cve']})",
                    description=cve_info["description"],
                    severity=Severity.CRITICAL if cve_info["cvss"] >= 9.0 else Severity.HIGH,
                    cvss_score=cve_info["cvss"],
                    cve_id=cve_info["cve"],
                    module=self.module_id,
                    status=FindingStatus.OPEN,
                    evidence=f"Samba version: {version_str} on port {service.port}",
                    remediation=cve_info["remediation"],
                ))

        # Check for SMBv1
        if version < (4, 0, 0):
            findings.append(Finding(
                title="Outdated Samba Version Using SMBv1",
                description=(
                    f"Samba {version_str} likely supports SMBv1, which has multiple "
                    f"known vulnerabilities including EternalBlue-style attacks."
                ),
                severity=Severity.HIGH,
                cvss_score=8.1,
                module=self.module_id,
                status=FindingStatus.OPEN,
                evidence=f"Samba version: {version_str}",
                remediation="Update Samba and disable SMBv1: 'min protocol = SMB2' in smb.conf.",
            ))

        return findings

    def _enumerate_shares(self, ip: str) -> list[Finding]:
        """Try to enumerate SMB shares for sensitive names."""
        findings = []

        try:
            result = subprocess.run(
                ["smbclient", "-L", ip, "-N", "-g"],
                capture_output=True,
                text=True,
                timeout=15,
            )

            if result.returncode != 0:
                return findings

            sensitive_names = ["admin", "backup", "data", "private", "secret", "confidential",
                             "finance", "hr", "password", "config", "database", "root"]

            for line in result.stdout.split("\n"):
                if line.startswith("Disk|"):
                    parts = line.split("|")
                    if len(parts) >= 2:
                        share_name = parts[1].lower()
                        for sensitive in sensitive_names:
                            if sensitive in share_name:
                                findings.append(Finding(
                                    title=f"Sensitive SMB Share Detected: \\\\{ip}\\{parts[1]}",
                                    description=(
                                        f"A share named '{parts[1]}' was found which may "
                                        f"contain sensitive data based on its name."
                                    ),
                                    severity=Severity.MEDIUM,
                                    cvss_score=5.3,
                                    module=self.module_id,
                                    status=FindingStatus.REVIEW,
                                    evidence=f"Share: {parts[1]} on {ip}",
                                    remediation="Review share permissions and restrict access.",
                                ))
                                break

        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            pass

        return findings
