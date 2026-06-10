"""
SUID/SGID Abuse Module

Checks for exploitable SUID/SGID binaries on the target.
Requires authenticated (SSH) access to the target system.
"""

from __future__ import annotations

from linarmor.core.target import Finding, Severity, FindingStatus, Target
from linarmor.modules.base_module import BaseModule


class SUIDModule(BaseModule):
    name = "SUID/SGID Abuse"
    description = "Privilege escalation via SUID binaries"
    module_id = "suid"
    requires_auth = True

    # Known SUID binaries that can be abused for privilege escalation
    # Source: GTFOBins (https://gtfobins.github.io/)
    EXPLOITABLE_SUID_BINARIES = {
        "/usr/bin/pkexec": {
            "cve": "CVE-2021-4034",
            "name": "PwnKit",
            "cvss": 7.8,
            "description": "pkexec is vulnerable to local privilege escalation (PwnKit).",
        },
        "/usr/bin/find": {
            "cve": None,
            "name": "find SUID",
            "cvss": 7.8,
            "description": "find with SUID can execute commands as root via -exec.",
        },
        "/usr/bin/vim": {
            "cve": None,
            "name": "vim SUID",
            "cvss": 7.8,
            "description": "vim with SUID can spawn a root shell via :!/bin/sh.",
        },
        "/usr/bin/nmap": {
            "cve": None,
            "name": "nmap SUID",
            "cvss": 7.8,
            "description": "nmap with SUID (interactive mode) can spawn a root shell.",
        },
        "/usr/bin/python3": {
            "cve": None,
            "name": "python SUID",
            "cvss": 7.8,
            "description": "Python with SUID can execute arbitrary code as root.",
        },
        "/usr/bin/bash": {
            "cve": None,
            "name": "bash SUID",
            "cvss": 9.8,
            "description": "bash with SUID allows direct root shell access via -p flag.",
        },
        "/usr/bin/env": {
            "cve": None,
            "name": "env SUID",
            "cvss": 7.8,
            "description": "env with SUID can execute arbitrary commands as root.",
        },
    }

    def scan(self, target: Target) -> list[Finding]:
        """
        Scan for exploitable SUID binaries.
        NOTE: This module requires SSH access. In unauthenticated mode,
        it returns a placeholder finding indicating auth is needed.
        """
        findings = []

        self._emit("warn", "SUID module requires authenticated access — "
                   "limited to known CVE checks based on OS detection")

        # In unauthenticated mode, we can only flag known vulnerabilities
        # based on OS version (e.g., PwnKit affects nearly all Linux)
        if target.os_family == "Linux" or "linux" in target.os_name.lower():
            findings.append(Finding(
                title="SUID Binary Check — Requires Authenticated Scan",
                description=(
                    "SUID/SGID binary analysis requires SSH access to the target. "
                    "Based on the detected Linux OS, common exploitable SUID binaries "
                    "like pkexec (CVE-2021-4034) may be present. "
                    "Run an authenticated scan for full SUID analysis."
                ),
                severity=Severity.INFO,
                cvss_score=0.0,
                module=self.module_id,
                status=FindingStatus.REVIEW,
                evidence=f"Target OS: {target.os_name or 'Linux detected'}",
                remediation="Run an authenticated scan with SSH credentials for full SUID analysis.",
            ))

        return findings
