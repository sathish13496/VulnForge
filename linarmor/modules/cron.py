"""
Cron Job Vulnerabilities Module

Checks for writable cron scripts and PATH hijacking.
Requires authenticated (SSH) access to the target system.
"""

from __future__ import annotations

from linarmor.core.target import Finding, Severity, FindingStatus, Target
from linarmor.modules.base_module import BaseModule


class CronModule(BaseModule):
    name = "Cron Job Vulnerabilities"
    description = "Writable cron scripts, PATH hijacking"
    module_id = "cron"
    requires_auth = True

    def scan(self, target: Target) -> list[Finding]:
        findings = []

        self._emit("warn", "Cron module requires authenticated access — "
                   "returning informational finding")

        if target.os_family == "Linux" or "linux" in target.os_name.lower():
            findings.append(Finding(
                title="Cron Job Analysis — Requires Authenticated Scan",
                description=(
                    "Analyzing cron jobs for writable scripts, PATH hijacking, and "
                    "insecure wildcard usage requires SSH access to the target. "
                    "Run an authenticated scan for full cron analysis."
                ),
                severity=Severity.INFO,
                cvss_score=0.0,
                module=self.module_id,
                status=FindingStatus.REVIEW,
                evidence=f"Target OS: {target.os_name or 'Linux detected'}",
                remediation="Run an authenticated scan with SSH credentials.",
            ))

        return findings
